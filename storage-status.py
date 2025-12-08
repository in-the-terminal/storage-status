#!/usr/bin/env python3
"""
Storage Status - Terminal dashboard for Ubuntu/ZFS storage servers.
Monitors ZFS pools, datasets, services, and system resources.

Usage:
    storage-status              - Display full dashboard
    storage-status --remote     - Force remote mode (SSH)
    storage-status --local      - Force local mode
    storage-status pools        - Show only ZFS pool status
    storage-status datasets     - Show only ZFS datasets
    storage-status services     - Show only service status

Last Updated On: 2025-12-08
"""

import argparse
import json
import subprocess
import socket
import os
import re
import time
import sys
import select
import termios
import tty
import threading
import tempfile
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box


# Configuration from environment variables
STORAGE_SERVER_HOSTNAME = os.environ.get('STORAGE_HOSTNAME')
STORAGE_SERVER_IPS = os.environ.get('STORAGE_IPS', '').split(',') if os.environ.get('STORAGE_IPS') else []
SSH_HOST = os.environ.get('STORAGE_SSH_HOST')


class KeyboardListener:
    """
    Background thread keyboard listener for terminal applications.
    """

    def __init__(self):
        """Initialize keyboard listener."""
        self.old_settings = None
        self.running = False
        self.thread = None
        self.last_key = None
        self.lock = threading.Lock()

    def start(self):
        """Start listening for keyboard input in background thread."""
        self.old_settings = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop listening and restore terminal settings."""
        self.running = False
        if self.old_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def _listen(self):
        """Background thread that listens for keypresses."""
        while self.running:
            if select.select([sys.stdin], [], [], 0.1)[0]:
                try:
                    key = sys.stdin.read(1)
                    with self.lock:
                        self.last_key = key
                except Exception:
                    pass

    def get_key(self) -> Optional[str]:
        """
        Get the last key pressed and clear it.

        Returns:
            The last key pressed, or None if no key was pressed
        """
        with self.lock:
            key = self.last_key
            self.last_key = None
            return key


class CommandRunner:
    """
    Executes commands either locally or via SSH depending on detection.
    Uses SSH ControlMaster for connection multiplexing in remote mode.
    """

    def __init__(self, force_mode: Optional[str] = None):
        """
        Initialize the command runner.

        Args:
            force_mode: 'local', 'remote', or None for auto-detect
        """
        self.is_local = self._detect_local() if force_mode is None else (force_mode == 'local')
        self.ssh_host = SSH_HOST
        self._control_path = None
        self._setup_ssh_multiplexing()

    def _setup_ssh_multiplexing(self) -> None:
        """
        Set up SSH ControlMaster socket path for connection reuse.
        Creates a unique control socket in the temp directory.
        """
        if not self.is_local and self.ssh_host:
            # Create control socket path in temp directory
            self._control_path = os.path.join(
                tempfile.gettempdir(),
                f'storage-status-ssh-{os.getpid()}'
            )

    def _get_ssh_command(self, command: str) -> List[str]:
        """
        Build SSH command with ControlMaster options for multiplexing.

        Args:
            command: The remote command to execute

        Returns:
            List of command arguments for subprocess
        """
        ssh_cmd = ['ssh']
        if self._control_path:
            ssh_cmd.extend([
                '-o', 'ControlMaster=auto',
                '-o', f'ControlPath={self._control_path}',
                '-o', 'ControlPersist=60',
            ])
        ssh_cmd.extend([self.ssh_host, command])
        return ssh_cmd

    def cleanup(self) -> None:
        """
        Close the SSH ControlMaster connection if active.
        """
        if self._control_path and os.path.exists(self._control_path):
            try:
                subprocess.run(
                    ['ssh', '-O', 'exit', '-o', f'ControlPath={self._control_path}', self.ssh_host],
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                pass

    def _detect_local(self) -> bool:
        """
        Detect if we're running on the storage server.

        Returns:
            True if running locally on storage server, False otherwise
        """
        # Check hostname
        hostname = socket.gethostname()
        if hostname == STORAGE_SERVER_HOSTNAME:
            return True

        # Check if any local IP matches storage server IPs
        try:
            result = subprocess.run(
                ['hostname', '-I'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                local_ips = result.stdout.strip().split()
                for ip in local_ips:
                    if ip in STORAGE_SERVER_IPS:
                        return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def run(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Run a command either locally or via SSH.
        SSH commands use ControlMaster for connection multiplexing.

        Args:
            command: The command to execute
            timeout: Timeout in seconds

        Returns:
            Tuple of (success, output)
        """
        try:
            if self.is_local:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                result = subprocess.run(
                    self._get_ssh_command(command),
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

            if result.returncode == 0:
                return True, result.stdout
            else:
                # Return stdout if available (some commands output there even on failure)
                # otherwise return stderr
                return False, result.stdout if result.stdout else result.stderr

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)


def parse_size(size_str: str) -> int:
    """
    Parse ZFS size string to bytes.

    Args:
        size_str: Size string like '123T', '456G', '789M'

    Returns:
        Size in bytes
    """
    size_str = size_str.strip().upper()
    multipliers = {
        'B': 1,
        'K': 1024,
        'M': 1024**2,
        'G': 1024**3,
        'T': 1024**4,
        'P': 1024**5,
    }

    for suffix, mult in multipliers.items():
        if size_str.endswith(suffix):
            try:
                return int(float(size_str[:-1]) * mult)
            except ValueError:
                return 0

    try:
        return int(size_str)
    except ValueError:
        return 0


def format_size(bytes_val: int) -> str:
    """
    Format bytes to human-readable string.

    Args:
        bytes_val: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def create_progress_bar(percent: float, width: int = 30) -> Text:
    """
    Create a visual progress bar.

    Args:
        percent: Percentage (0-100)
        width: Width of the bar in characters

    Returns:
        Rich Text object with the progress bar
    """
    filled = int(percent * width / 100)
    bar = '█' * filled + '░' * (width - filled)

    # Color based on usage level
    if percent >= 90:
        color = 'bold red'
    elif percent >= 75:
        color = 'yellow'
    else:
        color = 'green'

    text = Text()
    text.append(bar, style=color)
    text.append(f" {percent:.1f}%", style=color)
    return text


class StorageStatus:
    """
    Main class for gathering and displaying storage server status.
    """

    def __init__(self, runner: CommandRunner):
        """
        Initialize storage status.

        Args:
            runner: CommandRunner instance for executing commands
        """
        self.runner = runner

    def get_zpool_status(self) -> Dict[str, Any]:
        """
        Get ZFS pool status information.

        Returns:
            Dictionary with pool information
        """
        pools = []

        # Get pool list
        success, output = self.runner.run("zpool list -H -o name,size,alloc,free,cap,health,dedup")
        if not success:
            return {'error': output, 'pools': []}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 7:
                cap = parts[4].replace('%', '')
                pools.append({
                    'name': parts[0],
                    'size': parts[1],
                    'alloc': parts[2],
                    'free': parts[3],
                    'capacity': float(cap) if cap.isdigit() else 0,
                    'health': parts[5],
                    'dedup': parts[6],
                })

        return {'pools': pools}

    def get_dataset_usage(self) -> Dict[str, Any]:
        """
        Get ZFS dataset usage information.

        Returns:
            Dictionary with dataset information
        """
        datasets = []

        success, output = self.runner.run(
            "zfs list -H -o name,used,avail,refer,compressratio,mountpoint"
        )
        if not success:
            return {'error': output, 'datasets': []}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 6:
                datasets.append({
                    'name': parts[0],
                    'used': parts[1],
                    'avail': parts[2],
                    'refer': parts[3],
                    'compress': parts[4],
                    'mountpoint': parts[5],
                })

        return {'datasets': datasets}

    def get_service_status(self) -> Dict[str, Any]:
        """
        Get status of critical services.

        Returns:
            Dictionary with service status information
        """
        services = ['smbd', 'nfs-server', 'zfs-import-cache', 'zfs-mount', 'ssh']
        status = {}

        for service in services:
            success, output = self.runner.run(f"systemctl is-active {service}")
            # is-active returns non-zero for inactive/failed, but output still tells us the state
            state = output.strip() if output.strip() else 'unknown'
            # For one-shot services, check if they completed successfully
            if state == 'inactive':
                success2, output2 = self.runner.run(
                    f"systemctl show -p ExecMainExitTimestamp,Result {service}"
                )
                if success2 and 'Result=success' in output2:
                    state = 'completed'
            status[service] = state

        return {'services': status}

    def get_system_resources(self) -> Dict[str, Any]:
        """
        Get system resource utilization.

        Returns:
            Dictionary with CPU, RAM, load information
        """
        resources = {}

        # Load average
        success, output = self.runner.run("cat /proc/loadavg")
        if success:
            parts = output.strip().split()
            resources['load'] = {
                '1min': float(parts[0]),
                '5min': float(parts[1]),
                '15min': float(parts[2]),
            }

        # Memory info
        success, output = self.runner.run("cat /proc/meminfo")
        if success:
            mem = {}
            for line in output.strip().split('\n'):
                if ':' in line:
                    key, val = line.split(':')
                    # Extract numeric value (in kB)
                    num = re.search(r'(\d+)', val)
                    if num:
                        mem[key.strip()] = int(num.group(1)) * 1024  # Convert to bytes

            if 'MemTotal' in mem and 'MemAvailable' in mem:
                resources['memory'] = {
                    'total': mem['MemTotal'],
                    'available': mem['MemAvailable'],
                    'used': mem['MemTotal'] - mem['MemAvailable'],
                    'percent': ((mem['MemTotal'] - mem['MemAvailable']) / mem['MemTotal']) * 100
                }

        # Uptime
        success, output = self.runner.run("uptime -p")
        if success:
            resources['uptime'] = output.strip().replace('up ', '')

        return resources

    def get_network_stats(self) -> Dict[str, Any]:
        """
        Get network interface statistics.

        Returns:
            Dictionary with network interface information
        """
        interfaces = []

        success, output = self.runner.run("ip -br addr | grep -v '^lo'")
        if not success:
            return {'error': output, 'interfaces': []}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                iface = {
                    'name': parts[0],
                    'state': parts[1],
                    'ips': parts[2:] if len(parts) > 2 else [],
                }
                interfaces.append(iface)

        return {'interfaces': interfaces}

    def get_smb_connections(self) -> Dict[str, Any]:
        """
        Get active SMB connections using smbstatus --json for detailed info.

        Returns:
            Dictionary with SMB connection information including:
            - pid: Process ID
            - user: Username
            - machine: Client machine name/IP
            - hostname: Reverse DNS hostname (if resolvable)
            - protocol: SMB protocol version (e.g., SMB3_11)
            - connected: Connection timestamp
        """
        connections = []

        # Try JSON output first for richer data
        success, output = self.runner.run("smbstatus --json 2>/dev/null")
        if success and output.strip():
            try:
                data = json.loads(output)
                sessions = data.get('sessions', {})

                for session_id, session in sessions.items():
                    # Extract machine/IP - could be hostname or IP
                    machine = session.get('remote_machine', 'unknown')
                    hostname = session.get('hostname', '')

                    # Parse connection time from session
                    connected = session.get('session_started', '')
                    if connected:
                        # Format: "2025-12-08T12:34:56+0000" -> "12:34:56"
                        try:
                            if 'T' in connected:
                                time_part = connected.split('T')[1].split('+')[0].split('-')[0]
                                connected = time_part[:8]  # HH:MM:SS
                        except (IndexError, ValueError):
                            pass

                    connections.append({
                        'pid': session.get('server_id', {}).get('pid', '-'),
                        'user': session.get('username', 'unknown'),
                        'machine': machine,
                        'hostname': hostname if hostname and hostname != machine else None,
                        'protocol': session.get('signing', {}).get('dialect', '-'),
                        'connected': connected,
                    })

            except (json.JSONDecodeError, KeyError):
                # Fall back to basic smbstatus -b
                pass

        # Fallback to basic output if JSON failed or no connections found
        if not connections:
            success, output = self.runner.run("smbstatus -b 2>/dev/null | tail -n +5")
            if success and output.strip():
                for line in output.strip().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            connections.append({
                                'pid': parts[0],
                                'user': parts[1],
                                'machine': parts[3] if len(parts) > 3 else 'unknown',
                                'hostname': None,
                                'protocol': '-',
                                'connected': '-',
                            })

        # Resolve hostnames for machine IPs that look like IPs
        self._resolve_smb_hostnames(connections)

        return {'connections': connections}

    def _resolve_smb_hostnames(self, connections: List[Dict[str, Any]]) -> None:
        """
        Resolve hostnames for SMB connection machine IPs via reverse DNS.

        Args:
            connections: List of connection dictionaries to update
        """
        # Get unique machines that look like IPs (no hostname yet)
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

        machines_to_resolve = set()
        for conn in connections:
            machine = conn.get('machine', '')
            if ip_pattern.match(machine) and not conn.get('hostname'):
                machines_to_resolve.add(machine)

        hostname_cache: Dict[str, Optional[str]] = {}
        for machine in machines_to_resolve:
            try:
                hostname, _, _ = socket.gethostbyaddr(machine)
                hostname_cache[machine] = hostname
            except (socket.herror, socket.gaierror, socket.timeout):
                hostname_cache[machine] = None

        # Apply resolved hostnames
        for conn in connections:
            machine = conn.get('machine', '')
            if machine in hostname_cache and not conn.get('hostname'):
                conn['hostname'] = hostname_cache[machine]

    def get_smb_shares(self) -> Dict[str, Any]:
        """
        Get configured SMB shares from smb.conf via testparm.

        Returns:
            Dictionary with share information:
            - shares: List of {name, path, comment, valid_users, read_only}
        """
        shares = []

        success, output = self.runner.run("testparm -s 2>/dev/null")
        if success and output.strip():
            current_share = None

            for line in output.split('\n'):
                line = line.rstrip()

                # New share section: [share_name]
                if line.startswith('[') and line.endswith(']'):
                    # Save previous share if exists (skip [global])
                    if current_share and current_share['name'] != 'global':
                        shares.append(current_share)

                    share_name = line[1:-1]
                    current_share = {
                        'name': share_name,
                        'path': '',
                        'comment': '',
                        'valid_users': '',
                        'read_only': True,  # Default in Samba
                    }

                # Parse share properties
                elif current_share and '=' in line:
                    # Format: "\tkey = value" or "key = value"
                    line = line.strip()
                    if '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip().lower()
                        value = value.strip()

                        if key == 'path':
                            current_share['path'] = value
                        elif key == 'comment':
                            current_share['comment'] = value
                        elif key == 'valid users':
                            current_share['valid_users'] = value
                        elif key == 'read only':
                            current_share['read_only'] = value.lower() != 'no'

            # Don't forget the last share
            if current_share and current_share['name'] != 'global':
                shares.append(current_share)

        return {'shares': shares}

    def get_nfs_connections(self) -> Dict[str, Any]:
        """
        Get active NFS connections by checking established connections on port 2049.
        Uses ss -i for extended TCP metrics (bytes, RTT, timing).

        Returns:
            Dictionary with NFS connection information including:
            - ip: Client IP address
            - hostname: Reverse DNS hostname (if resolvable)
            - port: Client source port
            - bytes_acked: Bytes acknowledged by client
            - bytes_received: Bytes received from client
            - rtt: Round-trip time in ms
            - lastsnd: Time since last send (ms)
            - lastrcv: Time since last receive (ms)
        """
        connections = []

        # Get established TCP connections on NFS port (2049) with extended info
        # ss -i outputs connection info followed by extended stats on next line
        success, output = self.runner.run(
            "ss -tin state established '( sport = :2049 )' 2>/dev/null"
        )
        if success and output.strip():
            lines = output.strip().split('\n')
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                # Skip header line
                if line.startswith('State') or line.startswith('Recv-Q'):
                    i += 1
                    continue

                # Parse connection line (format: Recv-Q Send-Q Local:Port Peer:Port Process)
                parts = line.split()
                if len(parts) >= 4:
                    # Peer address is typically in position 4 (0-indexed: 3)
                    # Format varies: could be "ip:port" or "[ipv6]:port"
                    peer = parts[3]
                    if peer.startswith('['):
                        # IPv6: [::1]:port
                        bracket_end = peer.rfind(']')
                        ip = peer[1:bracket_end]
                        port = peer[bracket_end+2:] if bracket_end+2 < len(peer) else '-'
                    elif ':' in peer:
                        ip, port = peer.rsplit(':', 1)
                    else:
                        ip = peer
                        port = '-'

                    conn = {
                        'ip': ip,
                        'port': port,
                        'hostname': None,
                        'bytes_acked': None,
                        'bytes_received': None,
                        'rtt': None,
                        'lastsnd': None,
                        'lastrcv': None,
                    }

                    # Check if next line contains extended info (starts with whitespace)
                    if i + 1 < len(lines) and lines[i + 1].startswith('\t'):
                        ext_line = lines[i + 1].strip()
                        # Parse extended stats: bytes_acked:123 bytes_received:456 ...
                        conn['bytes_acked'] = self._parse_ss_metric(ext_line, 'bytes_acked')
                        conn['bytes_received'] = self._parse_ss_metric(ext_line, 'bytes_received')
                        conn['rtt'] = self._parse_ss_metric(ext_line, 'rtt')
                        conn['lastsnd'] = self._parse_ss_metric(ext_line, 'lastsnd')
                        conn['lastrcv'] = self._parse_ss_metric(ext_line, 'lastrcv')
                        i += 1

                    connections.append(conn)
                i += 1

        # Resolve hostnames for unique IPs (with caching)
        self._resolve_hostnames(connections)

        return {'connections': connections}

    def _parse_ss_metric(self, line: str, metric: str) -> Optional[str]:
        """
        Parse a specific metric value from ss -i extended output.

        Args:
            line: The extended stats line from ss -i
            metric: The metric name to extract (e.g., 'bytes_acked', 'rtt')

        Returns:
            The metric value as string, or None if not found
        """
        # Metrics appear as "metric:value" or "metric:value/unit"
        pattern = rf'\b{metric}:(\S+)'
        match = re.search(pattern, line)
        if match:
            return match.group(1)
        return None

    def _resolve_hostnames(self, connections: List[Dict[str, Any]]) -> None:
        """
        Resolve hostnames for connection IPs via reverse DNS.
        Modifies connections in place, adding 'hostname' field.

        Args:
            connections: List of connection dictionaries to update
        """
        # Get unique IPs to avoid redundant lookups
        unique_ips = set(conn['ip'] for conn in connections if conn.get('ip'))
        hostname_cache: Dict[str, Optional[str]] = {}

        for ip in unique_ips:
            try:
                # Reverse DNS lookup with timeout (socket default)
                hostname, _, _ = socket.gethostbyaddr(ip)
                hostname_cache[ip] = hostname
            except (socket.herror, socket.gaierror, socket.timeout):
                # No reverse DNS entry or lookup failed
                hostname_cache[ip] = None

        # Apply resolved hostnames to connections
        for conn in connections:
            ip = conn.get('ip')
            if ip in hostname_cache:
                conn['hostname'] = hostname_cache[ip]

    def get_nfs_exports(self) -> Dict[str, Any]:
        """
        Get configured NFS exports from /etc/exports.

        Returns:
            Dictionary with export information:
            - exports: List of {path, clients, options}
        """
        exports = []

        success, output = self.runner.run("cat /etc/exports 2>/dev/null")
        if success and output.strip():
            for line in output.strip().split('\n'):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                # Format: "/path" client(options) or "/path" *(options)
                # Path may be quoted
                if line.startswith('"'):
                    # Quoted path
                    end_quote = line.find('"', 1)
                    if end_quote == -1:
                        continue
                    path = line[1:end_quote]
                    rest = line[end_quote + 1:].strip()
                else:
                    # Unquoted path
                    parts = line.split(None, 1)
                    if not parts:
                        continue
                    path = parts[0]
                    rest = parts[1] if len(parts) > 1 else ''

                # Parse client(options) - may have multiple
                # Format: client(opts) or *(opts) or client1(opts) client2(opts)
                clients_opts = []
                for entry in rest.split():
                    if '(' in entry:
                        client_part = entry.split('(')[0]
                        opts_part = entry.split('(')[1].rstrip(')')
                        clients_opts.append({
                            'client': client_part if client_part else '*',
                            'options': opts_part,
                        })

                exports.append({
                    'path': path,
                    'clients': clients_opts,
                })

        return {'exports': exports}


def create_pool_panel(pool_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing ZFS pool status.

    Args:
        pool_data: Pool information from get_zpool_status()

    Returns:
        Rich Panel with pool status
    """
    if 'error' in pool_data:
        return Panel(
            Text(f"Error: {pool_data['error']}", style="red"),
            title="[bold blue][1] ZFS Pools[/bold blue]",
            box=box.ROUNDED
        )

    table = Table(box=None, show_header=True, header_style="bold")
    table.add_column("Pool", style="cyan")
    table.add_column("Size")
    table.add_column("Used")
    table.add_column("Free")
    table.add_column("Capacity")
    table.add_column("Health")
    table.add_column("Dedup")

    for pool in pool_data['pools']:
        health_style = "green" if pool['health'] == "ONLINE" else "red bold"
        table.add_row(
            pool['name'],
            pool['size'],
            pool['alloc'],
            pool['free'],
            create_progress_bar(pool['capacity'], 20),
            Text(pool['health'], style=health_style),
            pool['dedup'],
        )

    return Panel(
        table,
        title="[bold blue][1] ZFS Pools[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_dataset_panel(dataset_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing ZFS dataset usage.

    Args:
        dataset_data: Dataset information from get_dataset_usage()

    Returns:
        Rich Panel with dataset usage
    """
    if 'error' in dataset_data:
        return Panel(
            Text(f"Error: {dataset_data['error']}", style="red"),
            title="[bold blue][2] ZFS Datasets[/bold blue]",
            box=box.ROUNDED
        )

    table = Table(box=None, show_header=True, header_style="bold")
    table.add_column("Dataset", style="cyan")
    table.add_column("Used", justify="right")
    table.add_column("Avail", justify="right")
    table.add_column("Compress")

    for ds in dataset_data['datasets']:
        # Indent child datasets
        name = ds['name']
        depth = name.count('/') - 1
        display_name = "  " * depth + name.split('/')[-1] if '/' in name else name

        table.add_row(
            display_name,
            ds['used'],
            ds['avail'],
            ds['compress'],
        )

    return Panel(
        table,
        title="[bold blue][2] ZFS Datasets[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_services_panel(service_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing service status.

    Args:
        service_data: Service information from get_service_status()

    Returns:
        Rich Panel with service status
    """
    table = Table(box=None, show_header=False)
    table.add_column("Service", style="cyan", width=20)
    table.add_column("Status")

    for service, status in service_data['services'].items():
        if status == 'active':
            status_text = Text("● Running", style="green")
        elif status == 'completed':
            status_text = Text("✓ Completed", style="green")
        elif status == 'inactive':
            status_text = Text("○ Stopped", style="yellow")
        elif status == 'failed':
            status_text = Text("✗ Failed", style="red")
        elif status == 'unknown':
            status_text = Text("? Unknown", style="dim")
        else:
            status_text = Text(f"○ {status}", style="yellow")

        table.add_row(service, status_text)

    return Panel(
        table,
        title="[bold blue][3] Services[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_resources_panel(resource_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing system resources.

    Args:
        resource_data: Resource information from get_system_resources()

    Returns:
        Rich Panel with resource status
    """
    content = Table.grid(padding=(0, 2))
    content.add_column(justify="right", style="bold")
    content.add_column(justify="left")

    # Load average
    if 'load' in resource_data:
        load = resource_data['load']
        content.add_row("Load", f"{load['1min']:.2f} / {load['5min']:.2f} / {load['15min']:.2f}")

    # Memory
    if 'memory' in resource_data:
        mem = resource_data['memory']
        mem_text = Text()
        mem_text.append(f"{format_size(mem['used'])} / {format_size(mem['total'])} ")
        mem_text.append_text(create_progress_bar(mem['percent'], 15))
        content.add_row("Memory", mem_text)

    # Uptime
    if 'uptime' in resource_data:
        content.add_row("Uptime", resource_data['uptime'])

    return Panel(
        content,
        title="[bold blue]System Resources[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_network_panel(network_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing network interfaces.

    Args:
        network_data: Network information from get_network_stats()

    Returns:
        Rich Panel with network status
    """
    table = Table(box=None, show_header=True, header_style="bold")
    table.add_column("Interface", style="cyan")
    table.add_column("State")
    table.add_column("IP Address")

    for iface in network_data.get('interfaces', []):
        state_style = "green" if iface['state'] == "UP" else "red"
        ips = ', '.join(iface['ips']) if iface['ips'] else '-'
        table.add_row(
            iface['name'],
            Text(iface['state'], style=state_style),
            ips,
        )

    return Panel(
        table,
        title="[bold blue][4] Network Interfaces[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_smb_panel(smb_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing SMB connections.

    Args:
        smb_data: SMB connection information

    Returns:
        Rich Panel with SMB connections
    """
    connections = smb_data.get('connections', [])

    if not connections:
        content = Text("No active connections", style="dim")
    else:
        table = Table(box=None, show_header=True, header_style="bold")
        table.add_column("User", style="cyan")
        table.add_column("Machine")

        for conn in connections:
            table.add_row(conn['user'], conn['machine'])

        content = table

    return Panel(
        content,
        title=f"[bold blue]SMB ({len(connections)})[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_nfs_panel(nfs_data: Dict[str, Any]) -> Panel:
    """
    Create a panel showing NFS connections.

    Args:
        nfs_data: NFS connection information

    Returns:
        Rich Panel with NFS connections
    """
    connections = nfs_data.get('connections', [])

    if not connections:
        content = Text("No active connections", style="dim")
    else:
        table = Table(box=None, show_header=True, header_style="bold")
        table.add_column("Client IP", style="cyan")

        for conn in connections:
            table.add_row(conn['ip'])

        content = table

    return Panel(
        content,
        title=f"[bold blue]NFS ({len(connections)})[/bold blue]",
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_connections_panel(smb_data: Dict[str, Any], nfs_data: Dict[str, Any], show_smb: bool) -> Panel:
    """
    Create a toggling panel that shows either SMB or NFS connections.

    Args:
        smb_data: SMB connection information
        nfs_data: NFS connection information
        show_smb: If True, show SMB; if False, show NFS

    Returns:
        Rich Panel with connection info
    """
    smb_count = len(smb_data.get('connections', []))
    nfs_count = len(nfs_data.get('connections', []))

    if show_smb:
        connections = smb_data.get('connections', [])
        if not connections:
            content = Text("No active connections", style="dim")
        else:
            # Group by user@machine and count
            user_machine_counts: Dict[str, int] = {}
            for conn in connections:
                key = f"{conn['user']}@{conn['machine']}"
                user_machine_counts[key] = user_machine_counts.get(key, 0) + 1

            table = Table(box=None, show_header=True, header_style="bold")
            table.add_column("User", style="cyan")
            table.add_column("Machine")
            for key, count in user_machine_counts.items():
                user, machine = key.split('@', 1)
                machine_display = f"{machine} (x{count})" if count > 1 else machine
                table.add_row(user, machine_display)
            content = table
        active = "SMB"
        inactive = "NFS"
        active_count = smb_count
        inactive_count = nfs_count
    else:
        connections = nfs_data.get('connections', [])
        if not connections:
            content = Text("No active connections", style="dim")
        else:
            # Count connections per IP
            ip_counts: Dict[str, int] = {}
            for conn in connections:
                ip = conn.get('ip', 'unknown')
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

            table = Table(box=None, show_header=True, header_style="bold")
            table.add_column("Client IP", style="cyan")
            for ip, count in ip_counts.items():
                display = f"{ip} (x{count})" if count > 1 else ip
                table.add_row(display)
            content = table
        active = "NFS"
        inactive = "SMB"
        active_count = nfs_count
        inactive_count = smb_count

    # Title shows active view with count, number hints, and inactive count in dim
    if show_smb:
        title = f"[bold blue][5] SMB ({smb_count})[/bold blue] [dim]| [6] NFS ({nfs_count})[/dim]"
    else:
        title = f"[dim][5] SMB ({smb_count}) |[/dim] [bold blue][6] NFS ({nfs_count})[/bold blue]"

    return Panel(
        content,
        title=title,
        box=box.ROUNDED,
        padding=(0, 1)
    )


def create_dashboard_from_cache(cached_data: Dict[str, Any], mode: str, show_smb: bool = True) -> Layout:
    """
    Create the full dashboard layout from cached data.

    Args:
        cached_data: Pre-fetched data dictionary
        mode: 'local' or 'remote'
        show_smb: If True, show SMB connections; if False, show NFS

    Returns:
        Rich Layout with all panels
    """
    pool_data = cached_data['pool']
    dataset_data = cached_data['dataset']
    service_data = cached_data['service']
    resource_data = cached_data['resource']
    network_data = cached_data['network']
    smb_data = cached_data['smb']
    nfs_data = cached_data['nfs']

    # Create layout
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"Storage Server Dashboard - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Create panels
    pool_panel = create_pool_panel(pool_data)
    dataset_panel = create_dataset_panel(dataset_data)
    services_panel = create_services_panel(service_data)
    resources_panel = create_resources_panel(resource_data)
    network_panel = create_network_panel(network_data)
    connections_panel = create_connections_panel(smb_data, nfs_data, show_smb)

    # Arrange layout
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )

    layout["body"].split_row(
        Layout(name="left"),
        Layout(name="right"),
    )

    layout["left"].split_column(
        Layout(pool_panel, name="pools"),
        Layout(dataset_panel, name="datasets"),
    )

    layout["right"].split_column(
        Layout(resources_panel, name="resources", size=6),
        Layout(services_panel, name="services", size=9),
        Layout(name="right_bottom"),
    )

    layout["right_bottom"].split_row(
        Layout(network_panel, name="network"),
        Layout(connections_panel, name="connections"),
    )

    layout["footer"].update(Panel(
        Text("[1-6] Expand | [t] Toggle SMB/NFS | [q] Quit", justify="center", style="dim"),
        box=box.ROUNDED
    ))

    return layout


def _format_bytes(bytes_str: Optional[str]) -> str:
    """
    Format bytes value from ss output to human-readable format.

    Args:
        bytes_str: Bytes value as string (e.g., '123456')

    Returns:
        Human-readable size string (e.g., '120.5 KB')
    """
    if not bytes_str:
        return '-'
    try:
        bytes_val = int(bytes_str)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(bytes_val) < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} PB"
    except (ValueError, TypeError):
        return bytes_str


def _format_rtt(rtt_str: Optional[str]) -> str:
    """
    Format RTT value from ss output (format: rtt/rttvar).

    Args:
        rtt_str: RTT string (e.g., '0.123/0.045')

    Returns:
        Formatted RTT (e.g., '0.12 ms')
    """
    if not rtt_str:
        return '-'
    # RTT is in format "rtt/rttvar" - extract just the rtt part
    rtt_val = rtt_str.split('/')[0]
    try:
        ms = float(rtt_val)
        return f"{ms:.2f} ms"
    except (ValueError, TypeError):
        return rtt_str


def _format_last_activity(ms_str: Optional[str]) -> str:
    """
    Format last activity time from ss output.

    Args:
        ms_str: Milliseconds as string

    Returns:
        Human-readable time (e.g., '5.2s ago')
    """
    if not ms_str:
        return '-'
    try:
        ms = int(ms_str)
        if ms < 1000:
            return f"{ms}ms ago"
        elif ms < 60000:
            return f"{ms/1000:.1f}s ago"
        else:
            return f"{ms/60000:.1f}m ago"
    except (ValueError, TypeError):
        return ms_str


def _format_client_display(ip: str, hostname: Optional[str], ip_width: int = 15) -> str:
    """
    Format client display string with IP first and consistent spacing.

    Args:
        ip: Client IP address
        hostname: Resolved hostname (or None)
        ip_width: Width to pad IP addresses for alignment (default 15 for xxx.xxx.xxx.xxx)

    Returns:
        Formatted string like "10.27.27.11   hostname" or just "10.27.27.11"
    """
    # Pad IP to consistent width for alignment
    padded_ip = ip.ljust(ip_width)
    if hostname:
        return f"{padded_ip} {hostname}"
    return ip


def create_expanded_nfs_view(nfs_data: Dict[str, Any], nfs_exports: Dict[str, Any], mode: str) -> Layout:
    """
    Create a full-screen expanded view of NFS connections with two sections:
    active TCP connections and configured exports.

    Args:
        nfs_data: NFS connection information from get_nfs_connections()
        nfs_exports: NFS export configuration from get_nfs_exports()
        mode: 'local' or 'remote'

    Returns:
        Rich Layout with expanded NFS view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"NFS Details - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Section 1: Active TCP Connections
    connections = nfs_data.get('connections', [])

    if not connections:
        conn_panel = Panel(
            Text("No active NFS connections", style="dim", justify="center"),
            title=f"[bold blue]Active Connections (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        conn_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        conn_table.add_column("#", style="dim", width=4)
        conn_table.add_column("Client", style="cyan", no_wrap=True)
        conn_table.add_column("Port", style="dim", width=7)
        conn_table.add_column("Sent", justify="right", width=12)
        conn_table.add_column("Recv", justify="right", width=12)
        conn_table.add_column("RTT", justify="right", width=10)
        conn_table.add_column("Last Activity", justify="right", width=12)

        for idx, conn in enumerate(connections, 1):
            # Display IP first with consistent spacing, then hostname
            hostname = conn.get('hostname')
            ip = conn.get('ip', 'unknown')
            client_display = _format_client_display(ip, hostname)

            # Format last activity from lastsnd or lastrcv (whichever is more recent)
            lastsnd = conn.get('lastsnd')
            lastrcv = conn.get('lastrcv')
            last_activity = '-'
            if lastsnd or lastrcv:
                # Use the smaller value (more recent activity)
                try:
                    snd = int(lastsnd) if lastsnd else float('inf')
                    rcv = int(lastrcv) if lastrcv else float('inf')
                    last_ms = str(min(snd, rcv)) if min(snd, rcv) != float('inf') else None
                    last_activity = _format_last_activity(last_ms)
                except (ValueError, TypeError):
                    last_activity = '-'

            conn_table.add_row(
                str(idx),
                client_display,
                conn.get('port', '-'),
                _format_bytes(conn.get('bytes_acked')),
                _format_bytes(conn.get('bytes_received')),
                _format_rtt(conn.get('rtt')),
                last_activity,
            )

        conn_panel = Panel(
            conn_table,
            title=f"[bold blue]Active Connections ({len(connections)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Section 2: Configured Exports
    exports = nfs_exports.get('exports', [])

    if not exports:
        export_panel = Panel(
            Text("No NFS exports configured", style="dim", justify="center"),
            title=f"[bold blue]Configured Exports (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        export_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        export_table.add_column("#", style="dim", width=4)
        export_table.add_column("Export Path", style="green", no_wrap=True)
        export_table.add_column("Allowed Clients", style="cyan")
        export_table.add_column("Options", style="dim")

        for idx, export in enumerate(exports, 1):
            # Format clients and options
            clients_list = export.get('clients', [])
            if clients_list:
                clients_str = ', '.join(c.get('client', '*') for c in clients_list)
                # Show first client's options (typically same for all)
                options_str = clients_list[0].get('options', '') if clients_list else ''
            else:
                clients_str = '*'
                options_str = ''

            export_table.add_row(
                str(idx),
                export.get('path', '-'),
                clients_str,
                options_str,
            )

        export_panel = Panel(
            export_table,
            title=f"[bold blue]Configured Exports ({len(exports)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Footer
    footer = Panel(
        Text("[Esc] Back | [q] Quit", justify="center", style="dim"),
        box=box.ROUNDED
    )

    # Arrange layout with two sections
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
        Layout(footer, name="footer", size=3)
    )

    # Split body into two sections (connections on top, exports below)
    layout["body"].split_column(
        Layout(conn_panel, name="connections"),
        Layout(export_panel, name="exports"),
    )

    return layout


def create_expanded_smb_view(smb_data: Dict[str, Any], smb_shares: Dict[str, Any], mode: str) -> Layout:
    """
    Create a full-screen expanded view of SMB connections with two sections:
    active sessions and configured shares.

    Args:
        smb_data: SMB connection information from get_smb_connections()
        smb_shares: SMB share configuration from get_smb_shares()
        mode: 'local' or 'remote'

    Returns:
        Rich Layout with expanded SMB view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"SMB Details - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Section 1: Active Connections
    connections = smb_data.get('connections', [])

    if not connections:
        conn_panel = Panel(
            Text("No active SMB connections", style="dim", justify="center"),
            title=f"[bold blue]Active Connections (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        conn_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        conn_table.add_column("#", style="dim", width=4)
        conn_table.add_column("Client", style="cyan", no_wrap=True)
        conn_table.add_column("User", style="green")
        conn_table.add_column("Protocol", style="dim", width=10)
        conn_table.add_column("Connected", justify="right", width=10)

        for idx, conn in enumerate(connections, 1):
            # Display machine/IP with hostname using consistent format
            machine = conn.get('machine', 'unknown')
            hostname = conn.get('hostname')
            client_display = _format_client_display(machine, hostname)

            conn_table.add_row(
                str(idx),
                client_display,
                conn.get('user', '-'),
                conn.get('protocol', '-'),
                conn.get('connected', '-'),
            )

        conn_panel = Panel(
            conn_table,
            title=f"[bold blue]Active Connections ({len(connections)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Section 2: Configured Shares
    shares = smb_shares.get('shares', [])

    if not shares:
        share_panel = Panel(
            Text("No SMB shares configured", style="dim", justify="center"),
            title=f"[bold blue]Configured Shares (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        share_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        share_table.add_column("#", style="dim", width=4)
        share_table.add_column("Share", style="cyan", no_wrap=True)
        share_table.add_column("Path", style="green")
        share_table.add_column("Valid Users", style="dim")
        share_table.add_column("Access", width=12)

        for idx, share in enumerate(shares, 1):
            # Format access as Read/Write or Read Only
            access = "Read Only" if share.get('read_only', True) else "Read/Write"
            access_style = "yellow" if share.get('read_only', True) else "green"

            share_table.add_row(
                str(idx),
                share.get('name', '-'),
                share.get('path', '-'),
                share.get('valid_users', '*') or '*',
                Text(access, style=access_style),
            )

        share_panel = Panel(
            share_table,
            title=f"[bold blue]Configured Shares ({len(shares)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Footer
    footer = Panel(
        Text("[Esc] Back | [q] Quit", justify="center", style="dim"),
        box=box.ROUNDED
    )

    # Arrange layout with two sections
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
        Layout(footer, name="footer", size=3)
    )

    # Split body into two sections (connections on top, shares below)
    layout["body"].split_column(
        Layout(conn_panel, name="connections"),
        Layout(share_panel, name="shares"),
    )

    return layout


def create_view(current_view: str, cached_data: Dict[str, Any], mode: str, show_smb: bool) -> Layout:
    """
    Route to appropriate view based on current_view state.

    Args:
        current_view: Current view name ('dashboard', 'nfs', etc.)
        cached_data: Pre-fetched data dictionary
        mode: 'local' or 'remote'
        show_smb: If True, show SMB in connections panel; if False, show NFS

    Returns:
        Rich Layout for the requested view
    """
    if current_view == 'nfs':
        return create_expanded_nfs_view(
            cached_data['nfs'],
            cached_data.get('nfs_exports', {'exports': []}),
            mode
        )
    elif current_view == 'smb':
        return create_expanded_smb_view(
            cached_data['smb'],
            cached_data.get('smb_shares', {'shares': []}),
            mode
        )
    # Future expanded views: pools, datasets, services, network

    # Default: main dashboard
    return create_dashboard_from_cache(cached_data, mode, show_smb)


def create_dashboard(status: StorageStatus, mode: str, show_smb: bool = True) -> Layout:
    """
    Create the full dashboard layout by fetching fresh data.

    Args:
        status: StorageStatus instance
        mode: 'local' or 'remote'
        show_smb: If True, show SMB connections; if False, show NFS

    Returns:
        Rich Layout with all panels
    """
    # Gather all data
    cached_data = {
        'pool': status.get_zpool_status(),
        'dataset': status.get_dataset_usage(),
        'service': status.get_service_status(),
        'resource': status.get_system_resources(),
        'network': status.get_network_stats(),
        'smb': status.get_smb_connections(),
        'nfs': status.get_nfs_connections(),
    }

    return create_dashboard_from_cache(cached_data, mode, show_smb)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Storage Status - Terminal dashboard for Ubuntu/ZFS storage servers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    storage-status              Display full dashboard
    storage-status --remote     Force remote mode (SSH)
    storage-status --local      Force local mode
    storage-status pools        Show only ZFS pool status
    storage-status datasets     Show only ZFS datasets
        '''
    )
    parser.add_argument(
        'view',
        nargs='?',
        choices=['pools', 'datasets', 'services', 'network', 'smb'],
        help='Show specific view only'
    )
    parser.add_argument(
        '--remote',
        action='store_true',
        help='Force remote mode (SSH to storage server)'
    )
    parser.add_argument(
        '--local',
        action='store_true',
        help='Force local mode (run commands directly)'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='Display once and exit (no live refresh)'
    )
    return parser.parse_args()


def validate_config(force_mode: Optional[str]) -> None:
    """
    Validate that required environment variables are set.

    Args:
        force_mode: 'local', 'remote', or None for auto-detect
    """
    if force_mode == 'local':
        return  # No SSH config needed for local mode

    # For remote or auto-detect mode, SSH_HOST is required
    if not SSH_HOST:
        Console().print(
            "[red]Error: STORAGE_SSH_HOST environment variable is required[/red]\n"
            "\nSet the following environment variables:\n"
            "  STORAGE_SSH_HOST    - SSH host/alias for the storage server (required)\n"
            "  STORAGE_HOSTNAME    - Hostname for local detection (optional)\n"
            "  STORAGE_IPS         - Comma-separated IPs for local detection (optional)\n"
            "\nExample:\n"
            "  export STORAGE_SSH_HOST=my-storage-server\n"
            "  export STORAGE_HOSTNAME=ubuntu-storage\n"
            "  export STORAGE_IPS=10.0.0.10,10.0.0.11\n"
        )
        sys.exit(1)


def main():
    """Main entry point for storage status dashboard."""
    console = Console()
    args = parse_args()

    # Determine execution mode
    if args.remote and args.local:
        console.print("[red]Cannot specify both --remote and --local[/red]")
        sys.exit(1)

    force_mode = None
    if args.remote:
        force_mode = 'remote'
    elif args.local:
        force_mode = 'local'

    # Validate configuration
    validate_config(force_mode)

    # Initialize
    runner = CommandRunner(force_mode)
    status = StorageStatus(runner)

    mode = 'local' if runner.is_local else 'remote'
    console.print(f"[bold blue]Storage Status[/bold blue] - Mode: {mode}\n")

    # Single view mode
    if args.view:
        try:
            if args.view == 'pools':
                console.print(create_pool_panel(status.get_zpool_status()))
            elif args.view == 'datasets':
                console.print(create_dataset_panel(status.get_dataset_usage()))
            elif args.view == 'services':
                console.print(create_services_panel(status.get_service_status()))
            elif args.view == 'network':
                console.print(create_network_panel(status.get_network_stats()))
            elif args.view == 'smb':
                console.print(create_smb_panel(status.get_smb_connections()))
        finally:
            runner.cleanup()
        return

    # Full dashboard mode
    if args.once:
        try:
            console.print(create_dashboard(status, mode))
        finally:
            runner.cleanup()
        return

    keyboard = KeyboardListener()

    # Shared state for background data fetching (with proper initial structure)
    cached_data = {
        'pool': {'pools': []},
        'dataset': {'datasets': []},
        'service': {'services': {}},
        'resource': {},
        'network': {'interfaces': []},
        'smb': {'connections': []},
        'smb_shares': {'shares': []},
        'nfs': {'connections': []},
        'nfs_exports': {'exports': []},
    }
    data_lock = threading.Lock()
    fetch_running = True

    def fetch_data():
        """Background thread to fetch data every 5 seconds."""
        nonlocal cached_data
        while fetch_running:
            new_data = {
                'pool': status.get_zpool_status(),
                'dataset': status.get_dataset_usage(),
                'service': status.get_service_status(),
                'resource': status.get_system_resources(),
                'network': status.get_network_stats(),
                'smb': status.get_smb_connections(),
                'smb_shares': status.get_smb_shares(),
                'nfs': status.get_nfs_connections(),
                'nfs_exports': status.get_nfs_exports(),
            }
            with data_lock:
                cached_data = new_data
            # Sleep in small increments so we can exit quickly
            for _ in range(50):  # 5 seconds total
                if not fetch_running:
                    break
                time.sleep(0.1)

    try:
        show_smb = True  # Toggle state for SMB/NFS panel
        current_view = 'dashboard'  # View state: 'dashboard', 'nfs', etc.
        keyboard.start()

        # Start background data fetcher
        fetch_thread = threading.Thread(target=fetch_data, daemon=True)
        fetch_thread.start()

        # Wait for initial data fetch to complete
        while not cached_data.get('pool', {}).get('pools'):
            time.sleep(0.2)

        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while True:
                # Build and display view from cached data
                with data_lock:
                    current_data = cached_data.copy()
                view = create_view(current_view, current_data, mode, show_smb)
                live.update(view)

                # Check for keypress
                key = keyboard.get_key()
                if key:
                    # Number keys for expanded views (only on dashboard)
                    if current_view == 'dashboard' and key == '5':
                        current_view = 'smb'
                    elif current_view == 'dashboard' and key == '6':
                        current_view = 'nfs'
                    # Future: add keys 1-4 for other expanded views

                    # Escape or Backspace to return to dashboard
                    elif key == '\x1b' or key == '\x7f':  # Esc or Backspace
                        current_view = 'dashboard'

                    # Toggle SMB/NFS (only on dashboard)
                    elif current_view == 'dashboard' and (key.lower() == 't' or key == '\t'):
                        show_smb = not show_smb

                    # Quit
                    elif key.lower() == 'q' or key == '\x03':  # 'q' or Ctrl+C
                        break

                time.sleep(0.1)  # Small delay to prevent CPU spinning

    except KeyboardInterrupt:
        pass
    finally:
        fetch_running = False
        keyboard.stop()
        runner.cleanup()
        console.print("\n[dim]Dashboard stopped.[/dim]")


if __name__ == '__main__':
    main()
