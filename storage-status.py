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

Last Updated On: 2025-12-06
"""

import argparse
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
    """

    def __init__(self, force_mode: Optional[str] = None):
        """
        Initialize the command runner.

        Args:
            force_mode: 'local', 'remote', or None for auto-detect
        """
        self.is_local = self._detect_local() if force_mode is None else (force_mode == 'local')
        self.ssh_host = SSH_HOST

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
                    ['ssh', self.ssh_host, command],
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
        Get active SMB connections.

        Returns:
            Dictionary with SMB connection information
        """
        connections = []

        success, output = self.runner.run("smbstatus -b 2>/dev/null | tail -n +5")
        if success and output.strip():
            for line in output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        connections.append({
                            'pid': parts[0],
                            'user': parts[1],
                            'group': parts[2],
                            'machine': parts[3] if len(parts) > 3 else 'unknown',
                        })

        return {'connections': connections}

    def get_nfs_connections(self) -> Dict[str, Any]:
        """
        Get active NFS connections by checking established connections on port 2049.

        Returns:
            Dictionary with NFS connection information
        """
        connections = []

        # Get established TCP connections on NFS port (2049)
        success, output = self.runner.run(
            "ss -tn state established '( sport = :2049 )' 2>/dev/null | tail -n +2"
        )
        if success and output.strip():
            for line in output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        # Peer address is in format ip:port
                        peer = parts[3]
                        ip = peer.rsplit(':', 1)[0] if ':' in peer else peer
                        connections.append({'ip': ip})

        return {'connections': connections}


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
            title="[bold blue]ZFS Pools[/bold blue]",
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
        title="[bold blue]ZFS Pools[/bold blue]",
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
            title="[bold blue]ZFS Datasets[/bold blue]",
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
        title="[bold blue]ZFS Datasets[/bold blue]",
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
        title="[bold blue]Services[/bold blue]",
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
        title="[bold blue]Network Interfaces[/bold blue]",
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
            table = Table(box=None, show_header=True, header_style="bold")
            table.add_column("User", style="cyan")
            table.add_column("Machine")
            for conn in connections:
                table.add_row(conn['user'], conn['machine'])
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
            table = Table(box=None, show_header=True, header_style="bold")
            table.add_column("Client IP", style="cyan")
            for conn in connections:
                table.add_row(conn['ip'])
            content = table
        active = "NFS"
        inactive = "SMB"
        active_count = nfs_count
        inactive_count = smb_count

    # Title shows active view with count, and inactive count in dim
    title = f"[bold blue]{active} ({active_count})[/bold blue] [dim]| {inactive} ({inactive_count})[/dim]"

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
        Text("[t] Toggle SMB/NFS | [q] Quit | Refreshing every 5s", justify="center", style="dim"),
        box=box.ROUNDED
    ))

    return layout


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
        return

    # Full dashboard mode
    if args.once:
        console.print(create_dashboard(status, mode))
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
        'nfs': {'connections': []},
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
                'nfs': status.get_nfs_connections(),
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
        keyboard.start()

        # Start background data fetcher
        fetch_thread = threading.Thread(target=fetch_data, daemon=True)
        fetch_thread.start()

        # Wait for initial data fetch to complete
        while not cached_data.get('pool', {}).get('pools'):
            time.sleep(0.2)

        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while True:
                # Build and display dashboard from cached data
                with data_lock:
                    current_data = cached_data.copy()
                dashboard = create_dashboard_from_cache(current_data, mode, show_smb)
                live.update(dashboard)

                # Check for keypress
                key = keyboard.get_key()
                if key:
                    if key.lower() == 't' or key == '\t':  # 't' or Tab to toggle
                        show_smb = not show_smb
                        # Immediate refresh with cached data (no lock needed, just reading)
                        dashboard = create_dashboard_from_cache(current_data, mode, show_smb)
                        live.update(dashboard)
                    elif key.lower() == 'q' or key == '\x03':  # 'q' or Ctrl+C to quit
                        break

                time.sleep(0.1)  # Small delay to prevent CPU spinning

    except KeyboardInterrupt:
        pass
    finally:
        fetch_running = False
        keyboard.stop()
        console.print("\n[dim]Dashboard stopped.[/dim]")


if __name__ == '__main__':
    main()
