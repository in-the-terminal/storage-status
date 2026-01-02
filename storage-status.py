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

Last Updated On: 2025-12-09
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
import shlex
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
        escape_buffer = ""
        escape_timeout = None

        while self.running:
            # If we have a pending escape sequence, use short timeout
            timeout = 0.02 if escape_buffer else 0.1

            if select.select([sys.stdin], [], [], timeout)[0]:
                try:
                    char = sys.stdin.read(1)

                    if escape_buffer:
                        # We're in the middle of an escape sequence
                        escape_buffer += char

                        # Check if we have a complete arrow key sequence
                        if len(escape_buffer) >= 3 and escape_buffer[1] == '[':
                            key = None
                            if escape_buffer[2] == 'A':
                                key = 'UP'
                            elif escape_buffer[2] == 'B':
                                key = 'DOWN'
                            elif escape_buffer[2] == 'C':
                                key = 'RIGHT'
                            elif escape_buffer[2] == 'D':
                                key = 'LEFT'

                            if key:
                                with self.lock:
                                    self.last_key = key
                            escape_buffer = ""
                            escape_timeout = None
                        elif len(escape_buffer) >= 3:
                            # Unknown escape sequence, discard
                            escape_buffer = ""
                            escape_timeout = None
                    elif char == '\x1b':
                        # Start of escape sequence
                        escape_buffer = char
                        escape_timeout = time.time() + 0.1  # 100ms to complete
                    else:
                        # Regular key
                        with self.lock:
                            self.last_key = char
                except Exception:
                    escape_buffer = ""
                    escape_timeout = None
            elif escape_buffer:
                # Timeout while waiting for escape sequence
                if escape_timeout and time.time() > escape_timeout:
                    # Treat as standalone Escape key
                    with self.lock:
                        self.last_key = '\x1b'
                    escape_buffer = ""
                    escape_timeout = None

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
            command: The command to execute (string for shell execution)
            timeout: Timeout in seconds

        Returns:
            Tuple of (success, output)
        """
        try:
            if self.is_local:
                # For local execution, use shell=True with the command string
                # This is necessary for commands with pipes, redirects, etc.
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

    def run_safe(self, args: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """
        Run a command safely without shell expansion either locally or via SSH.
        This method should be used when incorporating untrusted or external data.

        Args:
            args: List of command arguments (e.g., ['zpool', 'status', pool_name])
            timeout: Timeout in seconds

        Returns:
            Tuple of (success, output)
        """
        try:
            if self.is_local:
                # Use argument list directly for safe execution
                result = subprocess.run(
                    args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                # For SSH, quote each argument and build safe command
                quoted_args = ' '.join(shlex.quote(arg) for arg in args)
                result = subprocess.run(
                    self._get_ssh_command(quoted_args),
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )

            if result.returncode == 0:
                return True, result.stdout
            else:
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


def validate_name(name: str, allowed_chars: str = r'[a-zA-Z0-9._-]') -> Optional[str]:
    """
    Validate a name (pool, interface, etc.) to prevent command injection.
    
    Args:
        name: The name to validate
        allowed_chars: Regex character class of allowed characters
        
    Returns:
        The original name if valid, None if invalid
    """
    if not name:
        return None
    # Check if name contains only allowed characters
    pattern = re.compile(f'^{allowed_chars}+$')
    if pattern.match(name):
        return name
    return None


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
        Get ZFS pool status information with detailed properties.

        Returns:
            Dictionary with pool information including:
            - name: Pool name
            - size: Total size
            - alloc: Allocated space
            - free: Free space
            - capacity: Usage percentage
            - health: Pool health status
            - dedup: Deduplication ratio
            - frag: Fragmentation percentage
            - read_errors: Total read errors across all vdevs
            - write_errors: Total write errors across all vdevs
            - cksum_errors: Total checksum errors across all vdevs
            - scan: Current scan status (scrub/resilver)
            - topology: List of vdevs with their devices
        """
        pools = []

        # Get pool list with fragmentation
        success, output = self.runner.run(
            "zpool list -H -o name,size,alloc,free,cap,health,dedup,frag"
        )
        if not success:
            return {'error': output, 'pools': []}

        pool_names = []
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 8:
                cap = parts[4].replace('%', '')
                frag = parts[7].replace('%', '').replace('-', '0')
                pool_info = {
                    'name': parts[0],
                    'size': parts[1],
                    'alloc': parts[2],
                    'free': parts[3],
                    'capacity': float(cap) if cap.isdigit() else 0,
                    'health': parts[5],
                    'dedup': parts[6],
                    'frag': float(frag) if frag.replace('.', '').isdigit() else 0,
                    'read_errors': 0,
                    'write_errors': 0,
                    'cksum_errors': 0,
                    'scan': None,
                    'topology': [],
                }
                pools.append(pool_info)
                pool_names.append(parts[0])

        # Get detailed status for each pool (topology, errors, scan)
        for pool in pools:
            topology, errors, scan = self._parse_pool_status(pool['name'])
            pool['topology'] = topology
            pool['read_errors'] = errors.get('read', 0)
            pool['write_errors'] = errors.get('write', 0)
            pool['cksum_errors'] = errors.get('cksum', 0)
            pool['scan'] = scan

        # Get vdev sizes from zpool list -v
        vdev_sizes = self._get_vdev_sizes()
        for pool in pools:
            for vdev in pool.get('topology', []):
                vdev_name = vdev.get('name', '')
                if vdev_name in vdev_sizes:
                    vdev['size'] = vdev_sizes[vdev_name].get('size')
                    vdev['alloc'] = vdev_sizes[vdev_name].get('alloc')
                # Also check devices for single-disk vdevs
                for device in vdev.get('devices', []):
                    dev_name = device.get('name', '')
                    if dev_name in vdev_sizes:
                        device['size'] = vdev_sizes[dev_name].get('size')

        return {'pools': pools}

    def _get_vdev_sizes(self) -> Dict[str, Dict[str, str]]:
        """
        Get vdev and device sizes from zpool list -v.

        Returns:
            Dictionary mapping vdev/device names to their size info
        """
        sizes = {}

        # Use -H for tab-separated, -p for parseable (bytes)
        success, output = self.runner.run("zpool list -v -H -p 2>/dev/null")
        use_bytes = True
        if not success:
            # Try without -p (parseable) flag for older ZFS versions
            success, output = self.runner.run("zpool list -v 2>/dev/null")
            use_bytes = False
            if not success:
                return sizes

        for line in output.strip().split('\n'):
            if not line.strip():
                continue

            # Check if line is indented (vdev/device) vs pool name
            # With -H, indented lines start with \t
            # Without -H, indented lines start with spaces
            is_indented = line.startswith('\t') or line.startswith('  ')

            if not is_indented:
                # This is a pool name line, skip it
                continue

            # Parse the line - with -H it's tab-separated
            if '\t' in line:
                parts = [p for p in line.split('\t') if p]  # Filter empty parts
            else:
                parts = line.split()

            if len(parts) >= 2:
                name = parts[0].strip()
                size = parts[1] if len(parts) > 1 else None
                alloc = parts[2] if len(parts) > 2 else None

                # Convert bytes to human-readable if -p was used
                if use_bytes:
                    if size and size.isdigit():
                        size = self._bytes_to_human(int(size))
                    if alloc and alloc.isdigit():
                        alloc = self._bytes_to_human(int(alloc))

                # Filter out '-' values
                if size == '-':
                    size = None
                if alloc == '-':
                    alloc = None

                sizes[name] = {'size': size, 'alloc': alloc}

        return sizes

    def _bytes_to_human(self, bytes_val: int) -> str:
        """
        Convert bytes to human-readable format.

        Args:
            bytes_val: Size in bytes

        Returns:
            Human-readable size string (e.g., '1.5T', '500G')
        """
        for unit in ['B', 'K', 'M', 'G', 'T', 'P']:
            if abs(bytes_val) < 1024.0:
                if unit == 'B':
                    return f"{int(bytes_val)}{unit}"
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f}E"

    def _parse_pool_status(self, pool_name: str) -> Tuple[List[Dict], Dict[str, int], Optional[str]]:
        """
        Parse zpool status output for topology, errors, and scan status.

        Args:
            pool_name: Name of the pool to query

        Returns:
            Tuple of (topology list, error counts dict, scan status string)
        """
        topology = []
        errors = {'read': 0, 'write': 0, 'cksum': 0}
        scan = None

        # Validate pool name to prevent command injection
        safe_pool_name = validate_name(pool_name)
        if not safe_pool_name:
            return topology, errors, scan

        success, output = self.runner.run_safe(['zpool', 'status', safe_pool_name])
        if not success:
            return topology, errors, scan

        lines = output.strip().split('\n')
        in_config = False
        current_vdev = None

        for line in lines:
            # Parse scan status
            if line.strip().startswith('scan:'):
                scan_text = line.split(':', 1)[1].strip()
                # Simplify scan status
                if 'scrub in progress' in scan_text:
                    # Extract progress percentage if available
                    match = re.search(r'(\d+\.?\d*)%', scan_text)
                    if match:
                        scan = f"scrub {match.group(1)}%"
                    else:
                        scan = "scrub in progress"
                elif 'resilver in progress' in scan_text:
                    match = re.search(r'(\d+\.?\d*)%', scan_text)
                    if match:
                        scan = f"resilver {match.group(1)}%"
                    else:
                        scan = "resilver in progress"
                elif 'scrub repaired' in scan_text or 'scrub canceled' in scan_text:
                    scan = "scrub completed"
                elif 'resilvered' in scan_text:
                    scan = "resilver completed"
                continue

            # Detect config section
            if line.strip() == 'config:':
                in_config = True
                continue

            if not in_config:
                continue

            # Skip header line
            if 'NAME' in line and 'STATE' in line:
                continue

            # Skip empty lines and errors section
            if not line.strip() or line.strip().startswith('errors:'):
                continue

            # Parse device/vdev lines
            # Format: "	NAME                      STATE     READ WRITE CKSUM"
            parts = line.split()
            if len(parts) >= 5:
                name = parts[0]
                state = parts[1]
                try:
                    read_err = int(parts[2]) if parts[2].isdigit() else 0
                    write_err = int(parts[3]) if parts[3].isdigit() else 0
                    cksum_err = int(parts[4]) if parts[4].isdigit() else 0
                except (ValueError, IndexError):
                    read_err = write_err = cksum_err = 0

                # Accumulate errors
                errors['read'] += read_err
                errors['write'] += write_err
                errors['cksum'] += cksum_err

                # Determine indent level (vdev vs device)
                indent = len(line) - len(line.lstrip())

                # Pool name is at indent 1, vdevs at 2, devices at 3+
                if indent <= 8:  # vdev level (mirror, raidz, etc.)
                    if name != pool_name:  # Skip pool name itself
                        current_vdev = {
                            'name': name,
                            'state': state,
                            'devices': [],
                            'read_errors': read_err,
                            'write_errors': write_err,
                            'cksum_errors': cksum_err,
                        }
                        topology.append(current_vdev)
                else:  # device level
                    device = {
                        'name': name,
                        'state': state,
                        'read_errors': read_err,
                        'write_errors': write_err,
                        'cksum_errors': cksum_err,
                    }
                    if current_vdev:
                        current_vdev['devices'].append(device)
                    else:
                        # Single disk pool (no vdev grouping)
                        topology.append({
                            'name': name,
                            'state': state,
                            'devices': [],
                            'read_errors': read_err,
                            'write_errors': write_err,
                            'cksum_errors': cksum_err,
                        })

        return topology, errors, scan

    def get_dataset_usage(self) -> Dict[str, Any]:
        """
        Get ZFS dataset usage information with detailed properties.

        Returns:
            Dictionary with dataset information including:
            - name: Dataset name
            - used: Space used by dataset and children
            - avail: Available space
            - refer: Referenced data (data accessible by this dataset)
            - compress: Compression ratio
            - mountpoint: Mount location
            - quota: Space quota (none if unlimited)
            - reservation: Reserved space (none if unreserved)
            - recordsize: Block size
            - snapshots: Number of snapshots for this dataset
        """
        datasets = []

        # Get dataset properties including quota, reservation, recordsize
        success, output = self.runner.run(
            "zfs list -H -o name,used,avail,refer,compressratio,mountpoint,quota,reservation,recordsize"
        )
        if not success:
            return {'error': output, 'datasets': []}

        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 9:
                datasets.append({
                    'name': parts[0],
                    'used': parts[1],
                    'avail': parts[2],
                    'refer': parts[3],
                    'compress': parts[4],
                    'mountpoint': parts[5],
                    'quota': parts[6] if parts[6] != 'none' else None,
                    'reservation': parts[7] if parts[7] != 'none' else None,
                    'recordsize': parts[8],
                    'snapshots': 0,  # Will be populated below
                })

        # Get snapshot counts per dataset
        snapshot_counts = self._get_snapshot_counts()
        for dataset in datasets:
            dataset['snapshots'] = snapshot_counts.get(dataset['name'], 0)

        return {'datasets': datasets}

    def _get_snapshot_counts(self) -> Dict[str, int]:
        """
        Get count of snapshots for each dataset.

        Returns:
            Dictionary mapping dataset names to snapshot counts
        """
        counts = {}

        # List all snapshots and count per dataset
        success, output = self.runner.run("zfs list -H -t snapshot -o name 2>/dev/null")
        if success and output.strip():
            for line in output.strip().split('\n'):
                if '@' in line:
                    # Snapshot format: dataset@snapname
                    dataset_name = line.split('@')[0]
                    counts[dataset_name] = counts.get(dataset_name, 0) + 1

        return counts

    def get_service_status(self) -> Dict[str, Any]:
        """
        Get status of critical services with detailed information.

        Returns:
            Dictionary with service status information including:
            - name: Service name
            - state: active/inactive/failed/completed
            - pid: Main process ID (for running services)
            - memory: Memory usage in bytes
            - runtime: How long service has been running
            - restarts: Number of restarts (NRestarts)
            - description: Human-readable service description
        """
        services = [
            'smbd', 'nfs-server', 'zfs-import-cache', 'zfs-mount', 'ssh',
            'docker', 'containerd', 'rsync', 'rpcbind', 'nfs-mountd',
            'smartd', 'zed', 'cron'
        ]
        status = {}
        detailed_services = []

        # Properties to fetch from systemctl show
        props = 'ActiveState,SubState,MainPID,MemoryCurrent,NRestarts,Description,ActiveEnterTimestamp,Result'

        for service in services:
            # Validate service name as extra safety measure
            safe_service = validate_name(service, r'[a-zA-Z0-9._-]')
            if not safe_service:
                continue
            # Get detailed properties in one call
            success, output = self.runner.run_safe(['systemctl', 'show', '-p', props, safe_service])

            service_info = {
                'name': service,
                'state': 'unknown',
                'pid': None,
                'memory': None,
                'runtime': None,
                'restarts': 0,
                'description': service,
            }

            if success and output.strip():
                props_dict = {}
                for line in output.strip().split('\n'):
                    if '=' in line:
                        key, val = line.split('=', 1)
                        props_dict[key] = val

                # Determine state
                active_state = props_dict.get('ActiveState', 'unknown')
                sub_state = props_dict.get('SubState', '')
                result = props_dict.get('Result', '')

                if active_state == 'active':
                    service_info['state'] = 'active'
                elif active_state == 'inactive':
                    # Check if one-shot service completed successfully
                    if result == 'success':
                        service_info['state'] = 'completed'
                    else:
                        service_info['state'] = 'inactive'
                elif active_state == 'failed':
                    service_info['state'] = 'failed'
                else:
                    service_info['state'] = active_state

                # PID (only meaningful for running services)
                pid = props_dict.get('MainPID', '0')
                if pid and pid != '0':
                    service_info['pid'] = int(pid)

                # Memory (may be unavailable or show as max uint64)
                memory = props_dict.get('MemoryCurrent', '')
                if memory and memory.isdigit():
                    mem_val = int(memory)
                    # Filter out "infinity" value (max uint64)
                    if mem_val < 2**62:
                        service_info['memory'] = mem_val

                # Restarts
                restarts = props_dict.get('NRestarts', '0')
                if restarts.isdigit():
                    service_info['restarts'] = int(restarts)

                # Description
                desc = props_dict.get('Description', service)
                service_info['description'] = desc if desc else service

                # Runtime (calculate from ActiveEnterTimestamp)
                timestamp = props_dict.get('ActiveEnterTimestamp', '')
                if timestamp and active_state == 'active':
                    service_info['runtime'] = self._parse_systemd_timestamp(timestamp)

            # Also store in simple dict for backward compatibility
            status[service] = service_info['state']
            detailed_services.append(service_info)

        return {'services': status, 'detailed': detailed_services}

    def _parse_systemd_timestamp(self, timestamp: str) -> Optional[int]:
        """
        Parse systemd timestamp and return seconds since activation.

        Args:
            timestamp: Systemd timestamp string (e.g., "Sun 2025-12-08 10:30:00 UTC")

        Returns:
            Seconds since activation, or None if parsing fails
        """
        if not timestamp or timestamp == 'n/a':
            return None
        try:
            # Systemd format: "Weekday YYYY-MM-DD HH:MM:SS TZ"
            # Strip weekday and timezone for parsing
            parts = timestamp.split()
            if len(parts) >= 3:
                date_str = f"{parts[1]} {parts[2]}"
                dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                now = datetime.now()
                delta = now - dt
                return int(delta.total_seconds())
        except (ValueError, IndexError):
            pass
        return None

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
        Get network interface statistics including speed, MAC, MTU, and traffic.

        Returns:
            Dictionary with network interface information:
            - name: Interface name
            - state: UP/DOWN
            - ips: List of IP addresses
            - speed: Link speed in Mbps (e.g., 10000 for 10G)
            - mac: MAC address
            - mtu: Maximum transmission unit
            - rx_bytes, rx_packets, rx_errors, rx_dropped: Receive stats
            - tx_bytes, tx_packets, tx_errors, tx_dropped: Transmit stats
        """
        interfaces = []

        # Get basic interface info (name, state, IPs)
        success, output = self.runner.run("ip -br addr | grep -v '^lo'")
        if not success:
            return {'error': output, 'interfaces': []}

        interface_names = []
        for line in output.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                iface = {
                    'name': parts[0],
                    'state': parts[1],
                    'ips': parts[2:] if len(parts) > 2 else [],
                    'speed': None,
                    'mac': None,
                    'mtu': None,
                    'rx_bytes': 0,
                    'rx_packets': 0,
                    'rx_errors': 0,
                    'rx_dropped': 0,
                    'tx_bytes': 0,
                    'tx_packets': 0,
                    'tx_errors': 0,
                    'tx_dropped': 0,
                }
                interfaces.append(iface)
                interface_names.append(parts[0])

        # Get detailed stats for each interface using ip -s link
        success, output = self.runner.run("ip -s link show 2>/dev/null")
        if success and output.strip():
            self._parse_link_stats(output, interfaces)

        # Get speed for each interface from sysfs
        for iface in interfaces:
            name = iface['name']
            # Validate interface name to prevent path traversal/command injection
            # Note: colons removed from allowed chars as they're not typical in interface names
            safe_name = validate_name(name, r'[a-zA-Z0-9._-]')
            if not safe_name:
                continue
            # Use run_safe for consistent security approach
            success, speed = self.runner.run_safe(['cat', f'/sys/class/net/{safe_name}/speed'])
            if success and speed.strip().lstrip('-').isdigit():
                iface['speed'] = int(speed.strip())

        return {'interfaces': interfaces}

    def _parse_link_stats(self, output: str, interfaces: List[Dict[str, Any]]) -> None:
        """
        Parse ip -s link output to extract MAC, MTU, and traffic statistics.

        Args:
            output: Output from ip -s link show
            interfaces: List of interface dicts to update in place
        """
        # Create lookup by interface name
        iface_lookup = {iface['name']: iface for iface in interfaces}

        current_iface = None
        lines = output.strip().split('\n')
        i = 0

        while i < len(lines):
            line = lines[i]

            # Interface line: "2: eno1: <...> mtu 1500 ..."
            if line and line[0].isdigit() and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    name = parts[1].strip().split('@')[0]  # Handle veth@if... names
                    if name in iface_lookup:
                        current_iface = iface_lookup[name]
                        # Extract MTU from this line
                        mtu_match = re.search(r'mtu (\d+)', line)
                        if mtu_match:
                            current_iface['mtu'] = int(mtu_match.group(1))

            # MAC address line: "    link/ether 00:10:9b:20:c9:2a ..."
            elif current_iface and 'link/ether' in line:
                mac_match = re.search(r'link/ether ([0-9a-f:]+)', line)
                if mac_match:
                    current_iface['mac'] = mac_match.group(1)

            # RX stats line (after "RX:" header)
            elif current_iface and line.strip().startswith('RX:'):
                # Next line has the actual values
                if i + 1 < len(lines):
                    i += 1
                    values = lines[i].split()
                    if len(values) >= 4:
                        try:
                            current_iface['rx_bytes'] = int(values[0])
                            current_iface['rx_packets'] = int(values[1])
                            current_iface['rx_errors'] = int(values[2])
                            current_iface['rx_dropped'] = int(values[3])
                        except (ValueError, IndexError):
                            pass

            # TX stats line (after "TX:" header)
            elif current_iface and line.strip().startswith('TX:'):
                # Next line has the actual values
                if i + 1 < len(lines):
                    i += 1
                    values = lines[i].split()
                    if len(values) >= 4:
                        try:
                            current_iface['tx_bytes'] = int(values[0])
                            current_iface['tx_packets'] = int(values[1])
                            current_iface['tx_errors'] = int(values[2])
                            current_iface['tx_dropped'] = int(values[3])
                        except (ValueError, IndexError):
                            pass

            i += 1

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
        # Set socket timeout for DNS lookups to prevent hanging
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            for machine in machines_to_resolve:
                try:
                    hostname, _, _ = socket.gethostbyaddr(machine)
                    hostname_cache[machine] = hostname
                except (socket.herror, socket.gaierror, socket.timeout):
                    hostname_cache[machine] = None
        finally:
            socket.setdefaulttimeout(old_timeout)

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

        # Set socket timeout for DNS lookups to prevent hanging
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            for ip in unique_ips:
                try:
                    # Reverse DNS lookup with timeout
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    hostname_cache[ip] = hostname
                except (socket.herror, socket.gaierror, socket.timeout):
                    # No reverse DNS entry or lookup failed
                    hostname_cache[ip] = None
        finally:
            socket.setdefaulttimeout(old_timeout)

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


def _format_speed(speed: Optional[int]) -> str:
    """
    Format link speed in Mbps to human-readable format.

    Args:
        speed: Link speed in Mbps (e.g., 10000 for 10G)

    Returns:
        Formatted speed string (e.g., '10G', '1G', '100M')
    """
    if speed is None or speed < 0:
        return '-'
    if speed >= 1000:
        return f"{speed // 1000}G"
    return f"{speed}M"


def _count_pool_topology_lines(pool_data: Dict[str, Any]) -> int:
    """
    Count the number of lines in the pool topology display.

    Args:
        pool_data: Pool information from get_zpool_status()

    Returns:
        Total number of lines in topology section
    """
    count = 0
    pools = pool_data.get('pools', [])

    for pool in pools:
        topology = pool.get('topology', [])
        if not topology:
            count += 1  # "No vdev information" line
            continue

        count += 1  # Pool header line

        for vdev in topology:
            count += 1  # Vdev line
            devices = vdev.get('devices', [])
            count += len(devices)  # Device lines

        count += 1  # Blank line between pools (except last)

    # Remove trailing blank line
    if count > 0 and pools:
        count -= 1

    return count


def _format_traffic_bytes(bytes_val: Optional[int]) -> str:
    """
    Format traffic bytes to human-readable format.

    Args:
        bytes_val: Bytes value as integer

    Returns:
        Human-readable size string (e.g., '1.5 GB')
    """
    if bytes_val is None:
        return '-'
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def _format_runtime(seconds: Optional[int]) -> str:
    """
    Format runtime in seconds to human-readable format.

    Args:
        seconds: Runtime in seconds

    Returns:
        Formatted runtime string (e.g., '2d 5h', '3h 45m', '15m')
    """
    if seconds is None:
        return '-'
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"


def create_expanded_pools_view(
    pool_data: Dict[str, Any],
    mode: str,
    scroll_offset: int = 0,
    page_size: int = 15
) -> Layout:
    """
    Create a full-screen expanded view of ZFS pools with two sections:
    pool summary on top, vdev/disk topology below.

    Args:
        pool_data: Pool information from get_zpool_status()
        mode: 'local' or 'remote'
        scroll_offset: Starting line index for topology display (for pagination)
        page_size: Number of topology lines to display per page

    Returns:
        Rich Layout with expanded pools view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"ZFS Pools - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    pools = pool_data.get('pools', [])

    # Section 1: Pool Summary
    if not pools:
        summary_panel = Panel(
            Text("No ZFS pools found", style="dim", justify="center"),
            title="[bold blue]Pool Summary (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        summary_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        summary_table.add_column("#", style="dim", width=3)
        summary_table.add_column("Pool", style="cyan", no_wrap=True)
        summary_table.add_column("Size", justify="right", width=8)
        summary_table.add_column("Alloc", justify="right", width=8)
        summary_table.add_column("Free", justify="right", width=8)
        summary_table.add_column("Cap", justify="right", width=5)
        summary_table.add_column("Frag", justify="right", width=5)
        summary_table.add_column("Dedup", justify="right", width=6)
        summary_table.add_column("Health", width=10)
        summary_table.add_column("Errors", justify="right", width=8)
        summary_table.add_column("Scan", style="dim")

        for idx, pool in enumerate(pools, 1):
            # Format capacity with color
            cap = pool.get('capacity', 0)
            cap_str = f"{int(cap)}%"
            if cap >= 90:
                cap_text = Text(cap_str, style="red")
            elif cap >= 75:
                cap_text = Text(cap_str, style="yellow")
            else:
                cap_text = Text(cap_str, style="green")

            # Format fragmentation
            frag = pool.get('frag', 0)
            frag_str = f"{int(frag)}%"
            if frag >= 50:
                frag_text = Text(frag_str, style="yellow")
            else:
                frag_text = Text(frag_str, style="dim")

            # Format health with color
            health = pool.get('health', 'UNKNOWN')
            if health == 'ONLINE':
                health_text = Text(health, style="green")
            elif health == 'DEGRADED':
                health_text = Text(health, style="yellow")
            elif health in ('FAULTED', 'OFFLINE', 'UNAVAIL'):
                health_text = Text(health, style="red")
            else:
                health_text = Text(health, style="dim")

            # Format errors
            total_errors = (pool.get('read_errors', 0) +
                          pool.get('write_errors', 0) +
                          pool.get('cksum_errors', 0))
            if total_errors > 0:
                errors_text = Text(str(total_errors), style="red")
            else:
                errors_text = Text("0", style="dim")

            # Format scan status
            scan = pool.get('scan') or '-'

            summary_table.add_row(
                str(idx),
                pool.get('name', '-'),
                pool.get('size', '-'),
                pool.get('alloc', '-'),
                pool.get('free', '-'),
                cap_text,
                frag_text,
                pool.get('dedup', '-'),
                health_text,
                errors_text,
                scan,
            )

        summary_panel = Panel(
            summary_table,
            title=f"[bold blue]Pool Summary ({len(pools)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Section 2: Vdev Topology
    topology_content = []
    for pool in pools:
        pool_name = pool.get('name', 'unknown')
        topology = pool.get('topology', [])

        if not topology:
            topology_content.append(Text(f"  {pool_name}: No vdev information", style="dim"))
            continue

        # Pool header with total size
        pool_size = pool.get('size', '')
        pool_header = f"  {pool_name}"
        if pool_size:
            pool_header += f" [dim]({pool_size})[/dim]"
        topology_content.append(Text.from_markup(f"[bold cyan]{pool_header}[/bold cyan]"))

        for vdev in topology:
            vdev_name = vdev.get('name', 'unknown')
            vdev_state = vdev.get('state', 'UNKNOWN')
            vdev_size = vdev.get('size')
            devices = vdev.get('devices', [])

            # Format vdev state
            if vdev_state == 'ONLINE':
                state_style = "green"
            elif vdev_state == 'DEGRADED':
                state_style = "yellow"
            else:
                state_style = "red"

            # Format vdev errors
            vdev_errors = (vdev.get('read_errors', 0) +
                         vdev.get('write_errors', 0) +
                         vdev.get('cksum_errors', 0))
            error_suffix = f" [red]({vdev_errors} errors)[/red]" if vdev_errors > 0 else ""

            # Format size info for vdev
            size_info = f" [dim]{vdev_size}[/dim]" if vdev_size else ""

            if devices:
                # This is a vdev group (mirror, raidz, etc.)
                # Determine vdev type from name (mirror-0, raidz1-0, etc.)
                vdev_type = vdev_name.split('-')[0] if '-' in vdev_name else vdev_name
                topology_content.append(Text.from_markup(
                    f"    ├─ {vdev_name} [bold]{vdev_type.upper()}[/bold]{size_info} [{state_style}]{vdev_state}[/{state_style}]{error_suffix}"
                ))
                for i, device in enumerate(devices):
                    dev_name = device.get('name', 'unknown')
                    dev_state = device.get('state', 'UNKNOWN')
                    dev_size = device.get('size')
                    dev_errors = (device.get('read_errors', 0) +
                                device.get('write_errors', 0) +
                                device.get('cksum_errors', 0))

                    if dev_state == 'ONLINE':
                        dev_style = "green"
                    elif dev_state == 'DEGRADED':
                        dev_style = "yellow"
                    else:
                        dev_style = "red"

                    prefix = "│     └─" if i == len(devices) - 1 else "│     ├─"
                    error_info = f" [red]({dev_errors} errors)[/red]" if dev_errors > 0 else ""
                    dev_size_info = f" [dim]{dev_size}[/dim]" if dev_size else ""
                    topology_content.append(Text.from_markup(
                        f"    {prefix} {dev_name}{dev_size_info} [{dev_style}]{dev_state}[/{dev_style}]{error_info}"
                    ))
            else:
                # Single disk (no children) - show as DISK type
                dev_size_info = f" [dim]{vdev_size}[/dim]" if vdev_size else ""
                topology_content.append(Text.from_markup(
                    f"    └─ {vdev_name} [bold]DISK[/bold]{dev_size_info} [{state_style}]{vdev_state}[/{state_style}]{error_suffix}"
                ))

        topology_content.append(Text(""))  # Blank line between pools

    total_lines = len(topology_content)

    if topology_content:
        # Remove trailing blank line for counting
        if topology_content and str(topology_content[-1]) == "":
            topology_content.pop()
            total_lines = len(topology_content)

        # Apply pagination to topology
        visible_lines = topology_content[scroll_offset:scroll_offset + page_size]

        topology_text = Text()
        for line in visible_lines:
            topology_text.append(line)
            topology_text.append("\n")

        # Build title with scroll indicator if needed
        if total_lines > page_size:
            end_idx = min(scroll_offset + page_size, total_lines)
            scroll_indicator = f" [{scroll_offset + 1}-{end_idx} of {total_lines}]"
            up_arrow = "↑" if scroll_offset > 0 else " "
            down_arrow = "↓" if scroll_offset + page_size < total_lines else " "
            title = f"[bold blue]Vdev Topology{scroll_indicator} {up_arrow}{down_arrow}[/bold blue]"
        else:
            title = "[bold blue]Vdev Topology[/bold blue]"

        topology_panel = Panel(
            topology_text,
            title=title,
            box=box.ROUNDED,
            padding=(0, 1)
        )
    else:
        topology_panel = Panel(
            Text("No topology information available", style="dim", justify="center"),
            title="[bold blue]Vdev Topology[/bold blue]",
            box=box.ROUNDED
        )
        total_lines = 0

    # Footer with scroll controls if paginated
    if total_lines > page_size:
        footer_text = "[↑/↓] Scroll | [Esc] Back | [q] Quit"
    else:
        footer_text = "[Esc] Back | [q] Quit"

    footer = Panel(
        Text(footer_text, justify="center", style="dim"),
        box=box.ROUNDED
    )

    # Arrange layout with two sections
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(name="body"),
        Layout(footer, name="footer", size=3)
    )

    # Split body into two sections (summary on top, topology below)
    layout["body"].split_column(
        Layout(summary_panel, name="summary"),
        Layout(topology_panel, name="topology"),
    )

    return layout


def create_expanded_datasets_view(
    dataset_data: Dict[str, Any],
    mode: str,
    scroll_offset: int = 0,
    page_size: int = 20
) -> Layout:
    """
    Create a full-screen expanded view of ZFS datasets with a single
    comprehensive table showing all dataset properties.

    Args:
        dataset_data: Dataset information from get_dataset_usage()
        mode: 'local' or 'remote'
        scroll_offset: Starting index for display (for pagination)
        page_size: Number of datasets to display per page

    Returns:
        Rich Layout with expanded datasets view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"ZFS Datasets - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Build dataset table
    datasets = dataset_data.get('datasets', [])
    total_datasets = len(datasets)

    if not datasets:
        content_panel = Panel(
            Text("No ZFS datasets found", style="dim", justify="center"),
            title="[bold blue]ZFS Datasets (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        # Create comprehensive table
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)

        table.add_column("#", style="dim", width=3)
        table.add_column("Dataset", style="cyan", no_wrap=True)
        table.add_column("Used", justify="right", width=8)
        table.add_column("Avail", justify="right", width=8)
        table.add_column("Refer", justify="right", width=8)
        table.add_column("Ratio", justify="right", width=6)
        table.add_column("Quota", justify="right", width=8)
        table.add_column("Reserv", justify="right", width=8)
        table.add_column("Record", justify="right", width=7)
        table.add_column("Snaps", justify="right", width=5)
        table.add_column("Mountpoint", style="dim", no_wrap=True)

        # Apply pagination
        visible_datasets = datasets[scroll_offset:scroll_offset + page_size]

        for idx, ds in enumerate(visible_datasets, scroll_offset + 1):
            # Format dataset name with indentation for hierarchy
            name = ds.get('name', '-')
            depth = name.count('/')
            if depth > 0:
                # Show only the last component with indentation
                short_name = '  ' * depth + name.split('/')[-1]
            else:
                short_name = name

            # Format quota/reservation (show '-' if None)
            quota = ds.get('quota') or '-'
            reservation = ds.get('reservation') or '-'

            # Format snapshot count with color if > 0
            snap_count = ds.get('snapshots', 0)
            if snap_count > 0:
                snap_text = Text(str(snap_count), style="cyan")
            else:
                snap_text = Text("0", style="dim")

            # Truncate mountpoint if too long
            mountpoint = ds.get('mountpoint', '-')
            if len(mountpoint) > 25:
                mountpoint = '...' + mountpoint[-22:]

            table.add_row(
                str(idx),
                short_name,
                ds.get('used', '-'),
                ds.get('avail', '-'),
                ds.get('refer', '-'),
                ds.get('compress', '-'),
                quota,
                reservation,
                ds.get('recordsize', '-'),
                snap_text,
                mountpoint,
            )

        # Build title with scroll indicator if needed
        if total_datasets > page_size:
            end_idx = min(scroll_offset + page_size, total_datasets)
            scroll_indicator = f" [{scroll_offset + 1}-{end_idx} of {total_datasets}]"
            up_arrow = "↑" if scroll_offset > 0 else " "
            down_arrow = "↓" if scroll_offset + page_size < total_datasets else " "
            title = f"[bold blue]ZFS Datasets ({total_datasets}){scroll_indicator} {up_arrow}{down_arrow}[/bold blue]"
        else:
            title = f"[bold blue]ZFS Datasets ({total_datasets})[/bold blue]"

        content_panel = Panel(
            table,
            title=title,
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Footer with scroll controls if paginated
    if total_datasets > page_size:
        footer_text = "[↑/↓] Scroll | [Esc] Back | [q] Quit"
    else:
        footer_text = "[Esc] Back | [q] Quit"

    footer = Panel(
        Text(footer_text, justify="center", style="dim"),
        box=box.ROUNDED
    )

    # Arrange layout - single content section
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(content_panel, name="body"),
        Layout(footer, name="footer", size=3)
    )

    return layout


def create_expanded_services_view(service_data: Dict[str, Any], mode: str) -> Layout:
    """
    Create a full-screen expanded view of services with two sections:
    running/active services on top, stopped/failed services below.

    Args:
        service_data: Service information from get_service_status()
        mode: 'local' or 'remote'

    Returns:
        Rich Layout with expanded services view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"Services - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Get detailed service list
    detailed = service_data.get('detailed', [])

    # Split into running and stopped/failed
    running_services = []
    stopped_services = []

    for svc in detailed:
        state = svc.get('state', 'unknown')
        if state in ('active', 'completed'):
            running_services.append(svc)
        else:
            stopped_services.append(svc)

    # Section 1: Running Services
    if not running_services:
        running_panel = Panel(
            Text("No services running", style="dim", justify="center"),
            title="[bold green]Running Services (0)[/bold green]",
            box=box.ROUNDED
        )
    else:
        running_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        running_table.add_column("#", style="dim", width=3)
        running_table.add_column("Service", style="cyan", no_wrap=True, width=18)
        running_table.add_column("State", width=10)
        running_table.add_column("PID", justify="right", width=7)
        running_table.add_column("Memory", justify="right", width=10)
        running_table.add_column("Runtime", justify="right", width=10)
        running_table.add_column("Restarts", justify="right", width=8)
        running_table.add_column("Description", style="dim", no_wrap=True)

        for idx, svc in enumerate(running_services, 1):
            state = svc.get('state', 'unknown')
            if state == 'active':
                state_text = Text("● active", style="green")
            else:  # completed
                state_text = Text("✓ done", style="green")

            # Format memory
            memory = svc.get('memory')
            if memory is not None:
                memory_str = _format_traffic_bytes(memory)
            else:
                memory_str = '-'

            # Format restarts with color if > 0
            restarts = svc.get('restarts', 0)
            if restarts > 0:
                restarts_text = Text(str(restarts), style="yellow")
            else:
                restarts_text = Text("0", style="dim")

            # Truncate description if too long
            desc = svc.get('description', '-')
            if len(desc) > 40:
                desc = desc[:37] + '...'

            running_table.add_row(
                str(idx),
                svc.get('name', '-'),
                state_text,
                str(svc.get('pid', '-')) if svc.get('pid') else '-',
                memory_str,
                _format_runtime(svc.get('runtime')),
                restarts_text,
                desc,
            )

        running_panel = Panel(
            running_table,
            title=f"[bold green]Running Services ({len(running_services)})[/bold green]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Section 2: Stopped/Failed Services
    if not stopped_services:
        stopped_panel = Panel(
            Text("All services running", style="dim", justify="center"),
            title="[bold yellow]Stopped/Failed Services (0)[/bold yellow]",
            box=box.ROUNDED
        )
    else:
        stopped_table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)
        stopped_table.add_column("#", style="dim", width=3)
        stopped_table.add_column("Service", style="cyan", no_wrap=True, width=18)
        stopped_table.add_column("State", width=10)
        stopped_table.add_column("Restarts", justify="right", width=8)
        stopped_table.add_column("Description", style="dim", no_wrap=True)

        for idx, svc in enumerate(stopped_services, 1):
            state = svc.get('state', 'unknown')
            if state == 'failed':
                state_text = Text("✗ failed", style="red")
            elif state == 'inactive':
                state_text = Text("○ stopped", style="yellow")
            else:
                state_text = Text(state, style="dim")

            # Format restarts with color if > 0
            restarts = svc.get('restarts', 0)
            if restarts > 0:
                restarts_text = Text(str(restarts), style="yellow")
            else:
                restarts_text = Text("0", style="dim")

            # Truncate description if too long
            desc = svc.get('description', '-')
            if len(desc) > 50:
                desc = desc[:47] + '...'

            stopped_table.add_row(
                str(idx),
                svc.get('name', '-'),
                state_text,
                restarts_text,
                desc,
            )

        stopped_panel = Panel(
            stopped_table,
            title=f"[bold yellow]Stopped/Failed Services ({len(stopped_services)})[/bold yellow]",
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

    # Split body into two sections (running on top, stopped below)
    layout["body"].split_column(
        Layout(running_panel, name="running"),
        Layout(stopped_panel, name="stopped"),
    )

    return layout


def create_expanded_network_view(network_data: Dict[str, Any], mode: str) -> Layout:
    """
    Create a full-screen expanded view of network interfaces with a single
    comprehensive table showing interface details and traffic statistics.

    Args:
        network_data: Network interface information from get_network_stats()
        mode: 'local' or 'remote'

    Returns:
        Rich Layout with expanded network view
    """
    layout = Layout()

    # Header
    mode_text = "Local" if mode == 'local' else f"Remote ({SSH_HOST})"
    header = Panel(
        Text(f"Network Interfaces - {mode_text} - {datetime.now().strftime('%H:%M:%S')}",
             justify="center", style="bold"),
        box=box.ROUNDED
    )

    # Build interface table
    interfaces = network_data.get('interfaces', [])

    if not interfaces:
        content_panel = Panel(
            Text("No network interfaces found", style="dim", justify="center"),
            title="[bold blue]Network Interfaces (0)[/bold blue]",
            box=box.ROUNDED
        )
    else:
        # Create comprehensive table with all info
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold", expand=True)

        # Interface identity columns
        table.add_column("#", style="dim", width=3)
        table.add_column("Interface", style="cyan", no_wrap=True)
        table.add_column("State", width=6)
        table.add_column("Speed", justify="right", width=6)
        table.add_column("MAC", style="dim", width=18)
        table.add_column("MTU", justify="right", width=5)
        table.add_column("IP Addresses", style="green")

        # Traffic stats columns
        table.add_column("RX", justify="right", width=10)
        table.add_column("TX", justify="right", width=10)
        table.add_column("Errors", justify="right", width=8)

        for idx, iface in enumerate(interfaces, 1):
            # Format state with color
            state = iface.get('state', 'UNKNOWN')
            if state == 'UP':
                state_text = Text("UP", style="green")
            elif state == 'DOWN':
                state_text = Text("DOWN", style="red")
            else:
                state_text = Text(state, style="yellow")

            # Format IP addresses (may have multiple)
            ips = iface.get('ips', [])
            # Strip CIDR notation for cleaner display
            ip_list = [ip.split('/')[0] for ip in ips]
            ip_display = ', '.join(ip_list) if ip_list else '-'

            # Calculate total errors (RX + TX errors + dropped)
            rx_errors = iface.get('rx_errors', 0) or 0
            tx_errors = iface.get('tx_errors', 0) or 0
            rx_dropped = iface.get('rx_dropped', 0) or 0
            tx_dropped = iface.get('tx_dropped', 0) or 0
            total_errors = rx_errors + tx_errors + rx_dropped + tx_dropped

            # Format errors with color if non-zero
            if total_errors > 0:
                error_text = Text(str(total_errors), style="red")
            else:
                error_text = Text("0", style="dim")

            table.add_row(
                str(idx),
                iface.get('name', '-'),
                state_text,
                _format_speed(iface.get('speed')),
                iface.get('mac', '-') or '-',
                str(iface.get('mtu', '-')) if iface.get('mtu') else '-',
                ip_display,
                _format_traffic_bytes(iface.get('rx_bytes')),
                _format_traffic_bytes(iface.get('tx_bytes')),
                error_text,
            )

        content_panel = Panel(
            table,
            title=f"[bold blue]Network Interfaces ({len(interfaces)})[/bold blue]",
            box=box.ROUNDED,
            padding=(0, 1)
        )

    # Footer
    footer = Panel(
        Text("[Esc] Back | [q] Quit", justify="center", style="dim"),
        box=box.ROUNDED
    )

    # Arrange layout - single content section (no split)
    layout.split_column(
        Layout(header, name="header", size=3),
        Layout(content_panel, name="body"),
        Layout(footer, name="footer", size=3)
    )

    return layout


def create_expanded_nfs_view(
    nfs_data: Dict[str, Any],
    nfs_exports: Dict[str, Any],
    mode: str,
    scroll_offset: int = 0,
    page_size: int = 12
) -> Layout:
    """
    Create a full-screen expanded view of NFS connections with two sections:
    active TCP connections and configured exports.

    Args:
        nfs_data: NFS connection information from get_nfs_connections()
        nfs_exports: NFS export configuration from get_nfs_exports()
        mode: 'local' or 'remote'
        scroll_offset: Starting index for connection display (for pagination)
        page_size: Number of connections to display per page

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
    total_connections = len(connections)

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

        # Apply pagination - show only a window of connections
        visible_connections = connections[scroll_offset:scroll_offset + page_size]

        for idx, conn in enumerate(visible_connections, scroll_offset + 1):
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

        # Build title with scroll indicator if needed
        if total_connections > page_size:
            end_idx = min(scroll_offset + page_size, total_connections)
            scroll_indicator = f" [{scroll_offset + 1}-{end_idx} of {total_connections}]"
            # Add arrow hints
            up_arrow = "↑" if scroll_offset > 0 else " "
            down_arrow = "↓" if scroll_offset + page_size < total_connections else " "
            title = f"[bold blue]Active Connections ({total_connections}){scroll_indicator} {up_arrow}{down_arrow}[/bold blue]"
        else:
            title = f"[bold blue]Active Connections ({total_connections})[/bold blue]"

        conn_panel = Panel(
            conn_table,
            title=title,
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

    # Footer with scroll controls if there are more connections than page size
    if total_connections > page_size:
        footer_text = "[↑/↓] Scroll | [Esc] Back | [q] Quit"
    else:
        footer_text = "[Esc] Back | [q] Quit"

    footer = Panel(
        Text(footer_text, justify="center", style="dim"),
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


def create_view(
    current_view: str,
    cached_data: Dict[str, Any],
    mode: str,
    show_smb: bool,
    scroll_offset: int = 0
) -> Layout:
    """
    Route to appropriate view based on current_view state.

    Args:
        current_view: Current view name ('dashboard', 'nfs', etc.)
        cached_data: Pre-fetched data dictionary
        mode: 'local' or 'remote'
        show_smb: If True, show SMB in connections panel; if False, show NFS
        scroll_offset: Scroll position for paginated views

    Returns:
        Rich Layout for the requested view
    """
    if current_view == 'nfs':
        return create_expanded_nfs_view(
            cached_data['nfs'],
            cached_data.get('nfs_exports', {'exports': []}),
            mode,
            scroll_offset=scroll_offset
        )
    elif current_view == 'smb':
        return create_expanded_smb_view(
            cached_data['smb'],
            cached_data.get('smb_shares', {'shares': []}),
            mode
        )
    elif current_view == 'network':
        return create_expanded_network_view(
            cached_data['network'],
            mode
        )
    elif current_view == 'services':
        return create_expanded_services_view(
            cached_data['service'],
            mode
        )
    elif current_view == 'datasets':
        return create_expanded_datasets_view(
            cached_data['dataset'],
            mode,
            scroll_offset=scroll_offset
        )
    elif current_view == 'pools':
        return create_expanded_pools_view(
            cached_data['pool'],
            mode,
            scroll_offset=scroll_offset
        )

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
        scroll_offset = 0  # Scroll position for paginated views
        page_size = 12  # Number of items per page (matches create_expanded_nfs_view default)
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
                view = create_view(current_view, current_data, mode, show_smb, scroll_offset)
                live.update(view)

                # Check for keypress
                key = keyboard.get_key()
                if key:
                    # Number keys for expanded views (only on dashboard)
                    if current_view == 'dashboard' and key == '1':
                        current_view = 'pools'
                        scroll_offset = 0  # Reset scroll on view change
                    elif current_view == 'dashboard' and key == '2':
                        current_view = 'datasets'
                        scroll_offset = 0  # Reset scroll on view change
                    elif current_view == 'dashboard' and key == '3':
                        current_view = 'services'
                        scroll_offset = 0  # Reset scroll on view change
                    elif current_view == 'dashboard' and key == '4':
                        current_view = 'network'
                        scroll_offset = 0  # Reset scroll on view change
                    elif current_view == 'dashboard' and key == '5':
                        current_view = 'smb'
                        scroll_offset = 0  # Reset scroll on view change
                    elif current_view == 'dashboard' and key == '6':
                        current_view = 'nfs'
                        scroll_offset = 0  # Reset scroll on view change

                    # Scroll up (arrow up or k for vim-style)
                    elif current_view in ('nfs', 'datasets', 'pools') and (key == 'UP' or key == 'k'):
                        scroll_offset = max(0, scroll_offset - 1)

                    # Scroll down (arrow down or j for vim-style)
                    elif current_view in ('nfs', 'datasets', 'pools') and (key == 'DOWN' or key == 'j'):
                        # Get total items to prevent scrolling past end
                        if current_view == 'nfs':
                            total = len(current_data.get('nfs', {}).get('connections', []))
                            view_page_size = page_size  # 12
                        elif current_view == 'datasets':
                            total = len(current_data.get('dataset', {}).get('datasets', []))
                            view_page_size = 20
                        elif current_view == 'pools':
                            # Count topology lines for pools
                            total = _count_pool_topology_lines(current_data.get('pool', {}))
                            view_page_size = 15
                        else:
                            total = 0
                            view_page_size = page_size
                        max_offset = max(0, total - view_page_size)
                        scroll_offset = min(max_offset, scroll_offset + 1)

                    # Escape or Backspace to return to dashboard
                    elif key == '\x1b' or key == '\x7f':  # Esc or Backspace
                        current_view = 'dashboard'
                        scroll_offset = 0  # Reset scroll when returning to dashboard

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
