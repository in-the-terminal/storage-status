# storage-status

Terminal dashboard for monitoring Ubuntu/ZFS storage servers. Displays real-time ZFS pool health, dataset usage, system resources, services, and network information.

Last Updated On: 2025-12-09

## Features

- **ZFS Pool Status** - Health, capacity, deduplication ratios
- **ZFS Dataset Usage** - Hierarchical view with compression ratios
- **System Resources** - Load average, memory usage, uptime
- **Service Status** - SMB, NFS, SSH, ZFS services
- **Network Interfaces** - Interface status and IP addresses
- **SMB/NFS Connections** - Active Samba and NFS client connections (toggleable)

## Installation

```bash
# Clone the repository
git clone https://github.com/in-the-terminal/storage-status.git
cd storage-status

# Install dependencies
pip3 install -r requirements.txt

# Create symlink (optional)
ln -sf "$(pwd)/storage-status.py" ~/bin/storage-status

# Install man page (optional, choose one):
# System-wide:
sudo cp storage-status.1 /usr/local/share/man/man1/
# Or user-local (add MANPATH to shell config):
mkdir -p ~/share/man/man1
cp storage-status.1 ~/share/man/man1/
echo 'export MANPATH="$HOME/share/man:$MANPATH"' >> ~/.zshrc
```

## Usage

```bash
# Full dashboard with auto-refresh
storage-status

# Run once without live refresh
storage-status --once

# Force remote mode (SSH)
storage-status --remote

# Force local mode
storage-status --local

# View specific sections
storage-status pools      # ZFS pools only
storage-status datasets   # ZFS datasets only
storage-status services   # Service status only
storage-status network    # Network interfaces only
storage-status smb        # SMB connections only
```

## Keyboard Controls

In live mode (without `--once`):

| Key | Action |
|-----|--------|
| `1` | Expand ZFS Pools (topology, fragmentation, errors) |
| `2` | Expand ZFS Datasets (quota, reservation, snapshots) |
| `3` | Expand Services (running/stopped, memory, restarts) |
| `4` | Expand Network Interfaces (details + traffic stats) |
| `5` | Expand SMB Details (connections + shares) |
| `6` | Expand NFS Details (connections + exports) |
| `↑` / `k` | Scroll up in expanded views |
| `↓` / `j` | Scroll down in expanded views |
| `Esc` / `Backspace` | Return to main dashboard |
| `t` / `Tab` | Toggle between SMB and NFS connections |
| `q` / `Ctrl+C` | Quit |

## Auto-Detection

The tool automatically detects whether it's running locally on the storage server or remotely:

- **Local mode**: Commands run directly on the system
- **Remote mode**: Commands run via SSH to the configured storage server

### How Detection Works

1. Compares current hostname to `STORAGE_HOSTNAME`
2. If no match, compares local IPs (from `hostname -I`) against `STORAGE_IPS`
3. If either matches → local mode; otherwise → remote mode (requires SSH)

### Example Output

```
$ storage-status --once
Storage Status - Mode: remote

$ ssh ubuntu-storage storage-status --once
Storage Status - Mode: local
```

Use `--local` or `--remote` to override detection.

## SSH Setup (Remote Mode)

For non-interactive operation, configure SSH key authentication. Choose based on your security requirements:

**Standard key with passphrase (recommended):**

```bash
ssh-keygen -t ed25519                    # Enter a passphrase when prompted
eval "$(ssh-agent -s)" && ssh-add        # Cache key for session
ssh-copy-id user@storage-server
```

**Hardware security key (FIDO2/YubiKey):**

```bash
ssh-keygen -t ed25519-sk                 # Requires physical touch per connection
ssh-copy-id user@storage-server
```

**SSH config for convenience:**

```
# ~/.ssh/config
Host storage-server
    HostName 10.0.0.10
    User admin
```

Test: `ssh storage-server hostname`

**Note:** The tool automatically uses SSH connection multiplexing (ControlMaster) to reuse a single TCP connection for all commands, significantly improving performance in remote mode.

## Required Permissions

The SSH user on the storage server needs access to:

- `zpool`, `zfs` - ZFS status commands
- `systemctl` - Service status (read-only)
- `smbstatus` - SMB connection details (may require `sambashare` group)
- `testparm` - SMB share configuration
- `/proc/loadavg`, `/proc/meminfo` - System stats (world-readable)
- `ss` - Socket statistics for NFS connections (with `-i` for extended metrics)
- `/etc/exports` - NFS export configuration (world-readable)

## Configuration

Set the following environment variables:

```bash
# Required for remote mode
export STORAGE_SSH_HOST=my-storage-server    # SSH host/alias

# Optional - for local detection
export STORAGE_HOSTNAME=ubuntu-storage       # Hostname of storage server
export STORAGE_IPS=10.0.0.10,10.0.0.11       # Comma-separated IPs
```

Add these to your `~/.bashrc`, `~/.zshrc`, or shell profile for persistence.

## Requirements

- Python 3.8+
- SSH access to storage server (for remote mode)
- ZFS utilities installed on the storage server

## Troubleshooting

**Detection not working as expected:**

```bash
# Check what the tool sees
hostname                    # Compare to STORAGE_HOSTNAME
hostname -I                 # Compare to STORAGE_IPS
echo $STORAGE_HOSTNAME $STORAGE_IPS
```

**SSH connection issues:**

```bash
ssh -v $STORAGE_SSH_HOST    # Verbose output for debugging
```

**Permission denied on commands:**

```bash
# Add user to required groups on storage server
sudo usermod -aG sambashare $USER
```

## License

MIT
