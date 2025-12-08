# storage-status

Terminal dashboard for monitoring Ubuntu/ZFS storage servers. Displays real-time ZFS pool health, dataset usage, system resources, services, and network information.

Last Updated On: 2025-12-06

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
| `t` / `Tab` | Toggle between SMB and NFS connections |
| `q` / `Ctrl+C` | Quit |

## Auto-Detection

The tool automatically detects whether it's running locally on the storage server or remotely:

- **Local mode**: Commands run directly on the system
- **Remote mode**: Commands run via SSH to the configured storage server

Detection is based on hostname and IP address matching. Use `--local` or `--remote` to override.

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

## License

MIT
