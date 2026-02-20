# KernelEye Agent - Build & Installation Guide

This document describes the build system and installation process for the KernelEye Agent.

## Quick Start

### Option 1: One-Line Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/kerneleye/kerneleye/main/agent/install.sh | sudo bash
```

Or clone and install:

```bash
git clone https://github.com/kerneleye/kerneleye.git
cd kerneleye/agent
sudo ./install.sh
```

### Option 2: Build from Source

```bash
cd agent
make all          # Check deps, generate eBPF, and build
sudo make install # Install to /usr/local/bin
```

## Build System (Makefile)

The Makefile provides a comprehensive build system with semantic versioning support.

### Main Targets

| Target               | Description                                |
| -------------------- | ------------------------------------------ |
| `make all`           | Full build (check deps → gen eBPF → build) |
| `make build`         | Build debug binary                         |
| `make build-release` | Build optimized release binary             |
| `make clean`         | Remove build artifacts                     |
| `make install`       | Install binary and config to system        |
| `make uninstall`     | Remove binary from system                  |
| `make test`          | Run unit tests                             |
| `make lint`          | Run linter                                 |

### Version Management

The build system uses [Semantic Versioning](https://semver.org/) (SemVer):

```bash
# Show current version
make version

# Bump versions
make release-major   # 0.2.0 → 1.0.0
make release-minor   # 0.2.0 → 0.3.0
make release-patch   # 0.2.0 → 0.2.1

# Set specific version
make set-version VERSION=1.0.0-beta.1
```

### Build Information

Version information is injected at build time:

```bash
# After building, check version
./kerneleye-agent -version

# Output:
# ╔══════════════════════════════════════════════════════════╗
# ║          KernelEye Agent - Version Information           ║
# ╚══════════════════════════════════════════════════════════╝
#   Version:    0.2.0+abc1234
#   Git Commit: abc1234
#   Git Branch: main
#   Build Date: 2026-02-18T14:24:59Z
#   Built By:   user@hostname
#   Go Version: go1.25.5
```

### Build Variables

| Variable  | Default             | Description                |
| --------- | ------------------- | -------------------------- |
| `VERSION` | From `VERSION` file | Override version string    |
| `PREFIX`  | `/usr/local`        | Installation prefix        |
| `DEBUG`   | (unset)             | Set to `1` for debug build |

Example:

```bash
# Debug build
make build DEBUG=1

# Install to custom location
sudo make install PREFIX=/opt/kerneleye

# Custom version
make build-release VERSION=1.0.0-custom
```

## Installation Script

The `install.sh` script handles the complete installation with logging.

### Features

- ✅ Automatic dependency checking
- ✅ OS compatibility verification
- ✅ Build from source or use pre-built binary
- ✅ systemd service creation
- ✅ Wrapper script for easy execution
- ✅ Comprehensive logging

### Usage

```bash
# Basic install
sudo ./install.sh

# With options
sudo ./install.sh --prefix /opt/kerneleye

# Install dependencies only
./install.sh --install-deps

# Uninstall
sudo ./install.sh --uninstall

# Show help
./install.sh --help
```

### Wrapper Commands

After installation, use the `kerneleye` wrapper:

```bash
# Start in foreground
sudo kerneleye start

# Start with XDP
sudo kerneleye start -xdp -interface eth0

# Start in background
kerneleye start-bg

# Check status
kerneleye status

# View logs
kerneleye logs

# Edit config
kerneleye config

# Stop background agent
kerneleye stop

# Show version
kerneleye version
```

### Logging

Installation logs are saved to `/var/log/kerneleye/install.log`.

Agent logs (when running via wrapper or systemd):

- File: `/var/log/kerneleye/agent.log`
- View: `kerneleye logs` or `sudo tail -f /var/log/kerneleye/agent.log`

## Systemd Service

If systemd is available, the installer creates a service:

```bash
# Enable auto-start on boot
sudo systemctl enable kerneleye-agent

# Start the service
sudo systemctl start kerneleye-agent

# Check status
sudo systemctl status kerneleye-agent

# View logs
sudo journalctl -u kerneleye-agent -f
```

## Configuration

Configuration file: `/etc/kerneleye/agent.env`

```bash
# Required
KERNELEYE_API_KEY=your-api-key-here

# Optional
KERNELEYE_SERVER=api.kerneleye.cloud:443
ENABLE_REMEDIATION=true
ENABLE_XDP=true
INTERFACE=eth0
```

Edit with: `sudo kerneleye config`

## Directory Structure

After installation:

```
/usr/local/bin/
├── kerneleye-agent    # Main binary
└── kerneleye          # Wrapper script

/etc/kerneleye/
└── agent.env          # Configuration file

/var/log/kerneleye/
├── install.log        # Installation log
└── agent.log          # Runtime logs

/etc/systemd/system/
└── kerneleye-agent.service  # systemd service (if applicable)
```

## Prerequisites

### Build Requirements

- Go 1.25+
- clang/llvm 14+
- Linux kernel 5.8+ (with BTF support)
- Linux headers for your kernel

### Install Dependencies

**Ubuntu/Debian:**

```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

**Fedora/RHEL/CentOS:**

```bash
sudo dnf install clang llvm libbpf-devel kernel-headers
```

**Arch:**

```bash
sudo pacman -S clang llvm libbpf linux-headers
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build Agent

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install dependencies
        run: sudo apt-get install -y clang llvm libbpf-dev

      - name: Build
        run: |
          cd agent
          make build-release

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: kerneleye-agent
          path: agent/kerneleye-agent
```

## Troubleshooting

### Build Issues

**"bpf_bpfel_x86.go: no such file"**

```bash
make gen-ebpf  # Regenerate eBPF bindings
```

**"failed to load eBPF"**

- Check kernel version: `uname -r` (need 5.8+)
- Verify BTF: `ls /sys/kernel/btf/vmlinux`
- Run as root: `sudo ./kerneleye-agent`

### Installation Issues

**"Permission denied"**

```bash
sudo ./install.sh
```

**"Log file not writable"**

```bash
sudo mkdir -p /var/log/kerneleye
sudo chown $USER:$USER /var/log/kerneleye
```

## Development

### Quick Dev Cycle

```bash
# 1. Make changes to code
# 2. Build and run
make build && sudo ./kerneleye-agent

# Or with live rebuild
make run  # Builds and runs with sudo
```

### eBPF Development

```bash
# After modifying ebpf/*.c files
cd agent
make gen-ebpf  # Regenerate Go bindings
make build
```

## License

See [LICENSE](../LICENSE) for details.
