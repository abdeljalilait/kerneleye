# KernelEye Agent

The lightweight eBPF-based monitoring agent for KernelEye.

## What It Does

- Monitors TCP connections at the kernel level using eBPF
- Aggregates network metadata (no payload inspection)
- Sends batched statistics to KernelEye API every 10 seconds
- Detects port scanning, SYN floods, and failed handshakes

## Prerequisites

### System Requirements
- **Linux Kernel**: 5.8+ (with BTF support)
- **Architecture**: x86_64, ARM64
- **Permissions**: root (for eBPF loading)

### Build Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r)

# Fedora/RHEL
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers
```

## Building

### 1. Generate vmlinux.h (Kernel Type Definitions)

```bash
# This extracts kernel type definitions for CO-RE
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
```

### 2. Generate eBPF Go Bindings

```bash
go mod download
go generate ./...
```

This creates `bpf_bpfel.go` and `bpf_bpfel.o` from the C code.

### 3. Build the Agent

```bash
go build -o kerneleye-agent .
```

## Running

### Local Development (Demo Mode)

```bash
# Run without API key (local logging only)
sudo ./kerneleye-agent
```

### Production Mode

```bash
# Set API key from KernelEye dashboard
export KERNELEYE_API_KEY="ke_your_api_key_here"
export KERNELEYE_SERVER="api.kerneleye.io:443"

sudo ./kerneleye-agent
```

### As a Systemd Service

```bash
# Copy binary
sudo cp kerneleye-agent /usr/local/bin/

# Create config
sudo mkdir -p /etc/kerneleye
echo "KERNELEYE_API_KEY=ke_your_api_key" | sudo tee /etc/kerneleye/config

# Install service
sudo cp systemd/kerneleye-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kerneleye-agent
sudo systemctl start kerneleye-agent

# Check status
sudo systemctl status kerneleye-agent
sudo journalctl -u kerneleye-agent -f
```

## Testing

Generate some traffic to test detection:

```bash
# In terminal 1: Run the agent
sudo ./kerneleye-agent

# In terminal 2: Generate connections
# Normal connection
curl http://localhost

# Port scan simulation (will trigger alerts)
for port in {1..100}; do nc -zv localhost $port 2>&1 | grep -q "succeeded" && echo "Port $port open"; done
```

You should see suspicious activity logged with threat scores > 20.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KERNELEYE_API_KEY` | `demo-key` | Your API key from dashboard |
| `KERNELEYE_SERVER` | `api.kerneleye.io:443` | Backend server address |
| `KERNELEYE_FLUSH_INTERVAL` | `10s` | How often to send data |
| `KERNELEYE_LOG_LEVEL` | `info` | Logging level |

## Troubleshooting

### "Failed to load eBPF objects"

- **Check kernel version**: `uname -r` (need 5.8+)
- **Check BTF support**: `ls /sys/kernel/btf/vmlinux`
- **Check permissions**: Must run as root

### "Failed to attach kretprobe"

- Kernel might not export the symbol. Try:
  ```bash
  sudo cat /proc/kallsyms | grep inet_csk_accept
  ```

### High CPU Usage

- Check flush interval - very short intervals cause overhead
- Ensure you're batching events properly

## Data Privacy

The agent **NEVER** captures:
- Packet payloads
- HTTP headers
- Credentials
- Application data

It **ONLY** captures:
- IP addresses
- Port numbers
- Protocol types
- Connection flags
- Packet counts

## Architecture

```
┌─────────────────┐
│   eBPF Hooks    │
│  (Kernel Space) │
└────────┬────────┘
         │ Ring Buffer
         ▼
┌─────────────────┐
│   Go Agent      │
│  (User Space)   │
│                 │
│  - Aggregator   │──┐
│  - Scorer       │  │ Every 10s
│  - gRPC Client  │  │
└─────────────────┘  │
                     ▼
              ┌──────────────┐
              │  API Server  │
              └──────────────┘
```

## License

Proprietary - All Rights Reserved
