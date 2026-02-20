# KernelEye Agent

The lightweight eBPF-based monitoring and remediation agent for KernelEye.

## What It Does

- **Real-time Traffic Monitoring** - eBPF-based TCP/UDP connection tracking
- **Bandwidth Tracking** - TC hooks for ingress/egress bytes per IP
- **Traffic Direction Detection** - Distinguishes inbound vs outbound connections
- **XDP Firewall** - Ultra-fast packet filtering before network stack
- **Intelligent Remediation** - Automatic threat blocking and rate limiting
- **Threat Analysis** - Configurable detection rules with scoring

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         KERNEL                              │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │ XDP Firewall │   │ Traffic Probe│   │    TC Hooks    │   │
│  │              │   │              │   │                │   │
│  │ • IP Blocking│   │ • kprobes    │   │ • Ingress BW   │   │
│  │ • Rate Limit │   │ • TCP state  │   │ • Egress BW    │   │
│  │ • CIDR Block │   │ • UDP events │   │ • Per-IP stats │   │
│  └──────┬───────┘   └──────┬───────┘   └───────┬────────┘   │
│         │                  │                   │            │
└─────────┼──────────────────┼───────────────────┼────────────┘
          │                  │                   │
          │    Ring Buffer   │   Ring Buffer     │  eBPF Maps
          ▼                  ▼                   ▼
┌─────────────────────────────────────────────────────────────┐
│                       USERSPACE                             │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐   │
│  │   Analyzer   │   │  Aggregator  │   │   gRPC Client  │   │
│  │              │   │              │   │                │   │
│  │ • Scoring    │   │ • Per-IP     │   │ • Batch send   │   │
│  │ • Detection  │──▶│  statistics  │──▶│ • TLS secured  │   │
│  │ • Decisions  │   │ • Windowing  │   │ • Heartbeat    │   │
│  └──────────────┘   └──────────────┘   └────────────────┘   │
│         │                                      │            │
│         ▼                                      ▼            │
│  ┌──────────────┐                    ┌────────────────┐     │
│  │ Remediator   │                    │  Backend API   │     │
│  │              │                    │  (SaaS)        │     │
│  │ • XDP block  │                    └────────────────┘     │
│  │ • IPSet block│                                           │
│  │ • Rate limit │                                           │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

## Components

### eBPF Programs

| File                   | Type                | Purpose                       |
| ---------------------- | ------------------- | ----------------------------- |
| `ebpf/traffic_probe.c` | kprobes/tracepoints | TCP/UDP connection monitoring |
| `ebpf/xdp_firewall.c`  | XDP                 | Ultra-fast packet filtering   |

### Remediation System

| Component                          | Description                                  |
| ---------------------------------- | -------------------------------------------- |
| `remediation/analyzer.go`          | Threat analysis with configurable thresholds |
| `remediation/xdp_remediator.go`    | XDP-based IP blocking (fastest)              |
| `remediation/remediator.go`        | IPSet/iptables-based blocking                |
| `remediation/hybrid_remediator.go` | Combines XDP + IPSet for defense in depth    |

### Detection Capabilities

| Threat              | Detection Method                | Action                |
| ------------------- | ------------------------------- | --------------------- |
| **Port Scanning**   | Unique ports per IP > threshold | Block                 |
| **SYN Flood**       | High SYN rate + low ACK         | XDP Drop + Rate Limit |
| **Brute Force**     | Failed connections > threshold  | Block                 |
| **Bandwidth Abuse** | Bytes in/out exceeds limit      | Rate Limit            |

## Prerequisites

### System Requirements

- **Linux Kernel**: 5.8+ (with BTF support)
- **Architecture**: x86_64, ARM64
- **Permissions**: root (for eBPF/XDP loading)

### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    bpftool

# Fedora/RHEL
sudo dnf install -y \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    bpftool

# Arch Linux
sudo pacman -S clang llvm libbpf linux-headers bpftool
```

## Building

### 1. Generate vmlinux.h

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
```

### 2. Generate eBPF Go Bindings

```bash
go mod download
go generate ./...
```

### 3. Build the Agent

```bash
go build -o kerneleye-agent .
```

## Running

### Development Mode

```bash
# Run with local logging
sudo ./kerneleye-agent
```

### Production Mode

```bash
export KERNELEYE_API_KEY="ke_your_api_key_here"
export KERNELEYE_SERVER="api.kerneleye.cloud:443"
sudo ./kerneleye-agent
```

### Systemd Service

```bash
# Copy binary
sudo cp kerneleye-agent /usr/local/bin/

# Create config
sudo mkdir -p /etc/kerneleye
echo "KERNELEYE_API_KEY=ke_your_api_key" | sudo tee /etc/kerneleye/config

# Install service
sudo cp systemd/kerneleye-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kerneleye-agent
```

## Configuration

### Environment Variables

| Variable                   | Default          | Description            |
| -------------------------- | ---------------- | ---------------------- |
| `KERNELEYE_API_KEY`        | `demo-key`       | API key from dashboard |
| `KERNELEYE_SERVER`         | `localhost:8080` | Backend server address |
| `KERNELEYE_FLUSH_INTERVAL` | `10s`            | Data send interval     |
| `KERNELEYE_LOG_LEVEL`      | `info`           | Log verbosity          |

### Analyzer Config

The threat analyzer can be tuned in code:

```go
config := remediation.AnalyzerConfig{
    SynFloodThreshold:       1000, // SYN/min for flood detection
    PortScanThreshold:       20,   // Unique ports for scan detection
    FailedConnThreshold:     50,   // Failed connections for brute force
    RateLimitWindowSeconds:  60,   // Analysis window
    BlockDurationMinutes:    30,   // How long to block threats
}
```

## Testing

### Generate Test Traffic

```bash
# Port scan (triggers alert)
nmap -p 1-100 localhost

# SYN flood simulation
hping3 -S -p 80 --flood localhost

# Normal traffic
curl http://localhost
```

### Verify XDP Firewall

```bash
# Check loaded XDP programs
ip link show

# View blocked IPs
sudo bpftool map dump name blocked_ips

# Check rate limits
sudo bpftool map dump name rate_limits
```

## Data Privacy

**Never Captured:**

- ❌ Packet payloads
- ❌ HTTP headers/body
- ❌ Credentials
- ❌ Application data

**Only Captured:**

- ✅ IP addresses (source/destination)
- ✅ Ports and protocols
- ✅ Connection flags (SYN/ACK)
- ✅ Packet counts & bytes
- ✅ Traffic direction

## Troubleshooting

### "Failed to load eBPF objects"

```bash
# Check kernel version (need 5.8+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Run as root
sudo ./kerneleye-agent
```

### "Failed to attach XDP"

```bash
# Check network interface
ip link show

# Remove existing XDP program
sudo ip link set dev eth0 xdp off

# Check for conflicts
sudo bpftool prog list
```

### "High CPU usage"

- Increase flush interval
- Check if XDP is properly offloaded
- Review analyzer thresholds

## License

Proprietary - All Rights Reserved
