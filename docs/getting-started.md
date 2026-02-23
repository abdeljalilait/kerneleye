# 🚀 Getting Started with KernelEye

Welcome! This guide will get you up and running with KernelEye in under 10 minutes.

## What You're Building

KernelEye is a **kernel-level network security platform** that:

- Monitors traffic using eBPF (no log parsing!)
- Detects threats with XDP firewall (fastest possible filtering)
- Scores IPs based on suspicious behavior (port scanning, SYN floods, etc.)
- Provides real-time remediation (blocking, rate limiting)
- Shows live traffic in a beautiful dashboard

## 📋 Prerequisites

### Required

- **Docker & Docker Compose** - For running PostgreSQL
- **Go 1.21+** - For backend and agent
- **Node.js 18+** - For dashboard

### For Agent (Linux Only)

- **Linux Kernel 5.8+** with BTF support
- **clang, llvm, bpftool** - For eBPF compilation
- **Root privileges** - For loading eBPF/XDP programs

## 🎬 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/abdeljalilait/kerneleye.git
cd kerneleye
cp .env.example .env
chmod +x setup.sh
./setup.sh
```

### 2. Start Infrastructure

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Wait for database
sleep 5

# Run migrations
for f in backend/migrations/*.sql; do
  docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < "$f"
done
```

### 3. Start Backend

```bash
cd backend
go mod download
go run cmd/api/main.go
```

Output:

```
✅ Database connected
🚀 KernelEye API listening on port 8080
📡 gRPC server listening on port 50051
```

### 4. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Output:

```
VITE ready in 500ms
➜  Local: http://localhost:3000/
```

### 5. Start Agent (Linux Only)

```bash
cd agent

# One-time: Generate kernel headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# Generate eBPF bindings
go generate ./...

# Build and run
go build -o kerneleye-agent
sudo ./kerneleye-agent
```

Output:

```
╔════════════════════════════════════════╗
║   KernelEye Agent v1.0                 ║
╚════════════════════════════════════════╝
✅ eBPF probes attached
✅ XDP firewall loaded
✅ TC hooks attached
📊 Monitoring: TCP, UDP, Bandwidth
```

## 🎯 Testing the System

### Login to Dashboard

Open http://localhost:3000 and login:

- **Email**: `demo@kerneleye.net`
- **Password**: `demo`

### Generate Test Traffic

```bash
# Port scan (will trigger alerts)
nmap -p 1-50 localhost

# Or manual scan
for port in {1..50}; do
  nc -zv localhost $port 2>/dev/null &
done
```

### Watch the Results

- **Agent Terminal**: Connection events captured
- **Dashboard Live Stream**: Real-time traffic feed
- **Threats Page**: IPs with high threat scores
- **Server Detail**: Per-IP statistics with bandwidth

Expected threat score for port scan: **~150** (Malicious 🚨)

## 📊 Understanding the Dashboard

### Overview Page

- **KPI Cards**: Server count, active threats, blocked IPs, traffic rate
- **Traffic Chart**: Hourly connection volume
- **Live Stream**: Real-time WebSocket event feed

### Server Detail

- **Expandable IP rows**: Click to see per-port breakdown
- **Traffic direction**: Inbound ⬇️ vs Outbound ⬆️
- **Bandwidth tracking**: Bytes in/out per IP
- **Threat indicators**: Score-based coloring

### Threat Scoring

```
Formula: (SYN × 2) + (Unique Ports × 3) + (Failed Handshakes × 5)

Example - Port Scan:
  - 50 SYN packets = 100
  - 50 unique ports = 150
  - Total Score = 250 (Malicious!)

Levels:
  < 20  → Normal ✅
  20-40 → Suspicious ⚠️
  > 40  → Malicious 🚨
```

## 🛡️ Remediation System

KernelEye can automatically block threats:

| Layer      | Speed | Method                      |
| ---------- | ----- | --------------------------- |
| **XDP**    | ~50ns | Drops packets at NIC driver |
| **IPSet**  | ~1µs  | iptables + ipset rules      |
| **Hybrid** | Both  | Defense in depth            |

### Blocking Modes

- **Manual**: Block IPs via dashboard
- **Automatic**: Analyzer blocks threats above threshold
- **Rate Limit**: Slow down suspicious IPs without blocking

## 🔧 Troubleshooting

### "Database connection failed"

```bash
docker-compose ps          # Check PostgreSQL
docker-compose logs postgres # View logs
docker-compose restart postgres
```

### "Failed to load eBPF objects"

```bash
uname -r                    # Need 5.8+
ls /sys/kernel/btf/vmlinux  # Need BTF
sudo ./kerneleye-agent      # Need root
```

### "XDP attach failed"

```bash
ip link show                # Check interfaces
sudo ip link set eth0 xdp off  # Remove existing XDP
```

### Dashboard shows "No data"

```bash
curl http://localhost:8080/health  # Check backend
# Verify agent is running and sending data
```

## 📂 Project Structure

```
kerneleye/
├── agent/              # eBPF monitoring agent
│   ├── ebpf/           # eBPF C programs
│   └── remediation/    # Threat mitigation
├── backend/            # Go API server
│   ├── internal/api/   # HTTP/gRPC handlers
│   └── migrations/     # Database schema
├── dashboard/          # React frontend
│   └── src/            # Components & pages
└── proto/              # Protobuf definitions
```

## 🚀 Next Steps

1. **Deploy to production** - See [docs/deployment.md](deployment.md)
2. **Configure alerts** - Set up email/Slack notifications
3. **Tune thresholds** - Adjust analyzer settings
4. **Enable auto-blocking** - Configure remediation policies

## 📚 Additional Resources

- [Development Guide](development.md) - Full dev workflow
- [Agent Architecture](../agent/README.md) - eBPF internals
- [Database Schema](../backend/migrations/) - PostgreSQL structure

---

**Built with ❤️ for indie hackers and small teams**
