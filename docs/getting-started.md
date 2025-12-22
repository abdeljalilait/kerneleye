# 🚀 Getting Started with KernelEye

Welcome! This guide will get you up and running with KernelEye in under 10 minutes.

## What You're Building

KernelEye is a **lightweight network threat detection platform** that:
- Monitors traffic at the kernel level using eBPF (no log parsing!)
- Scores IPs based on suspicious behavior (port scanning, SYN floods, etc.)
- Provides a beautiful dashboard to visualize threats
- Is **10x simpler** than CrowdSec

## 📋 Prerequisites

### Required
- **Docker & Docker Compose** - For running PostgreSQL
- **Linux** (for agent only) - Kernel 5.8+ with BTF support

### Optional (for development)
- **Go 1.21+** - To run backend/agent
- **Node.js 18+** - To run dashboard
- **bpftool, clang, llvm** - To build eBPF agent

## 🎬 Quickest Start (Docker)

```bash
# 1. Clone and setup
git clone <your-repo>
cd kerneleye
cp .env.example .env

# 2. Run the automated setup
chmod +x setup.sh
./setup.sh

# 3. Start all services
docker-compose up -d

# 4. Open the dashboard
open http://localhost:3000
```

**That's it!** You now have:
- ✅ PostgreSQL running
- ✅ Backend API on port 8080
- ✅ Dashboard on port 3000

## 🧪 Development Mode (Recommended)

For active development, run services separately:

### Terminal 1: Backend

```bash
cd backend
go mod download
go run cmd/api/main.go
```

Output:
```
✅ Database connected
🚀 KernelEye API listening on port 8080
```

### Terminal 2: Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Output:
```
VITE ready in 500 ms
➜  Local:   http://localhost:3000/
```

### Terminal 3: Agent (Linux only)

```bash
cd agent

# One-time setup
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
go generate

# Build and run
go build -o kerneleye-agent
sudo ./kerneleye-agent
```

Output:
```
╔════════════════════════════════════════╗
║   KernelEye Agent v0.1.0 (MVP)         ║
╚════════════════════════════════════════╝
Monitoring: TCP connections (IPv4)
```

## 🎯 Testing the System

### 1. Login to Dashboard

Open http://localhost:3000 and login with:
- **Email**: `demo@kerneleye.io`
- **Password**: `demo`

### 2. Generate Test Traffic

Simulate a port scan (this will trigger alerts!):

```bash
# Generate 50 connection attempts to different ports
for port in {1..50}; do
  nc -zv localhost $port 2>/dev/null &
done

# Or use nmap if installed
nmap -p 1-100 localhost
```

### 3. Watch the Magic ✨

- **Agent Terminal**: See connection events being captured
- **Dashboard**: Watch threat scores appear in real-time
- **Alerts**: IPs with score > 20 will generate alerts

Expected threat score for port scan: **~150** (Malicious 🚨)

## 📊 Understanding the Dashboard

### Overview Page
- **KPI Cards**: Server count, active threats, blocked requests, traffic rate
- **Traffic Chart**: Hourly connection volume
- **Server Status**: All monitored agents
- **Top Threats**: IPs with highest scores
- **Live Stream**: Real-time event feed

### Threat Scoring

```
Formula: (SYN × 2) + (Unique Ports × 3) + (Failed Handshakes × 5)

Example - Port Scan:
  - 50 SYN packets = 50 × 2 = 100
  - 50 unique ports = 50 × 3 = 150
  - Total Score = 250 (Malicious!)

Levels:
  < 20  → Normal ✅
  20-40 → Suspicious ⚠️
  > 40  → Malicious 🚨
```

## 🔧 Common Issues

### "Database connection failed"

```bash
# Check if PostgreSQL is running
docker-compose ps

# Restart if needed
docker-compose restart postgres

# Check logs
docker-compose logs postgres
```

### "Failed to load eBPF objects"

```bash
# Check kernel version (need 5.8+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Make sure you're root
sudo ./kerneleye-agent
```

### "Agent can't connect to API"

```bash
# Make sure backend is running
curl http://localhost:8080/health

# Check environment variables
cat .env | grep KERNELEYE_SERVER

# Should be: localhost:8080 for local dev
```

### Dashboard shows "No data"

```bash
# 1. Check backend is running
curl http://localhost:8080/api/v1/stats/overview

# 2. Check you're logged in
# Look for 'kerneleye_token' in browser localStorage

# 3. Check browser console for errors
# Press F12 → Console tab
```

## 📂 Project Structure

```
kerneleye/
├── agent/          # eBPF monitoring agent (Go)
├── backend/        # API server (Go/Fiber)
├── dashboard/      # Web UI (React/TypeScript)
├── proto/          # gRPC/Protobuf definitions
├── docs/           # Documentation
└── setup.sh        # Automated setup script
```

## 🎨 Customization

### Change Threat Score Weights

Edit [backend/internal/scoring/scorer.go](../backend/internal/scoring/scorer.go):

```go
func NewThreatScorer() *ThreatScorer {
	return &ThreatScorer{
		SYNWeight:             2,  // ← Change this
		UniquePortsWeight:     3,  // ← Change this
		FailedHandshakeWeight: 5,  // ← Change this
	}
}
```

### Change Flush Interval (Agent)

Edit [agent/main.go](../agent/main.go):

```go
aggregator.StartFlushTimer(10 * time.Second)  // ← Change interval
```

### Add More eBPF Hooks

Edit [agent/ebpf/traffic_probe.c](../agent/ebpf/traffic_probe.c) and add new `SEC()` functions.

## 🚀 Next Steps

### Phase 1 (MVP) - Complete! ✅
- [x] eBPF TCP monitoring
- [x] Threat scoring
- [x] Dashboard with visualizations
- [x] Alert generation

### Phase 2 - Your Next Tasks
- [ ] Enable UDP monitoring (code is there, just uncomment!)
- [ ] Add real-time WebSocket updates
- [ ] Implement auto-blocking (iptables integration)
- [ ] Add email/Slack notifications
- [ ] Deploy to production server

### Production Deployment

See [docs/deployment.md](deployment.md) for:
- AWS/DigitalOcean setup
- SSL certificate configuration
- Monitoring & logging
- Backup strategies

## 💡 Architecture Recap

```
┌─────────────────┐
│  Customer Host  │
│                 │
│  ┌───────────┐  │
│  │ eBPF Agent│  │  Captures TCP/UDP at kernel level
│  └─────┬─────┘  │  Aggregates per-IP statistics
│        │        │
└────────┼────────┘
         │ gRPC (every 10s)
         ▼
┌─────────────────────┐
│   Backend API       │  Scores threats
│   (Go/Fiber)        │  Stores events
└─────────┬───────────┘  Generates alerts
          │
          ▼
    ┌──────────┐
    │PostgreSQL│
    └──────────┘
          ▲
          │ REST API
          │
    ┌─────┴──────┐
    │ Dashboard  │  Visualizes threats
    │  (React)   │  Manages servers
    └────────────┘
```

## 📚 Additional Resources

- [Development Guide](development.md) - Full development setup
- [API Documentation](api.md) - Endpoint reference (TODO)
- [Agent Architecture](agent.md) - eBPF internals (TODO)
- [Database Schema](../backend/migrations/001_initial_schema.sql)

## 🤝 Getting Help

- **Documentation**: Check [docs/](.)
- **Issues**: GitHub Issues
- **Community**: Discord (coming soon)
- **Email**: support@kerneleye.io

## 🎉 Success Checklist

After setup, verify:

- [ ] Dashboard loads at http://localhost:3000
- [ ] Can login with demo@kerneleye.io
- [ ] Backend responds to http://localhost:8080/health
- [ ] PostgreSQL is running (`docker-compose ps`)
- [ ] Agent captures connections (if on Linux)
- [ ] Port scan generates alerts in dashboard

**All checked?** You're ready to rock! 🚀

---

**Built with ❤️ for indie hackers and small teams**

Made simple. Made secure. Made for you.
