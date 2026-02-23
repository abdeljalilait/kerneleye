<p align="center">
  <img src="dashboard/logo_with_text.png" alt="KernelEye Logo" width="400">
</p>

# KernelEye 👁️

> **Kernel-Level Traffic Intelligence & Threat Remediation for Linux Servers**

A CrowdSec-like security monitoring platform without the operational complexity. Built for DigitalOcean users, SaaS founders, indie hackers, and agencies managing 5-50 servers.

## 🎯 What is KernelEye?

KernelEye is a real-time Linux server security platform that uses **eBPF** and **XDP** to detect and mitigate threats at the kernel level—before they reach your application.

**Core Features:**

- ✅ **Real-time traffic monitoring** using eBPF (kernel-level, no log parsing)
- ✅ **XDP-based firewall** for ultra-fast packet filtering (before network stack)
- ✅ **Intelligent threat scoring** with configurable thresholds
- ✅ **Automatic remediation** (IP blocking, rate limiting)
- ✅ **Bandwidth tracking** via TC hooks (ingress/egress per IP)
- ✅ **Traffic direction tracking** (inbound/outbound detection)
- ✅ **Live stream dashboard** with real-time WebSocket updates
- ✅ **Privacy-first**: metadata only, no payload inspection

## 🏗️ Architecture

```
┌───────────────────────────────────────┐
│           Customer Host               │
│                                       │
│  ┌─────────────┐    ┌──────────────┐  │
│  │ XDP Firewall│◄───│   Analyzer   │  │  Ultra-fast blocking
│  │ (kernel)    │    │  (userspace) │  │  before network stack
│  └─────────────┘    └──────────────┘  │
│         ▲                  ▲          │
│         │                  │          │
│  ┌──────┴──────────────────┴───────┐  │
│  │        eBPF Agent (Go)          │  │  TCP/UDP monitoring
│  │   • Traffic Probe (kprobes)     │  │  Bandwidth tracking
│  │   • TC Hooks (ingress/egress)   │  │  Connection analysis
│  └───────────────┬─────────────────┘  │
│                  │ gRPC (TLS)         │
└──────────────────┼────────────────────┘
                   ▼
┌──────────────────────────────────────┐
│       Central SaaS (Go API)          │
│                                      │
│  Ingest → Score → Store → Alert      │
└──────┬───────────────┬───────────────┘
       │               │
       ▼               ▼
  PostgreSQL    Dashboard (React)
                + WebSocket Live Stream
```

### Key Components

1. **Agent (Go + eBPF)** - Kernel-level network monitoring
   - `traffic_probe.c` - TCP/UDP connection tracking via kprobes
   - `xdp_firewall.c` - XDP-based packet filtering
   - TC hooks for bandwidth measurement
   - Threat analyzer with configurable rules

2. **Remediation System** - Multi-layer protection
   - **XDP Remediator** - Kernel-level blocking (fastest)
   - **IPSet Remediator** - iptables/ipset-based blocking
   - **Hybrid Remediator** - Combines both for optimal protection

3. **API Backend (Go)** - Ingests, scores, and stores traffic data

4. **Dashboard (React)** - Real-time threat visualization
   - Live traffic stream via WebSocket
   - Server management
   - Threat scoring & alerts

5. **PostgreSQL** - Events, scores, and user data

## 🔒 Privacy & Security

We **NEVER** collect:

- ❌ Packet payloads
- ❌ User credentials
- ❌ Request content
- ❌ Application data

We **ONLY** collect metadata:

- ✅ Source/Destination IP addresses
- ✅ Ports and protocols (TCP/UDP)
- ✅ Connection flags (SYN/ACK)
- ✅ Packet counts & bytes in/out
- ✅ Traffic direction (inbound/outbound)
- ✅ Timestamps

## 📊 Threat Detection & Scoring

### Detection Signals (eBPF-based)

| Signal            | Description                        | Weight   |
| ----------------- | ---------------------------------- | -------- |
| SYN Rate          | High volume of connection attempts | ×2       |
| Port Scanning     | Many unique ports accessed         | ×3       |
| Failed Handshakes | Incomplete TCP connections         | ×5       |
| SYN Flood         | Rapid SYN without ACK completion   | Critical |

### Scoring Thresholds

```
Score = (syn_rate × 2) + (unique_ports × 3) + (failed_connections × 5)

< 20  → Normal ✅      (No action)
20-40 → Suspicious ⚠️  (Monitor closely)
> 40  → Malicious 🚨   (Auto-block if enabled)
```

### Remediation Actions

| Action             | Implementation            | Speed  |
| ------------------ | ------------------------- | ------ |
| **XDP Block**      | Drops at NIC driver level | ~50ns  |
| **XDP Rate Limit** | Token bucket in kernel    | ~100ns |
| **IPSet Block**    | iptables + ipset          | ~1µs   |
| **CIDR Block**     | Network range blocking    | ~100ns |

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/abdeljalilait/kerneleye.git
cd kerneleye
chmod +x setup.sh
./setup.sh
```

### 2. Start Services

```bash
# Terminal 1: Backend
cd backend && go run cmd/api/main.go

# Terminal 2: Dashboard
cd dashboard && npm install && npm run dev

# Terminal 3: Agent (Linux only, requires root)
cd agent
go generate ./...
go build -o kerneleye-agent
sudo ./kerneleye-agent
```

### 3. Access Dashboard

Open http://localhost:3000 and login with:

- **Email**: `demo@kerneleye.cloud`
- **Password**: `demo`

📖 **Full Guide**: See [docs/getting-started.md](docs/getting-started.md)

## 📁 Project Structure

```
kerneleye/
├── agent/                  # Go + eBPF monitoring agent
│   ├── ebpf/               # eBPF C programs
│   │   ├── traffic_probe.c # TCP/UDP connection tracking
│   │   └── xdp_firewall.c  # XDP packet filtering
│   ├── remediation/        # Threat mitigation
│   │   ├── analyzer.go     # Threat analysis engine
│   │   ├── xdp_remediator.go    # XDP-based blocking
│   │   ├── remediator.go        # IPSet-based blocking
│   │   └── hybrid_remediator.go # Combined approach
│   ├── main.go             # Agent entry point
│   ├── aggregator.go       # Event aggregation
│   ├── network.go          # Network utilities
│   └── tc.go               # TC hooks for bandwidth
├── backend/                # Go API server
│   ├── cmd/api/            # Entry point
│   ├── internal/api/       # HTTP/gRPC handlers
│   ├── internal/database/  # PostgreSQL queries (sqlc)
│   ├── internal/scoring/   # Threat detection logic
│   └── migrations/         # Database migrations
├── dashboard/              # React frontend
│   ├── src/components/     # UI components
│   ├── src/pages/          # Dashboard pages
│   └── src/context/        # WebSocket context
├── proto/                  # Protobuf definitions
│   └── kerneleye/v1/       # API v1 schema
└── docs/                   # Documentation
```

## 🛠️ Tech Stack

| Layer              | Technologies                                   |
| ------------------ | ---------------------------------------------- |
| **Agent**          | Go 1.21+, eBPF (cilium/ebpf), XDP, TC, gRPC    |
| **Backend**        | Go, Fiber, PostgreSQL, sqlc                    |
| **Dashboard**      | React, TypeScript, Vite, React Query, Recharts |
| **Infrastructure** | Docker, Docker Compose, Protobuf               |

## �️ Roadmap

### Phase 1 (MVP) ✅ Complete

- [x] eBPF TCP/UDP connection monitoring
- [x] Traffic direction tracking (inbound/outbound)
- [x] Bandwidth tracking (bytes in/out per IP)
- [x] gRPC ingestion API with TLS
- [x] Threat scoring engine
- [x] PostgreSQL schema with migrations
- [x] React dashboard with live stream
- [x] WebSocket real-time updates
- [x] XDP-based firewall
- [x] Hybrid remediation (XDP + iptables)
- [x] Threat analyzer with configurable thresholds

### Phase 2 (In Progress)

- [ ] Email/webhook alerting
- [ ] Slack/Discord integrations
- [ ] Multi-user support with RBAC
- [ ] Custom scoring rules UI
- [ ] Geographic IP visualization

### Phase 3 (Planned)

- [ ] Cloudflare integration
- [ ] Advanced analytics & ML
- [ ] Kubernetes support
- [ ] API rate limiting dashboard

## 📖 Documentation

- **[Getting Started](docs/getting-started.md)** - 10-minute setup guide
- **[Development Guide](docs/development.md)** - Full development workflow
- **[Agent Architecture](agent/README.md)** - eBPF & XDP implementation
- **[Database Schema](backend/migrations/)** - PostgreSQL structure

## 📧 Contact

- **Website**: https://kerneleye.cloud
- **Email**: hello@kerneleye.cloud
- **Support**: support@kerneleye.net

## 📄 License

Proprietary - All Rights Reserved

---

**Built with ❤️ for indie hackers and small teams**

_Made simple. Made secure. Made for you._
