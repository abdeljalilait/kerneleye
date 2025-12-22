# KernelEye 👁️

> **Traffic Intelligence & Lightweight Protection for Small Fleets**

A CrowdSec-like security monitoring platform without the operational complexity. Built for DigitalOcean users, SaaS founders, indie hackers, and agencies managing 5-50 servers.

## 🎯 What is KernelEye?

**What we ARE:**

- ✅ Real-time traffic intelligence using eBPF
- ✅ Lightweight threat detection for small teams
- ✅ Simple, transparent pricing ($5-29/month)
- ✅ Privacy-first: metadata only, no payload inspection

**What we are NOT (in MVP):**

- ❌ Global threat intelligence network
- ❌ Community voting system
- ❌ Firewall replacement

## 🏗️ Architecture

```
┌───────────────┐
│ Customer Host │
│               │
│  Go Agent     │──┐ Secure stream
│  (eBPF)       │  │ (gRPC/HTTPS)
└───────────────┘  │
                   ▼
┌──────────────────────────────┐
│ Central SaaS (Go API)        │
│                              │
│ Ingest → Score → Store       │
└──────┬─────────┬─────────────┘
       │         │
       ▼         ▼
  PostgreSQL  Dashboard (React)
```

### Key Components

1. **Agent (Go + eBPF)** - Collects network metadata from kernel
2. **API Backend (Go)** - Ingests, scores, and stores traffic data
3. **Dashboard (React)** - Visualizes threats and provides alerts
4. **PostgreSQL** - Stores events, scores, and user data

## 🔒 Privacy & Security

We **NEVER** collect:

- ❌ Packet payloads
- ❌ User credentials
- ❌ Request content
- ❌ Application data

We **ONLY** collect metadata:

- ✅ Source IP address
- ✅ Destination port
- ✅ Protocol (TCP/UDP)
- ✅ Connection flags (SYN/ACK)
- ✅ Packet counts & bytes
- ✅ Timestamps

## 📊 Threat Scoring (Simple & Transparent)

Unlike CrowdSec's complex trust/consensus model, we use a **deterministic sliding window approach**:

```
Per-IP metrics (60-second window):
- syn_rate: Number of SYN packets
- unique_ports: Ports scanned
- failed_connections: Incomplete handshakes

Score = (syn_rate × 2) + (unique_ports × 3) + (failed_connections × 5)

Thresholds:
< 20  → Normal ✅
20-40 → Suspicious ⚠️
> 40  → Malicious 🚨
```

No machine learning. No community consensus. Just clear, explainable rules.

## 💰 Pricing

| Plan           | Price  | Servers    | Features                          |
| -------------- | ------ | ---------- | --------------------------------- |
| **Free Trial** | $0     | 1 server   | 7 days, alerts only               |
| **Starter**    | $5/mo  | 3 servers  | Traffic insights, CSV export      |
| **Pro**        | $15/mo | 10 servers | Advanced detection, blocking, API |
| **Team**       | $29/mo | 50 servers | Auto-blocking, webhooks, Slack    |

## 🚀 Quick Start

### 1. One-Command Setup

```bash
# Clone repository
git clone <your-repo>
cd kerneleye

# Run automated setup
chmod +x setup.sh
./setup.sh
```

### 2. Start Development

```bash
# Terminal 1: Backend
cd backend && go run cmd/api/main.go

# Terminal 2: Dashboard
cd dashboard && npm run dev

# Terminal 3: Agent (Linux only)
cd agent && sudo ./kerneleye-agent
```

### 3. Open Dashboard

Visit http://localhost:3000 and login with:

- Email: `demo@kerneleye.io`
- Password: `demo`

**📖 Full Guide**: See [docs/getting-started.md](docs/getting-started.md)

## 📁 Project Structure

```
kerneleye/
├── agent/              # Go + eBPF monitoring agent
│   ├── ebpf/           # eBPF C programs
│   ├── collector/      # Event aggregation
│   └── sender/         # gRPC client
├── backend/            # Go API server
│   ├── api/            # HTTP/gRPC handlers
│   ├── scoring/        # Threat detection logic
│   ├── models/         # Database models
│   └── migrations/     # PostgreSQL migrations
├── dashboard/          # React frontend
│   ├── src/
│   │   ├── components/ # UI components
│   │   ├── pages/      # Dashboard pages
│   │   └── api/        # API client
├── proto/              # Protobuf definitions
└── docs/               # Documentation
```

## 🛠️ Tech Stack

- **Agent**: Go 1.21+, eBPF (libbpf, cilium/ebpf), gRPC
- **Backend**: Go (Fiber/Gin), PostgreSQL, Redis (optional)
- **Dashboard**: React, Tailwind CSS, Recharts, **React Query (@tanstack/react-query)**
- **Infrastructure**: Docker, Docker Compose

> **Note:** The dashboard uses **React Query** for ALL API requests and data mutations. This provides automatic caching, background refetching, and consistent state updates across the application. See `src/hooks/useQueries.ts` for the query and mutation definitions.

## 📖 Documentation

- **[Getting Started](docs/getting-started.md)** - 10-minute setup guide
- **[Development Guide](docs/development.md)** - Full development workflow
- **[Agent Architecture](agent/README.md)** - eBPF implementation details
- **[Database Schema](backend/migrations/001_initial_schema.sql)** - PostgreSQL structure
- **[Threat Scoring](docs/scoring.md)** - How detection works (TODO)
- **[API Reference](docs/api.md)** - Endpoint documentation (TODO)
- **[Deployment Guide](docs/deployment.md)** - Production setup (TODO)

## 🗺️ Roadmap

### MVP (Phase 1) - Current Focus

- [x] eBPF TCP connection monitoring
- [ ] gRPC ingestion API
- [ ] Basic threat scoring
- [ ] PostgreSQL schema
- [ ] React dashboard (read-only)
- [ ] Alert system (email/webhook)

### Phase 2

- [ ] UDP monitoring
- [ ] Manual blocking via API
- [ ] CSV/JSON export
- [ ] Slack/Discord integrations
- [ ] Multi-user support

### Phase 3

- [ ] Auto-blocking (iptables/nftables)
- [ ] Cloudflare integration
- [ ] Advanced analytics
- [ ] Custom scoring rules

## 🤝 Contributing

This is currently a private MVP. Contributions will be welcome after public launch.

## 📄 License

Proprietary - All Rights Reserved

## 📧 Contact

- Website: https://kerneleye.io
- Email: hello@kerneleye.io
- Support: support@kerneleye.io

Below is a clear, end-to-end vision for KernelEye — product, market, pricing, architecture, and roadmap — written as if it were the internal north-star document for the company.

You can literally build from this.

🧠 KernelEye — Full Vision
1️⃣ What KernelEye is (one sentence)

KernelEye is an affordable, kernel-level security and attack-response SaaS for Linux servers that detects and blocks threats in real time—before they impact your system.

Not a firewall.
Not “eBPF tooling”.
Not “anti-DDoS”.

👉 Outcome-driven security, powered by the kernel.

2️⃣ The problem KernelEye solves (real pain)
Today’s reality for most Linux servers

Constant SSH brute-force

Internet scans (22, 80, 443, random ports)

Low-grade DDoS & SYN floods

Zero visibility at kernel level

iptables/nftables are:

Hard to manage

Reactive

Blind to behavior

Existing solutions fail because:

iptables/nftables → static, manual

Fail2Ban → slow, log-based

CrowdSec → great concept, but:

Heavy on log parsing

Limited kernel insight

Cloudflare → only protects HTTP

Enterprise EDR/SIEM → expensive & overkill

👉 There is a massive gap between “DIY firewall” and “enterprise security”.

3️⃣ KernelEye’s unique positioning (this is critical)
KernelEye sits here:
NIC
↓
XDP / eBPF ← KernelEye (earliest possible signal)
↓
nftables
↓
Application

Positioning statement

“KernelEye sees and stops attacks where everything else is blind: inside the Linux kernel.”

What makes KernelEye different
Aspect KernelEye
Detection Kernel-level (eBPF)
Blocking XDP + nftables (hybrid)
Speed Before conntrack
UX SaaS dashboard
Price SMB-friendly
Scope Bare metal + VM (not only K8s)

This is not Cilium (Kubernetes networking).
This is not CrowdSec (log-centric IDS).

4️⃣ Target customers (laser-focused)
🎯 Primary (Phase 1)

Indie hackers

SaaS founders

Small platforms

DevOps managing 1–20 servers

VPS users (OVH, Hetzner, DO, AWS EC2)

They:

Care about uptime

Hate security complexity

Will pay $5–$40/month

🎯 Secondary (Phase 2)

MSPs

Hosting providers

Agencies managing client servers

❌ Not your audience (for now)

Home users

Large enterprises

Kubernetes-only shops

5️⃣ Product pillars (non-negotiable)
🧱 Pillar 1 — Kernel Visibility

Network events (SYN, ACK, scans)

Process attribution (who opened the socket)

Connection lifecycle

Zero log dependency

🧱 Pillar 2 — Safe Enforcement

XDP for:

Floods

Known-bad IPs

nftables/ipset for:

Longer bans

Policy

Human safety

🧱 Pillar 3 — Clarity

“What happened?”

“Who attacked me?”

“What was blocked and why?”

If a user can’t answer these in 30 seconds → you failed.

6️⃣ Architecture (high-level)
Agent (on server)

eBPF probes (tracepoints, kprobes)

XDP program

Minimal state (LRU maps)

Ring buffer → userspace daemon

Userspace daemon

Event aggregation

Rate & behavior analysis

Decides:

XDP block

nftables block

Secure channel → SaaS

SaaS backend

Ingestion API

Time-series + relational DB

Correlation engine

Multi-tenant isolation

Dashboard

Server list

Attack timeline

Live events

Blocked IPs

Health indicators

7️⃣ Features by maturity
✅ MVP (what you launch with)

Must be boring, stable, safe

Server enrollment (agent token)

SSH brute-force detection

Scan detection

SYN flood detection (basic)

Safe auto-blocking (conservative)

Web dashboard

Email alerts

24h–7d retention

This already beats 80% of DIY setups.

🔥 V1 (product-market fit)

Attack timeline per server

Manual ban/unban

Slack / Webhook alerts

Per-server policy toggles

Multi-server view

Block reason transparency
