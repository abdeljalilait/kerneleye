# Getting Started with KernelEye

KernelEye is a self-hosted, open-source eBPF/XDP security and observability tool
for Linux servers. It monitors network traffic at the kernel level, scores threats,
and blocks attacks via XDP or iptables.

## Prerequisites

### Backend & Dashboard

- Docker & Docker Compose
- Go 1.22+
- Node.js 18+

### Agent (Linux only)

- Linux kernel 5.8+ with BTF (`ls /sys/kernel/btf/vmlinux`)
- clang, llvm, bpftool
- Root privileges (or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`)
- Optional for XDP: NIC driver with native XDP support

## Quick Start (Docker)

### 1. Clone and configure

```bash
git clone https://github.com/abdeljalilait/kerneleye.git
cd kerneleye
cp .env.example .env
```

Edit `.env` and set at minimum:

```bash
DATABASE_URL=postgres://kerneleye:kerneleye@localhost:5432/kerneleye
JWT_SECRET=$(openssl rand -base64 32)
API_KEY_SECRET=$(openssl rand -base64 32)
CMD_SIGNING_KEY=$(openssl rand -base64 32)  # Mandatory for remediation
AUTH_OWNER_EMAIL=your-email@gmail.com       # Your GitHub/Google email
GITHUB_CLIENT_ID=...                        # GitHub OAuth app
GITHUB_CLIENT_SECRET=...
```

### 2. Start the stack

```bash
docker-compose up -d
```

### 3. Generate an API key for your agent

Open `http://localhost:3000` in a browser, sign in via GitHub or Google OAuth,
then navigate to **Servers → Add Server**. Copy the generated API key.

### 4. Run the agent

```bash
cd agent

# Generate kernel headers (one-time)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
go generate ./...

# Build
go build -o kerneleye-agent

# Run (local dev — plaintext gRPC)
sudo KERNELEYE_API_KEY=ke_... \
     KERNELEYE_SERVER=localhost \
     CMD_SIGNING_KEY=<same as backend> \
     ./kerneleye-agent --insecure --enable-remediation
```

For production with TLS, omit `--insecure` and provide TLS flags:

```bash
sudo ./kerneleye-agent \
  --server grpcs://backend.example.com \
  --tls-ca-file /etc/kerneleye/ca.crt \
  --tls-cert-file /etc/kerneleye/agent.crt \
  --tls-key-file /etc/kerneleye/agent.key \
  --enable-remediation
```

### 5. Verify

```bash
# Agent should show:
# ✅ Agent approved! Starting monitoring...
# 🔐 TLS enabled (or ⚠️ TLS DISABLED if --insecure)

# Dashboard: Servers page shows your host as "active"
# Dashboard: Live Stream shows traffic events
```

## Manual Setup (without Docker)

### Backend

```bash
cp .env.example .env
# Edit .env with DATABASE_URL, secrets, OAuth credentials

cd backend
go run cmd/api/main.go
# → 🚀 KernelEye API listening on port 8080
# → 📡 gRPC listening on port 9091 (plaintext or TLS depending on config)

# Apply migrations (run from repo root before cd backend, or use migrations/*.sql)
cd ..
for f in backend/migrations/*.sql; do
  psql "$DATABASE_URL" -f "$f"
done
```

### Dashboard

```bash
cd dashboard
npm install
npm run dev
# → http://localhost:5173
```

## Test the System

Generate traffic to verify detection:

```bash
# Port scan (triggers threat scoring)
for port in $(seq 1 100); do
  nc -z -w1 localhost $port 2>/dev/null &
done

# Check dashboard Threats page — should show high scores for 127.0.0.1
```

## Key Concepts

### Architecture

```text
Agent (eBPF/XDP)  ──gRPC (TLS/mTLS)──>  Backend (Go)  ──REST/WS──>  Dashboard (React)
       │                                       │
       └── pinned maps: /sys/fs/bpf/kerneleye/ │
                                               └── PostgreSQL
```

### Threat Scoring

The scoring engine (`shared/scoring/scorer.go`) uses multi-factor analysis:
connection patterns, port diversity, handshake failures, SYN floods, and
bandwidth anomalies. Scores range 0-100 with thresholds at 30 (suspicious),
60 (malicious), and 80 (critical).

### Remediation

| Layer | Speed | How |
|-------|-------|-----|
| XDP | ~50ns | Drops packets at NIC driver |
| ipset/iptables | ~1µs | Kernel netfilter rules |
| Hybrid | Both | Defense in depth |

KernelEye blocks automatically above a configurable score threshold, or
manually via the dashboard. All block/unblock actions are audit-logged.

### Read-only Mode

Run the agent in monitoring-only mode (no blocking):

```bash
sudo ./kerneleye-agent --read-only
```

## Troubleshooting

### Agent won't start

```bash
# Check kernel version
uname -r  # Need 5.8+

# Check BTF support
ls /sys/kernel/btf/vmlinux

# Check eBPF status
cat /proc/sys/kernel/unprivileged_bpf_disabled  # Should be 0

# Verify you're root
sudo ./kerneleye-agent

# Check CMD_SIGNING_KEY is set when using --enable-remediation
echo $CMD_SIGNING_KEY
```

### Database connection

```bash
docker-compose ps          # Check if postgres is running
docker-compose logs postgres
```

### Dashboard shows no data

```bash
curl http://localhost:8080/health     # Backend health
sudo journalctl -u kerneleye-agent    # Agent logs
tail -f /var/log/kerneleye-audit.log  # Audit trail
```

### gRPC connection refused

```bash
# Agent with plaintext to localhost needs --insecure
./kerneleye-agent --server localhost --insecure

# With TLS, verify cert paths:
./kerneleye-agent --server grpcs://backend:9091 --tls-ca-file /path/to/ca.crt
```

## Next Steps

- [Development Guide](development.md) — Full dev workflow, eBPF debugging
- [Security Architecture](SECURITY_ARCHITECTURE.md) — Trust boundaries, security layers
- [Threat Model](THREAT_MODEL.md) — Attacker profiles, threat matrix
- [Trust Model](TRUST_MODEL.md) — Trust assumptions, command authorization flow
- [Agent README](../agent/README.md) — Agent internals and eBPF programs
