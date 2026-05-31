# Development Guide

Complete development workflow for KernelEye.

## Prerequisites

| Component    | Required For     | Version       |
| ------------ | ---------------- | ------------- |
| Docker       | PostgreSQL       | Latest        |
| Go           | Backend, Agent, Shared | 1.22+    |
| Node.js      | Dashboard        | 18+           |
| clang/llvm   | eBPF compilation | 14+           |
| bpftool      | eBPF development | Latest        |
| protoc       | Protobuf generation | 3.21+       |
| Linux Kernel | Agent            | 5.8+ with BTF |

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                      Agent (Linux, root)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ XDP Firewall│  │eBPF Probes  │  │    Remediation      │  │
│  │ (xdp_*.c)   │  │(traffic_*.c)│  │  XDP + ipset/iptbl  │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│        │                                              │      │
│        │ pinned maps   ┌──────────────────────┐       │      │
│        ▼               │  Command Auth         │       │      │
│  /sys/fs/bpf/          │  HMAC verify + nonce  │       │      │
│  kerneleye/            │  Audit logging        │       │      │
│                        └──────────────────────┘       │      │
│                                   │                    │      │
│                                   │ gRPC + mTLS        │      │
└───────────────────────────────────┼────────────────────┘      │
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│                     Backend (Go)                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ gRPC Server │  │ HTTP/REST   │  │  WebSocket          │  │
│  │ (TLS/mTLS)  │  │ (JWT auth)  │  │  (live stream)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ analysis/ ── scoring worker, block manager, retention   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                           │ SQL                               │
└───────────────────────────┼───────────────────────────────────┘
                            ▼
                    PostgreSQL + Redis
                            ▲
                            │ REST + WebSocket
┌───────────────────────────┴──────────────────────────────────┐
│                    Dashboard (React + Vite)                   │
│  TanStack Router, React Query, Ant Design, WebSocket live    │
└──────────────────────────────────────────────────────────────┘
```

### Shared Packages

```text
shared/
├── scoring/        Threat scoring engine (used by agent + backend)
└── cmdsigning/     HMAC command signing + nonce replay protection
```

## Local Development Setup

### 1. Clone and configure

```bash
git clone https://github.com/abdeljalilait/kerneleye.git
cd kerneleye
cp .env.example .env
```

Edit `.env` with at minimum:

```bash
DATABASE_URL=postgres://kerneleye:kerneleye@localhost:5432/kerneleye
JWT_SECRET=dev-secret
API_KEY_SECRET=dev-secret
CMD_SIGNING_KEY=dev-key   # Required for agent with --enable-remediation
AUTH_OWNER_EMAIL=you@gmail.com
```

### 2. Start PostgreSQL

```bash
docker-compose up -d postgres
sleep 3

for f in backend/migrations/*.sql; do
  docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < "$f"
done
```

### 3. Start Backend

```bash
cd backend
go run cmd/api/main.go
```

Endpoints:
- HTTP API: `http://localhost:8080`
- gRPC: `localhost:9091` (plaintext by default; add TLS env vars for encryption)

### 4. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard: `http://localhost:5173`

### 5. Start Agent (Linux only)

```bash
cd agent

# One-time: generate kernel headers
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
go generate ./...

# Build
go build -o kerneleye-agent

# Run (dev — plaintext via --insecure)
sudo KERNELEYE_API_KEY=ke_... \
     KERNELEYE_SERVER=localhost \
     CMD_SIGNING_KEY=dev-key \
     ./kerneleye-agent --insecure --enable-remediation
```

For monitoring without blocking: `--read-only`
For TLS: omit `--insecure` and use `--tls-ca-file`, `--tls-cert-file`, `--tls-key-file`.

## Component Development

### Agent

#### eBPF Programs (`agent/ebpf/`)

| File              | Purpose                       |
| ----------------- | ----------------------------- |
| `traffic_probe.c` | TCP/UDP connection monitoring |
| `xdp_firewall.c`  | XDP packet filtering          |

After modifying `.c` files:
```bash
go generate ./...
go build -o kerneleye-agent
```

#### Remediation (`agent/remediation/`)

| File                   | Purpose                   |
| ---------------------- | ------------------------- |
| `analyzer.go`          | Threat detection          |
| `auto_blocker.go`      | Score-based auto-blocking |
| `xdp_remediator.go`    | XDP fast-path blocking    |
| `ipset_remediator.go`  | ipset/iptables blocking   |
| `hybrid_remediator.go` | XDP + ipset coordination  |
| `types.go`             | Interfaces and types      |

```bash
go test ./remediation/... -v
```

#### Security (`agent/` root)

| File                    | Purpose                        |
| ----------------------- | ------------------------------ |
| `block_command_client.go` | Receive and verify signed commands |
| `audit.go`              | Structured JSON audit logging  |
| `map_integrity.go`      | Map trust checks and attestation |
| `config.go`             | TLS flags, `--read-only`, `--insecure` |

### Shared Packages (`shared/`)

| Package     | Purpose                                   |
| ----------- | ----------------------------------------- |
| `scoring/`  | Threat scorer with multi-factor analysis  |
| `cmdsigning/` | HMAC-SHA256 sign/verify, nonce tracker |

```bash
cd shared/cmdsigning && go test ./...
cd shared/scoring && go test ./...
```

### Backend

#### Database Queries (sqlc)

After modifying `backend/internal/database/queries/queries.sql`:
```bash
cd backend && sqlc generate
```

#### Migrations
```bash
touch backend/migrations/029_your_change.sql
docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < backend/migrations/029_your_change.sql
```

#### Protobuf

After modifying `proto/kerneleye/v1/*.proto`:
```bash
make gen-proto
cd proto/gen/go && go mod tidy
```

#### Analysis Workers (`backend/internal/analysis/`)

| File                 | Purpose                    |
| -------------------- | -------------------------- |
| `worker.go`          | Background traffic scoring |
| `block_manager.go`   | Auto-block decisions + command signing |
| `data_retention.go`  | Traffic data archival      |
| `monthly_report.go`  | Email reports              |

### Dashboard

Key directories:
- `src/hooks/useQueries.ts` — React Query hooks
- `src/context/WebSocketContext.tsx` — Live updates
- `src/pages/` — Route-level components

Adding an API call:
```typescript
export function useNewFeature() {
  return useQuery({
    queryKey: ['feature'],
    queryFn: () => apiClient.get('/api/v1/new-feature'),
  });
}
```

## Testing

```bash
# Agent
cd agent && go test ./... -v

# Backend
cd backend && go test ./... -v

# Shared
cd shared/scoring && go test ./... -v

# Generate test traffic
for port in $(seq 1 100); do nc -z -w1 localhost $port 2>/dev/null & done
sudo hping3 -S -p 80 --flood localhost   # SYN flood (requires hping3)
```

## Code Quality

```bash
# Go
gofmt -w . && go vet ./...

# TypeScript
cd dashboard && npm run lint && npm run typecheck
```

## Debugging

### eBPF Programs

```bash
sudo bpftool prog list                    # Loaded programs
sudo bpftool map dump name xdp_blocklist  # XDP blocklist contents
sudo cat /sys/kernel/debug/tracing/trace_pipe  # eBPF trace output
```

### Agent

```bash
# Audit log
tail -f /var/log/kerneleye-audit.log

# Debug logging
KERNELEYE_DEBUG=true sudo -E ./kerneleye-agent --insecure
```

### Backend

```bash
# Health check
curl http://localhost:8080/health

# gRPC reflection (if enabled)
grpcurl -plaintext localhost:9091 list
```

## Production Builds

```bash
# Backend
cd backend && CGO_ENABLED=0 go build -o api cmd/api/main.go

# Dashboard
cd dashboard && npm run build   # Output in dist/

# Agent
cd agent && go generate ./... && CGO_ENABLED=0 go build -o kerneleye-agent .
```
