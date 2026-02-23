# Development Guide

Complete development workflow for KernelEye.

## Prerequisites

| Component    | Required For     | Version       |
| ------------ | ---------------- | ------------- |
| Docker       | PostgreSQL       | Latest        |
| Go           | Backend & Agent  | 1.21+         |
| Node.js      | Dashboard        | 18+           |
| clang/llvm   | eBPF compilation | 14+           |
| bpftool      | eBPF development | Latest        |
| Linux Kernel | Agent            | 5.8+ with BTF |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent (Linux)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ XDP Firewall│  │eBPF Probes  │  │    Remediation      │  │
│  │ (xdp_*.c)   │  │(traffic_*.c)│  │    (Go)             │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                           │                                  │
│                           │ gRPC                             │
└───────────────────────────┼──────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                     Backend (Go)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ gRPC Server │  │ HTTP/REST   │  │  WebSocket          │  │
│  │ (handlers)  │  │ (handlers)  │  │  (live stream)      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                           │                                  │
│                           │ SQL                              │
└───────────────────────────┼──────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL                               │
│  users | servers | traffic | threats | api_keys             │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ REST + WebSocket
┌───────────────────────────┴──────────────────────────────────┐
│                    Dashboard (React)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │ React Query │  │ Components  │  │  WebSocket Context  │   │
│  │ (caching)   │  │ (UI)        │  │  (live updates)     │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Local Development Setup

### 1. Clone & Configure

```bash
git clone https://github.com/abdeljalilait/kerneleye.git
cd kerneleye
cp .env.example .env
```

### 2. Start PostgreSQL

```bash
docker-compose up -d postgres
sleep 5

# Run all migrations
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

Endpoints:

- HTTP API: `http://localhost:8080`
- gRPC: `localhost:50051`
- WebSocket: `ws://localhost:8080/api/v1/ws`

### 4. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard: `http://localhost:3000`

### 5. Start Agent (Linux)

```bash
cd agent

# Generate kernel headers (one-time)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# Generate Go bindings
go generate ./...

# Build
go build -o kerneleye-agent

# Run (requires root)
sudo ./kerneleye-agent
```

## Component Development

### Agent Development

#### eBPF Programs

Located in `agent/ebpf/`:

| File              | Purpose                       |
| ----------------- | ----------------------------- |
| `traffic_probe.c` | TCP/UDP connection monitoring |
| `xdp_firewall.c`  | XDP packet filtering          |

After modifying `.c` files:

```bash
go generate ./...
go build -o kerneleye-agent
```

#### Remediation System

Located in `agent/remediation/`:

| File                   | Purpose                 |
| ---------------------- | ----------------------- |
| `analyzer.go`          | Threat detection logic  |
| `xdp_remediator.go`    | XDP-based blocking      |
| `remediator.go`        | IPSet/iptables blocking |
| `hybrid_remediator.go` | Combined approach       |

Run tests:

```bash
go test ./remediation/... -v
```

### Backend Development

#### Database Queries (sqlc)

After modifying `backend/internal/database/queries/queries.sql`:

```bash
cd backend
sqlc generate
```

#### Adding Migrations

```bash
# Create new migration
touch backend/migrations/010_your_change.sql

# Apply
docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < backend/migrations/010_your_change.sql
```

#### Protobuf Changes

After modifying `proto/kerneleye/v1/ingest.proto`:

```bash
cd proto
buf generate
```

### Dashboard Development

#### Key Files

| Path                               | Purpose             |
| ---------------------------------- | ------------------- |
| `src/hooks/useQueries.ts`          | React Query hooks   |
| `src/context/WebSocketContext.tsx` | Live stream         |
| `src/components/LiveStream.tsx`    | Real-time feed      |
| `src/pages/ServerDetail.tsx`       | Server traffic view |

#### Adding API Calls

All API calls use React Query. Add hooks in `useQueries.ts`:

```typescript
export function useNewFeature() {
  return useQuery({
    queryKey: ['feature'],
    queryFn: () => apiClient.get('/api/v1/feature'),
  });
}
```

## Testing

### Agent Tests

```bash
cd agent
go test ./... -v
go test ./remediation/... -v -race  # With race detector
```

### Backend Tests

```bash
cd backend
go test ./... -v
```

### Integration Testing

Generate test traffic:

```bash
# Port scan
nmap -p 1-100 localhost

# SYN flood (requires hping3)
sudo hping3 -S -p 80 --flood localhost

# Normal connections
for i in {1..10}; do curl localhost; done
```

## Code Quality

### Go

```bash
# Format
gofmt -w .

# Lint
golangci-lint run

# Vet
go vet ./...
```

### TypeScript

```bash
cd dashboard
npm run lint
npm run typecheck
```

## Debugging

### eBPF Programs

```bash
# List loaded programs
sudo bpftool prog list

# View XDP maps
sudo bpftool map dump name blocked_ips
sudo bpftool map dump name rate_limits

# Trace eBPF output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Backend

```bash
# Enable debug logging
export LOG_LEVEL=debug
go run cmd/api/main.go
```

### WebSocket

Open browser DevTools → Network → WS tab to inspect live stream messages.

## Production Build

### Backend

```bash
cd backend
CGO_ENABLED=0 go build -o api cmd/api/main.go
```

### Dashboard

```bash
cd dashboard
npm run build
# Output in dist/
```

### Agent

```bash
cd agent
go generate ./...
CGO_ENABLED=0 go build -o kerneleye-agent .
```

## Common Issues

### "Failed to load eBPF"

- Check kernel: `uname -r` (need 5.8+)
- Check BTF: `ls /sys/kernel/btf/vmlinux`
- Run as root

### "sqlc: command not found"

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### "buf: command not found"

```bash
go install github.com/bufbuild/buf/cmd/buf@latest
```

## Support

- Documentation: [docs/](.)
- Issues: GitHub Issues
- Email: support@kerneleye.net
