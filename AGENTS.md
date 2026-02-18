# KernelEye - Agent Documentation

> **AI Coding Agent Guide for KernelEye Project**
> This document provides essential information for AI coding agents working on the KernelEye codebase.

## Project Overview

KernelEye is a real-time Linux server security monitoring platform that uses **eBPF** (Extended Berkeley Packet Filter) and **XDP** (eXpress Data Path) to detect and mitigate network threats at the kernel level—before they reach user applications.

### Core Value Proposition
- **Kernel-Level Monitoring**: Direct network visibility via eBPF hooks (no log parsing)
- **Ultra-Fast Remediation**: XDP-based packet filtering at the NIC driver level (~50ns)
- **Privacy-First**: Only collects connection metadata (IPs, ports, flags)—never payloads
- **Simple Deployment**: Single binary agent with automatic kernel compatibility

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Customer Server (Linux)                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐  │
│  │ XDP Firewall│◄───│   Analyzer  │◄───│   eBPF Probes       │  │
│  │  (kernel)   │    │ (userspace) │    │ (traffic_probe.c)   │  │
│  └─────────────┘    └─────────────┘    └─────────────────────┘  │
│                           │                                      │
│                           │ gRPC (TLS)                           │
└───────────────────────────┼──────────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Central SaaS Backend                        │
│         Ingest → Score → Store → Alert → WebSocket               │
└───────────────────────────┬──────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   PostgreSQL         Dashboard (React)     REST API
   (events, scores)   (Real-time UI)        (management)
```

## Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Agent** | Go 1.25+, eBPF (cilium/ebpf), XDP, TC hooks, gRPC |
| **Backend** | Go, Fiber (HTTP), PostgreSQL (pgx/v5), sqlc, JWT |
| **Dashboard** | React 19, TypeScript, Vite, Ant Design, TanStack Query/Router, Recharts |
| **Protocol** | Protocol Buffers, gRPC (agent→backend), REST (dashboard→backend), WebSocket (live updates) |
| **Infrastructure** | Docker, Docker Compose, Nginx, Make |

## Project Structure

```
kerneleye/
├── agent/                      # eBPF monitoring agent (Go + C)
│   ├── ebpf/
│   │   ├── traffic_probe.c    # eBPF kernel hooks (TCP/UDP/TC)
│   │   └── xdp_firewall.c     # XDP packet filtering
│   ├── remediation/           # Threat mitigation system
│   │   ├── analyzer.go        # Threat detection logic
│   │   ├── xdp_remediator.go  # XDP-based blocking
│   │   ├── remediator.go      # IPSet/iptables blocking
│   │   └── hybrid_remediator.go # Combined approach
│   ├── main.go                # Agent entry point
│   ├── aggregator.go          # Event aggregation & gRPC submission
│   ├── ebpf.go                # eBPF program loading
│   ├── tc.go                  # TC (Traffic Control) bandwidth tracking
│   ├── grpc.go                # gRPC client implementation
│   ├── Makefile               # Build system with semver support
│   ├── install.sh             # Installation script with logging
│   ├── VERSION                # Semantic version file
│   └── go.mod
│
├── backend/                    # Go API server
│   ├── cmd/api/
│   │   └── main.go            # API entry point
│   ├── internal/
│   │   ├── api/               # HTTP/gRPC handlers
│   │   │   ├── handlers.go    # REST endpoints
│   │   │   ├── grpc_handlers.go # gRPC ingestion service
│   │   │   ├── auth.go        # JWT authentication
│   │   │   └── websocket.go   # WebSocket live stream
│   │   ├── database/          # Database layer (sqlc)
│   │   │   ├── queries.sql.go # Generated queries
│   │   │   └── queries/       # SQL query definitions
│   │   ├── scoring/           # Threat scoring engine
│   │   └── geoip/             # GeoIP enrichment service
│   ├── migrations/            # PostgreSQL schema migrations
│   ├── go.mod
│   ├── Dockerfile
│   └── sqlc.yaml              # sqlc configuration
│
├── dashboard/                  # React frontend
│   ├── src/
│   │   ├── api/               # API client
│   │   ├── components/        # UI components (Ant Design)
│   │   ├── pages/             # Route pages
│   │   ├── hooks/             # React Query hooks
│   │   └── context/           # WebSocket context
│   ├── package.json
│   ├── vite.config.ts
│   └── Dockerfile
│
├── proto/                      # Protocol Buffer definitions
│   └── kerneleye/v1/
│       └── ingest.proto       # Agent-API communication schema
│
├── docs/                       # Documentation
│   ├── development.md         # Development workflow
│   └── getting-started.md     # Setup guide
│
├── docker-compose.yml          # Full stack deployment
├── Makefile                   # Build automation
├── setup.sh                   # Development setup script
└── .env.example               # Environment template
```

## Build Commands

The project uses a `Makefile` for common build tasks:

```bash
# Generate all code (protobuf, sqlc, eBPF)
make generate

# Generate specific components
make gen-proto      # Compile .proto files to Go
make gen-sql        # Generate sqlc Go code from SQL
make gen-ebpf       # Compile eBPF C programs (requires clang)

# Build binaries
make build          # Build backend and agent
make build-backend  # Build backend API binary
make build-agent    # Build agent binary (includes gen-ebpf)

# Clean generated files
make clean          # Remove all generated artifacts

# Update dependencies
make deps           # Update and tidy all Go modules
```

### Manual Build Steps

**Backend:**
```bash
cd backend
go mod download
go build -o kerneleye-api ./cmd/api
```

**Agent (Linux only):**

The agent has a dedicated Makefile with semantic versioning support:

```bash
cd agent

# Quick build (uses existing eBPF artifacts)
make build

# Build release binary with version info
make build-release

# Show version information
make version

# Install to system (creates wrapper script and systemd service)
sudo make install

# Uninstall
sudo make uninstall
```

**Agent Makefile targets:**
- `make all` - Check deps, generate eBPF, and build
- `make build` - Build debug binary
- `make build-release` - Build optimized release binary
- `make version` - Display version information
- `make release-patch` - Bump patch version (0.2.0 → 0.2.1)
- `make release-minor` - Bump minor version (0.2.0 → 0.3.0)
- `make release-major` - Bump major version (0.2.0 → 1.0.0)

**Version Information:**
The agent embeds version info at build time using ldflags:
```bash
$ ./kerneleye-agent -version
Version:    0.2.0+abc1234
Git Commit: abc1234
Build Date: 2026-02-18T14:24:59Z
```

**Installation Script:**
For easy installation with logging support:
```bash
sudo ./install.sh              # Full install
./install.sh --help            # Show options
./install.sh --uninstall       # Remove agent
```

The installer creates:
- Binary at `/usr/local/bin/kerneleye-agent`
- Wrapper script at `/usr/local/bin/kerneleye`
- Config at `/etc/kerneleye/agent.env`
- systemd service (if available)
- Logs at `/var/log/kerneleye/`

**Manual Build (without Makefile):**
```bash
cd agent
# Generate eBPF bindings (requires clang, llvm, libbpf-dev)
go generate ./...
# Build
CGO_ENABLED=0 go build -o kerneleye-agent .
```

**Dashboard:**
```bash
cd dashboard
npm install
npm run build    # Production build
npm run dev      # Development server
```

## Development Setup

### Prerequisites

| Component | Required For | Version |
|-----------|--------------|---------|
| Docker | PostgreSQL | Latest |
| Go | Backend & Agent | 1.25+ |
| Node.js | Dashboard | 18+ |
| clang/llvm | eBPF compilation | 14+ |
| bpftool | eBPF development | Latest |
| Linux Kernel | Agent runtime | 5.8+ with BTF |

### Quick Start

1. **Run setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Start services (separate terminals):**
   ```bash
   # Terminal 1: Database
docker-compose up -d postgres
   
   # Terminal 2: Backend
   cd backend && go run cmd/api/main.go
   
   # Terminal 3: Dashboard
   cd dashboard && npm run dev
   
   # Terminal 4: Agent (Linux only, requires root)
   cd agent && sudo ./kerneleye-agent
   ```

3. **Access dashboard:** http://localhost:3000
   - Login: `demo@kerneleye.io` / `demo`

### Environment Variables

Create `.env` from `.env.example`:

```bash
# Database
DATABASE_URL=postgres://kerneleye:changeme@localhost:5432/kerneleye?sslmode=disable
DB_PASSWORD=changeme

# API
PORT=8080
GRPC_PORT=9091
CORS_ORIGINS=http://localhost:3000
JWT_SECRET=dev-secret-change-in-production

# Agent
KERNELEYE_API_KEY=demo-key
KERNELEYE_SERVER=localhost:8080
```

## Code Generation Workflow

### Database (sqlc)

After modifying `backend/internal/database/queries/queries.sql`:

```bash
cd backend
sqlc generate
```

This generates type-safe Go code from SQL queries.

### Protocol Buffers

After modifying `proto/kerneleye/v1/ingest.proto`:

```bash
make gen-proto
```

### eBPF Programs

After modifying `agent/ebpf/*.c` files:

```bash
cd agent
go generate ./...
```

This uses `bpf2go` to compile C code and generate Go bindings.

## Testing

### Unit Tests

```bash
# Agent
cd agent
go test ./... -v
go test ./remediation/... -v -race

# Backend
cd backend
go test ./... -v
```

### Integration Testing

Generate test traffic to verify detection:

```bash
# Port scan (triggers high threat score)
for port in {1..100}; do nc -zv localhost $port; done

# SYN flood (requires hping3)
sudo hping3 -S -p 80 --flood localhost

# Normal traffic
curl http://localhost
```

### eBPF Debugging

```bash
# List loaded eBPF programs
sudo bpftool prog list

# View XDP maps
sudo bpftool map dump name blocked_ips
sudo bpftool map dump name rate_limits

# Trace eBPF output
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Code Style Guidelines

### Go

- **Formatting**: Use `gofmt -w .`
- **Linting**: Run `golangci-lint run` and `go vet ./...`
- **Imports**: Group standard library, third-party, and local imports
- **Error Handling**: Always check errors, use descriptive error messages
- **Comments**: Document exported functions and types

### TypeScript/React

- **Linting**: Run `npm run lint` (if configured)
- **Type Safety**: Enable strict TypeScript checks
- **Components**: Use functional components with hooks
- **State Management**: Use TanStack Query for server state
- **Styling**: Use Ant Design components, Tailwind for custom styles

### eBPF C Code

- **License**: Always include `GPL` license identifier
- **Safety**: Verify bounds checking, use `BPF_CORE_READ` for portability
- **Comments**: Document security considerations and limitations

## Security Considerations

### Agent Privileges

The agent requires elevated privileges:
- `CAP_BPF` - Load eBPF programs
- `CAP_NET_ADMIN` - Attach XDP/TC programs, manage iptables
- `CAP_NET_RAW` - Raw socket access

**Never run the agent with more privileges than necessary.**

### Data Privacy

**Collected (metadata only):**
- Source/Destination IP addresses
- Ports and protocols (TCP/UDP)
- Connection flags (SYN/ACK)
- Packet counts & bytes in/out
- Traffic direction (inbound/outbound)
- Process info (PID, command name) - agent only

**Never Collected:**
- Packet payloads
- HTTP headers or bodies
- User credentials
- Application data

### Database Security

- Use strong passwords in production
- Enable SSL/TLS for database connections
- Rotate JWT secrets regularly
- Store API keys hashed (SHA-256)

## Deployment

### Docker Compose (Development)

```bash
# Full stack
docker-compose up -d

# Individual services
docker-compose up -d postgres
docker-compose up -d backend
docker-compose up -d dashboard
```

### Production Considerations

1. **Environment**: Use proper `JWT_SECRET` and `DB_PASSWORD`
2. **TLS**: Terminate TLS at reverse proxy (Nginx/Traefik)
3. **Database**: Use managed PostgreSQL with backups
4. **Agent**: Distribute via package manager or binary
5. **Monitoring**: Add health checks and metrics collection

## Key Files Reference

| File | Purpose |
|------|---------|
| `agent/main.go` | Agent initialization and event loop |
| `agent/Makefile` | Build system with semantic versioning |
| `agent/install.sh` | Installation script with logging |
| `agent/VERSION` | Semantic version file |
| `agent/ebpf/traffic_probe.c` | eBPF kernel hooks |
| `agent/remediation/analyzer.go` | Threat detection logic |
| `backend/cmd/api/main.go` | API server setup |
| `backend/internal/api/grpc_handlers.go` | Agent ingestion service |
| `backend/internal/scoring/scorer.go` | Threat scoring engine |
| `backend/migrations/001_initial_schema.sql` | Database schema |
| `proto/kerneleye/v1/ingest.proto` | Agent-API protocol |
| `dashboard/src/context/WebSocketContext.tsx` | Real-time updates |

## Troubleshooting

### "Failed to load eBPF"
- Check kernel version: `uname -r` (need 5.8+)
- Verify BTF support: `ls /sys/kernel/btf/vmlinux`
- Ensure running as root

### "sqlc: command not found"
```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### gRPC Import Errors
Ensure `proto/gen/go` module is generated:
```bash
make gen-proto
```

## Resources

- **Documentation**: `docs/development.md`, `docs/getting-started.md`
- **Agent Details**: `agent/README.md`
- **Project Summary**: `PROJECT_SUMMARY.md`
