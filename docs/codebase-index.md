# KernelEye Codebase Index

This index maps the first-party code (excluding `node_modules`, `.git`, build artifacts).

## Repository Scope

| Directory | Purpose |
|-----------|---------|
| `agent/` | Linux monitoring agent (Go + eBPF/XDP) |
| `backend/` | API and ingestion service (Go, Fiber, gRPC, PostgreSQL/sqlc) |
| `dashboard/` | React application (TanStack Router + Query, Ant Design, Tailwind) |
| `proto/` | gRPC contracts and generated bindings |
| `shared/` | Packages shared between agent and backend |
| `docs/` | Security, development, and architecture documentation |

## High-Level Runtime Flow

1. Agent captures traffic via eBPF ring buffer in `agent/main.go`.
2. Agent aggregates, scores, and optionally remediates via `agent/aggregator.go` and `agent/remediation/*`.
3. Agent sends heartbeat + traffic batches over gRPC (TLS/mTLS) via `agent/grpc.go`.
4. Backend validates API key, ingests, scores in `backend/internal/api/grpc_handlers.go`.
5. Backend persists via sqlc queries in `backend/internal/database/queries/*.sql`.
6. Backend analysis workers (`backend/internal/analysis/`) score accumulated traffic and manage blocks.
7. Dashboard reads REST endpoints via `dashboard/src/api/client.ts`.
8. Live updates fan through backend WebSocket hub and `dashboard/src/context/WebSocketContext.tsx`.
9. Block commands flow back: Backend → HMAC-signed → gRPC stream → Agent verifies → executes.

## Entry Points

- Backend: `backend/cmd/api/main.go`
- Agent: `agent/main.go`
- Dashboard bootstrap: `dashboard/src/main.tsx`
- Dashboard routes: `dashboard/src/router.tsx`
- Protocol: `proto/kerneleye/v1/ingest.proto`, `proto/kerneleye/v1/blocks.proto`

## Backend Index (`backend/`)

### API Layer

- `backend/cmd/api/main.go` — HTTP + gRPC server startup, middleware, TLS config.
- `backend/internal/api/auth.go` — JWT auth, refresh tokens, OAuth middleware.
- `backend/internal/api/oauth.go` — GitHub/Google OAuth handlers.
- `backend/internal/api/handlers.go` — Server CRUD, traffic, alerts, stats, API key generation.
- `backend/internal/api/apikey.go` — HMAC-SHA256 API key generation and validation.
- `backend/internal/api/apikey_builder.go` — Deployment modes, features metadata, install command builder.
- `backend/internal/api/grpc_handlers.go` — gRPC ingest: Register, Heartbeat, SubmitTraffic, ReportBlockedIP, ReportIntegrity.
- `backend/internal/api/block_grpc.go` — gRPC BlockService: StreamBlockCommands, GetBlockList, ReportBlock.
- `backend/internal/api/blocks.go` — REST block management endpoints.
- `backend/internal/api/whitelist.go` — Whitelist CRUD endpoints.
- `backend/internal/api/analytics.go` — Reports and visualizer endpoints.
- `backend/internal/api/websocket.go` — WebSocket hub, agent command channels, broadcast.

### Analysis Workers

- `backend/internal/analysis/worker.go` — Background scoring of accumulated traffic.
- `backend/internal/analysis/block_manager.go` — Auto-block decisions, HMAC command signing.
- `backend/internal/analysis/data_retention.go` — Traffic data archival and cleanup.
- `backend/internal/analysis/monthly_report.go` — Monthly email reports.

### Data Layer

- SQL sources: `backend/internal/database/queries/queries.sql`, `blocks.sql`
- Generated sqlc: `queries.sql.go`, `blocks.sql.go`, `models.go`
- Migrations: `backend/migrations/001_*.sql` through `028_*.sql`

### Domain Services

- `backend/internal/geoip/geoip.go` — MaxMind GeoIP enrichment.
- `backend/internal/email/service.go` — Mailtrap email notifications.
- `backend/internal/services/services.go` — Port-to-service name resolution.
- `backend/internal/api/ratelimit.go` — Redis-based rate limiting.

## Agent Index (`agent/`)

### Core Runtime

- `agent/main.go` — Startup, registration, eBPF load, event loop, shutdown.
- `agent/ebpf.go` — eBPF object loading and probe attachment.
- `agent/tc.go` — TC bandwidth tracking hooks.
- `agent/aggregator.go` — Per-IP aggregation, flush timers, heartbeat, gRPC submit, reconnection.
- `agent/grpc.go` — TLS/mTLS transport, gRPC connection building, registration polling.
- `agent/config.go` — CLI/env config: TLS flags, `--insecure`, `--read-only`, `--enable-remediation`.
- `agent/buffer.go` — Local SQLite buffer for fault tolerance.
- `agent/flush.go` — Batch submission with retry and buffering.

### Security

- `agent/block_command_client.go` — Receives signed block/unblock/rate-limit commands, verifies HMAC+nonce, checks timestamp window, persists nonce tracker.
- `agent/audit.go` — Structured JSON audit log for all remediation actions.
- `agent/map_integrity.go` — Periodic eBPF map integrity checks, attestation report generation.

### Kernel Programs

- `agent/ebpf/traffic_probe.c` — TCP/UDP traffic capture via kprobes and tracepoints.
- `agent/ebpf/xdp_firewall.c` — XDP packet filter with blocklist, CIDR, rate-limit maps.
- `agent/bpf_x86_bpfel.go` + `.o` — Generated eBPF bindings.

### Remediation

- `agent/remediation/analyzer.go` — Traffic analysis with configurable thresholds.
- `agent/remediation/auto_blocker.go` — Score-based auto-block logic.
- `agent/remediation/hybrid_remediator.go` — XDP + ipset coordinated blocking.
- `agent/remediation/xdp_remediator.go` — XDP fast-path blocking with map pinning.
- `agent/remediation/ipset_remediator.go` — ipset/iptables block management.
- `agent/remediation/types.go` — Interfaces, map trust classification, block types.

## Shared Packages (`shared/`)

- `shared/scoring/scorer.go` — Multi-factor threat scoring engine (connection patterns, port diversity, handshake failures, bandwidth anomalies).
- `shared/scoring/types.go` — IPMetrics, ThreatScore, ThreatLevel types.
- `shared/cmdsigning/signing.go` — HMAC-SHA256 sign/verify, nonce tracker, canonical payload builder for commands and block lists.

## Dashboard Index (`dashboard/`)

- Routing and auth guard: `dashboard/src/router.tsx`
- API client: `dashboard/src/api/client.ts`
- Auth session: `dashboard/src/context/AuthContext.tsx`
- WebSocket stream: `dashboard/src/context/WebSocketContext.tsx`
- Core pages: `Dashboard.tsx`, `Servers.tsx`, `ServerDetail.tsx`, `Threats.tsx`, `Alerts.tsx`, `Reports.tsx`, `Visualizer.tsx`, `BlockedIPs.tsx`, `Whitelist.tsx`, `Login.tsx`, `Profile.tsx`

## Protocol (`proto/`)

- `proto/kerneleye/v1/ingest.proto` — IngestService (Register, Heartbeat, SubmitTraffic, ReportBlockedIP, ReportIntegrity).
- `proto/kerneleye/v1/blocks.proto` — BlockService (StreamBlockCommands, GetBlockList, ReportBlock) with HMAC signature and nonce fields.
- `proto/gen/go/kerneleye/v1/` — Generated Go protobuf code (run `make gen-proto`).

## Notable Maintenance Hotspots

1. Migration numbering (`002_*`, `003_*`) has collisions that can break strict migration tools.
2. Multiple server onboarding paths exist: `HandleGenerateAPIKey`, `HandleCreateServerWithConfig`, gRPC `Register` fallback.
3. API key defaults to `default-secret-change-in-production` if `API_KEY_SECRET` env is missing.
4. `apikey_builder.go` hardcodes `api.kerneleye.net:443` in `getServerHost()` — replace for self-hosted deployments.

## Quick Navigation

```bash
# Backend API routes
sed -n '1,260p' backend/cmd/api/main.go

# Agent startup + event loop
sed -n '1,310p' agent/main.go

# gRPC ingestion handlers
sed -n '1,320p' backend/internal/api/grpc_handlers.go

# Command verification
sed -n '316,420p' agent/block_command_client.go

# SQL query contracts
sed -n '1,320p' backend/internal/database/queries/queries.sql

# Threat scoring logic
sed -n '1,120p' shared/scoring/scorer.go

# HMAC signing
sed -n '1,145p' shared/cmdsigning/signing.go
```
