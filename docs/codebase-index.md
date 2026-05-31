# KernelEye Codebase Index

This index maps the first-party code in `kerneleye` (excluding `node_modules`, `.git`, and build artifacts).

## Repository Scope

- First-party files indexed: `267`
- Main products:
1. `agent/` Linux monitoring agent (Go + eBPF/XDP)
2. `backend/` API and ingestion service (Go, Fiber, gRPC, PostgreSQL/sqlc)
3. `dashboard/` React application (TanStack Router + Query, Ant Design)
4. `proto/` gRPC contracts and generated bindings
5. `kerneleye-landing-page/` marketing site

## High-Level Runtime Flow

1. Agent captures traffic via eBPF ring buffer in `agent/main.go`.
2. Agent aggregates/scans/remediates in `agent/aggregator.go` and `agent/remediation/*`.
3. Agent sends heartbeat + traffic over gRPC (`proto/kerneleye/v1/ingest.proto`) via `agent/grpc.go`.
4. Backend ingests/validates/scores in `backend/internal/api/grpc_handlers.go`.
5. Backend persists through sqlc queries in `backend/internal/database/queries/*.sql`.
6. Dashboard reads REST endpoints via `dashboard/src/api/client.ts`.
7. Live updates fan out through backend WebSocket hub and `dashboard/src/context/WebSocketContext.tsx`.

## Entry Points

- Backend process: `backend/cmd/api/main.go`
- Agent process: `agent/main.go`
- Dashboard app bootstrap: `dashboard/src/main.tsx`
- Dashboard routes: `dashboard/src/router.tsx`
- Protocol: `proto/kerneleye/v1/ingest.proto`, `proto/kerneleye/v1/blocks.proto`

## Backend Index (`backend/`)

### API Layer

- `backend/internal/api/auth.go`: JWT auth, refresh tokens, owner-only access middleware.
- `backend/internal/api/oauth.go`: GitHub/Google OAuth handlers.
- `backend/internal/api/handlers.go`: server CRUD, traffic, alerts, stats, API key generation.
- `backend/internal/api/apikey.go`: HMAC API key generation/validation.
- `backend/internal/api/apikey_builder.go`: deployment modes/features, server creation with config, install command builder.
- `backend/internal/api/grpc_handlers.go`: agent register/status/heartbeat/traffic ingestion.
- `backend/internal/api/block_grpc.go`, `backend/internal/api/blocks.go`: block reporting/listing/unblock paths.
- `backend/internal/api/analytics.go`: reports/visualizer endpoints.
- `backend/internal/api/websocket.go`: hub and websocket streaming.

### Data Layer

- SQL sources:
1. `backend/internal/database/queries/queries.sql`
2. `backend/internal/database/queries/blocks.sql`
- Generated sqlc:
1. `backend/internal/database/queries.sql.go`
2. `backend/internal/database/blocks.sql.go`
3. `backend/internal/database/models.go`
- Migrations:
1. Base schema `backend/migrations/001_initial_schema.sql`
2. Incrementals `backend/migrations/002_...` through `backend/migrations/012_...`

### Domain Services

- `backend/internal/scoring/scorer.go`: normalized threat scoring.
- `backend/internal/geoip/geoip.go`: GeoIP lookup service.
- `backend/internal/email/service.go`: email notifications.

## Agent Index (`agent/`)

### Core Runtime

- `agent/main.go`: startup, config parsing, daemon mode, eBPF load, event loop.
- `agent/ebpf.go`: eBPF object loading and attach.
- `agent/tc.go`: TC bandwidth tracking.
- `agent/aggregator.go`: per-IP aggregation, flush timers, heartbeat, gRPC traffic submit.
- `agent/grpc.go`: register/poll approval, gRPC connection targeting/TLS mode.
- `agent/config.go`: CLI/env configuration.
- `agent/buffer.go`: local SQLite buffering for resilience.

### Kernel Programs

- `agent/ebpf/traffic_probe.c`: traffic capture probe.
- `agent/ebpf/xdp_firewall.c`: XDP firewall path.
- `agent/bpf_bpfel_x86.go` + `.o`: generated bindings/artifacts.

### Remediation

- `agent/remediation/analyzer.go`: detection decisions.
- `agent/remediation/hybrid_remediator.go`: orchestration for XDP + iptables/ipset.
- `agent/remediation/xdp_remediator.go`: XDP blocking.
- `agent/remediation/ipset_remediator.go`: ipset-based blocking.
- `agent/remediation/auto_blocker.go`: auto-block policy logic.

## Dashboard Index (`dashboard/`)

- Routing and auth guard: `dashboard/src/router.tsx`
- API clients and interceptors: `dashboard/src/api/client.ts`
- Auth/session context: `dashboard/src/context/AuthContext.tsx`
- WebSocket stream context: `dashboard/src/context/WebSocketContext.tsx`
- Core pages:
1. `dashboard/src/pages/Dashboard.tsx`
2. `dashboard/src/pages/Servers.tsx`
3. `dashboard/src/pages/ServerDetail.tsx`
4. `dashboard/src/pages/Threats.tsx`
5. `dashboard/src/pages/Alerts.tsx`
6. `dashboard/src/pages/Reports.tsx`
7. `dashboard/src/pages/Visualizer.tsx`

## `apikey_builder.go` Analysis

Target: `backend/internal/api/apikey_builder.go`

### What it does

1. Exposes available deployment modes (`/deployment-modes`) and feature metadata (`/agent-features`).
2. Generates API key + client token + install commands (docker/systemd/binary).
3. Persists and returns agent config defaults/fallbacks.

### Observed design notes

- It supports a pending registration model (`CreateServerWithAPIKey` with pending status) then activation via heartbeat/update flow.
- It hardcodes backend host in `getServerHost()` (`api.kerneleye.net:443`), which is convenient for SaaS but reduces deploy-time flexibility.
- It duplicates some logic present in `HandleGenerateAPIKey` in `handlers.go`, suggesting future consolidation potential.

## Notable Maintenance Hotspots

1. Migration numbering collisions (`002_*`, `003_*`) can break strict migration tooling depending on runner assumptions.
2. Multiple server onboarding paths exist:
- `HandleGenerateAPIKey` (placeholder path)
- `HandleGenerateAPIKeyWithConfig` and `HandleCreateServerWithConfig`
- gRPC `Register` fallback creation path
3. API key defaults to `default-secret-change-in-production` if env is missing in `backend/internal/api/apikey.go`.
4. `backend/migrations/001_initial_schema.sql` reflects older server/api_key constraints while later migrations relax/extend behavior.

## Quick Navigation Commands

```bash
# Backend API routes
sed -n '1,260p' backend/cmd/api/main.go

# Agent startup + event loop
sed -n '1,260p' agent/main.go

# gRPC ingestion handlers
sed -n '1,320p' backend/internal/api/grpc_handlers.go

# SQL query contracts
sed -n '1,320p' backend/internal/database/queries/queries.sql
sed -n '1,280p' backend/internal/database/queries/blocks.sql
```
