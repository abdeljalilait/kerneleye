# KernelEye Security Architecture

## Overview

KernelEye operates across three privilege levels:
- **Kernel space** — eBPF/XDP programs with ring-buffer access
- **Userspace agent** — Go daemon loading/managing eBPF, performing remediation
- **Backend/Dashboard** — Central server receiving telemetry, issuing commands

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                      Monitored Host                          │
│                                                              │
│  ┌─────────────┐     ringbuf     ┌───────────────────────┐  │
│  │ eBPF Kernel │ ◄────────────── │  Agent (root)         │  │
│  │   XDP       │                 │  - traffic probe      │  │
│  │   kprobes   │                 │  - XDP management     │  │
│  │   maps      │                 │  - ipset/iptables     │  │
│  └─────────────┘                 │  - audit logging      │  │
│        │                         └───────┬───────────────┘  │
│        │ pinned maps                      │ gRPC + mTLS     │
│        ▼                                 │ cmd signing     │
│  /sys/fs/bpf/kerneleye/                  ▼                  │
└─────────────────────────────────────────────────────────────┘
                                            │
                                    ┌───────▼───────────────┐
                                    │      Backend           │
                                    │  - gRPC ingest         │
                                    │  - analysis workers    │
                                    │  - block management    │
                                    │  - integrity monitor   │
                                    │  - PostgreSQL          │
                                    └───────┬───────────────┘
                                            │ HTTPS + JWT
                                    ┌───────▼───────────────┐
                                    │     Dashboard           │
                                    │  - React SPA           │
                                    │  - WebSocket           │
                                    └───────────────────────┘
```

## Security Layers

### Layer 1: Transport (Phase 1)
- Agent ↔ Backend: gRPC over TLS 1.3 with optional mTLS
- Backend ↔ Dashboard: HTTPS with JWT + HttpOnly refresh cookies
- Plaintext disabled; `--insecure` flag for development only

### Layer 2: Command Authorization (Phase 2)
- Every remediation command (block/unblock/rate-limit) is HMAC-SHA256 signed
- Agents verify signatures before execution
- Monotonic nonces prevent replay attacks
- Structured audit log for all block/unblock actions

### Layer 3: Map Integrity (Phase 3)
- eBPF maps classified by trust level (Low / Medium / High / Very High)
- High-trust maps (blocklists) have all writes audited
- Very-high-trust maps (config) are frozen after initialization
- Periodic pinned map file permission and modification-time checks

### Layer 4: State Attestation (Phase 4)
- Agent periodically reports loaded eBPF program IDs and hashes
- Map state snapshot with pinned path verification
- Agent binary hash self-check
- Backend alerts on integrity violations

## Component Security

### Agent

| Aspect | Mechanism |
|--------|-----------|
| Binary integrity | SHA-256 self-hash reported to backend |
| eBPF program integrity | Program ID + hash verification (Phase 4) |
| Map access control | Trust-level classification + frozen maps |
| Command execution | Signature verification + nonce replay protection |
| Audit trail | Structured JSON to `/var/log/kerneleye-audit.log` |
| Read-only mode | `--read-only` flag disables all remediation |

### Backend

| Aspect | Mechanism |
|--------|-----------|
| Agent authentication | HMAC-SHA256 API key (format: `ke_<payload>`) |
| Dashboard authentication | HS256 JWT + OAuth (GitHub/Google) |
| Command authorization | CMD_SIGNING_KEY-based HMAC signing |
| Rate limiting | Redis-based optional rate limiter |
| Database access | Parameterized queries via pgx/sqlc |

### Dashboard

| Aspect | Mechanism |
|--------|-----------|
| Session management | JWT (24h) + HttpOnly refresh cookie (7d) |
| Cross-agent data isolation | user_id scoping on all queries |
| WebSocket auth | JWT via query parameter upgrade |

## Route Protection

All API routes are authenticated by `AuthMiddleware` (`backend/internal/api/auth.go`).
Agent routes use API keys; dashboard routes use JWT.

| Route | Auth | Type |
|-------|------|------|
| `/api/v1/auth/*` | — | Public (OAuth callbacks, token refresh) |
| `/api/v1/servers/*` | JWT | Dashboard |
| `/api/v1/servers/generate-api-key` | JWT | Dashboard |
| `/api/v1/blocks` | JWT | Dashboard |
| `/api/v1/blocks/:ip/unblock` | JWT | Dashboard |
| `/api/v1/whitelist/*` | JWT | Dashboard |
| `/api/v1/threats` | JWT | Dashboard |
| `/api/v1/alerts` | JWT | Dashboard |
| `/api/v1/analytics/*` | JWT | Dashboard |
| `/api/v1/stats/*` | JWT | Dashboard |
| `/api/v1/ws` | JWT (query param) | Dashboard WebSocket |
| `/health` | — | Public |
| gRPC `IngestService` | API Key | Agent |
| gRPC `BlockService` | API Key | Agent |
| gRPC `ReportIntegrity` | API Key | Agent |

Agent API keys are validated by `ValidateAPIKey()` (`backend/internal/api/apikey.go`):
HMAC-SHA256 format (`ke_<base64>`), database verification, and server status check.

## Configuration Security

Required secrets for production deployment:

| Env Variable | Purpose | Recommendation |
|-------------|---------|----------------|
| `JWT_SECRET` | JWT signing | `openssl rand -base64 32` |
| `API_KEY_SECRET` | Agent API key HMAC | `openssl rand -base64 32` |
| `CMD_SIGNING_KEY` | Command HMAC signing | `openssl rand -base64 32` |
| `GRPC_TLS_CERT_FILE` | gRPC server certificate | Let's Encrypt or internal CA |
| `GRPC_TLS_KEY_FILE` | gRPC server private key | 0600 permissions |
| `GRPC_MTLS_CA_FILE` | mTLS client CA | Only if mTLS enabled |
| `KERNELEYE_TLS_CA_FILE` | Agent backend CA verification | For self-signed certificates |
| `KERNELEYE_TLS_CERT_FILE` | Agent mTLS client certificate | Per-agent identity |
| `KERNELEYE_TLS_KEY_FILE` | Agent mTLS client key | 0600 permissions |
| `AUTH_OWNER_EMAIL` | OAuth restriction | Single email for self-hosted |
