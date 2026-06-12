<p align="center">
  <img src="dashboard/logo_kerneleye.png" alt="KernelEye Logo" width="180">
</p>

# KernelEye

> Kernel-level traffic intelligence and threat remediation for Linux servers.

KernelEye is a self-hosted security monitoring platform for Linux servers. It uses eBPF, TC, and XDP in a Go agent to observe network metadata, score suspicious activity, and apply remediation through kernel-level XDP blocking and ipset/iptables rules. A Go backend stores and analyzes events, while a React dashboard provides server management, live traffic, threat views, blocked IPs, whitelisting, reports, and analytics.

## What It Does

- Real-time Linux traffic monitoring with eBPF.
- Bandwidth tracking with TC hooks.
- Threat scoring from shared Go scoring logic in `shared/scoring`.
- Agent-side analysis and optional automatic remediation.
- XDP fast-path packet blocking and ipset/iptables fallback.
- Backend-side analysis workers, block management, data retention, and monthly reports.
- gRPC ingestion and block command streaming between agent and backend with TLS/mTLS encryption and HMAC command signing.
- Monotonic nonce replay protection and structured audit logging for all remediation actions.
- Periodic eBPF map integrity verification and state attestation reports.
- React dashboard with WebSocket updates, server detail views, blocked IP management, whitelisting, reports, and analytics.
- GeoIP enrichment when MaxMind databases are configured.
- OAuth support for GitHub and Google (single-owner self-hosted access).
- Privacy-first collection: metadata only, no packet payloads.

## Architecture

```text
Monitored Linux host
  eBPF traffic probe + TC bandwidth hooks
  XDP firewall and ipset/iptables remediation
  Go agent (HMAC command verification, audit log)
      |
      | gRPC (TLS/mTLS) + HMAC-signed block commands
      v
Go backend API
  Fiber HTTP API
  gRPC ingest/block services (TLS/mTLS, command signing)
  analysis worker, block manager, retention, reports
  integrity report handler
      |
      v
PostgreSQL
      ^
      |
React dashboard
  REST API + WebSocket live updates
```

## Key Components

### Agent

The agent lives in `agent/` and is the Linux host process.

- `agent/main.go` starts registration, eBPF loading, bandwidth tracking, remediation, scoring, aggregation, and block command streaming.
- `agent/ebpf/traffic_probe.c` captures traffic metadata.
- `agent/ebpf/xdp_firewall.c` implements XDP packet filtering.
- `agent/tc.go` configures TC bandwidth tracking.
- `agent/aggregator.go` batches and flushes events to the backend.
- `agent/history_store.go` and `agent/flush.go` handle local persistence and retry behavior.
- `agent/remediation/` contains analyzer, auto-blocking, XDP, ipset, and hybrid remediators.

The agent requires Linux and elevated privileges for eBPF/XDP operations.

### Backend

The backend lives in `backend/`.

- `backend/cmd/api/main.go` starts the Fiber HTTP API and gRPC services.
- `backend/internal/api/` contains auth, dashboard handlers, gRPC handlers, block APIs, whitelist APIs, WebSocket handling, and rate limiting.
- `backend/internal/analysis/` contains scoring workers, block management, data retention, and monthly report logic.
- `backend/internal/database/` contains sqlc-generated database access code.
- `backend/internal/geoip/` handles GeoIP enrichment.
- `backend/internal/email/` sends Mailtrap-backed emails when configured.
- `backend/migrations/` contains PostgreSQL migrations.

HTTP defaults to port `8080`; gRPC defaults to port `9091`.

### Dashboard

The dashboard lives in `dashboard/` and is a Vite React application.

- `dashboard/src/pages/` includes overview, servers, server detail, threats, alerts, reports, visualizer, blocked IPs, whitelist, login, profile, and OAuth callback pages.
- `dashboard/src/components/` contains live traffic, block feed, charts, server lists, configurators, and shared layout components.
- `dashboard/src/api/client.ts` defines the REST API client.
- `dashboard/src/context/WebSocketContext.tsx` manages live event updates.

The dev server is configured for `http://localhost:3000`.

### Landing Page

The public marketing site lives in `kerneleye-landing-page/`. The production frontend image builds both the landing page and dashboard, then serves them through nginx.

### Shared Code and Protocols

- `shared/scoring/` contains the shared threat scoring module used by both agent and backend.
- `shared/cmdsigning/` contains the HMAC-SHA256 command signing and nonce replay protection module.
- `proto/kerneleye/v1/` contains protobuf definitions for ingest and block services.
- `proto/gen/go/` contains generated Go protobuf code.

## Privacy

KernelEye does not inspect packet payloads or application content.

Collected metadata includes:

- Source and destination IP addresses.
- Ports and protocols.
- TCP flags and connection counters.
- Packet and byte counts.
- Traffic direction.
- Timestamps.
- Optional GeoIP/ASN enrichment.

Not collected:

- Packet payloads.
- HTTP request bodies or headers.
- User credentials.
- Application data.

## Threat Scoring

Threat scoring is implemented in `shared/scoring/scorer.go`. The current scorer is more nuanced than a single linear formula: it considers SYN rate, unique port access, failed handshakes, burst behavior, service abuse, direction, confidence, and score decay over time.

Default classification thresholds:

```text
< 20   normal
20-39  suspicious
>= 40  malicious
>= 40  eligible for auto-blocking when remediation is enabled
```

The backend analysis worker also uses accumulated traffic windows and can trigger block management for high-risk sources.

## Remediation

KernelEye supports active remediation when enabled on the agent.

| Layer | Implementation | Purpose |
| --- | --- | --- |
| XDP | `agent/remediation/xdp_remediator.go` | Fast kernel-level drops before the network stack |
| IPSet | `agent/remediation/ipset_remediator.go` | ipset/iptables block management |
| Hybrid | `agent/remediation/hybrid_remediator.go` | Coordinates XDP and ipset behavior |
| Auto-blocker | `agent/remediation/auto_blocker.go` | Blocks sources above configured score thresholds |
| Backend block manager | `backend/internal/analysis/block_manager.go` | Coordinates backend-generated block state and commands |

The dashboard also exposes blocked IP and whitelist management.

## Quick Start

### Prerequisites

- Go 1.25.x for the current backend and agent modules.
- Node.js/npm for the React apps.
- PostgreSQL 14+ or 15+.
- For the agent: Linux with BTF support, root privileges, clang/LLVM, bpftool, libbpf headers, ipset, and iptables.

### Configure Environment

```bash
cp .env.example .env
```

Set at least:

```text
DATABASE_URL=postgres://kerneleye:<password>@localhost:5432/kerneleye?sslmode=disable
JWT_SECRET=<at-least-32-characters>
API_KEY_SECRET=<strong-secret>
CORS_ORIGINS=http://localhost:3000
```

Optional integrations include Redis rate limiting, Mailtrap email, GitHub/Google OAuth, and MaxMind GeoIP.

### Start Backend

```bash
cd backend
go mod download
go run cmd/api/main.go
```

The backend starts:

- HTTP API on `http://localhost:8080`
- gRPC on `localhost:9091`

### Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000`.

Sign-in is OAuth-only. Set `AUTH_OWNER_EMAIL` and configure at least one OAuth provider (GitHub or Google) for dashboard access. Only the configured owner email is permitted to sign in.

### Build and Run Agent

```bash
cd agent
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
go generate ./...
go build -o kerneleye-agent
sudo KERNELEYE_API_KEY=<server-api-key> \
  KERNELEYE_SERVER=localhost:8080 \
  KERNELEYE_GRPC_URL=localhost:9091 \
  ./kerneleye-agent
```

Useful agent flags:

```text
-enable-remediation     enable active blocking and auto-blocking
-xdp                    enable XDP fast-path blocking
-interface <name>       select XDP network interface
--read-only             monitor and report only, never block
--insecure              disable TLS (dev only)
--tls-ca-file <path>    backend CA certificate for TLS verification
--tls-cert-file <path>  agent client certificate for mTLS
--tls-key-file <path>   agent client private key for mTLS
-list-blocked           print current ipset state and exit
-flush-blocklists       flush ipset and XDP blocklists and exit
-clear-data             remove local agent SQLite stores and exit
-version                print build version
```

When `--enable-remediation` is set, `CMD_SIGNING_KEY` must be configured on
both agent and backend. Generate with `openssl rand -base64 32`.

## Project Structure

```text
kerneleye/
├── agent/                     Go eBPF/XDP monitoring agent
│   ├── ebpf/                  eBPF C programs and compiled objects
│   ├── remediation/           analyzer, XDP, ipset, hybrid remediation
│   ├── assets/                embedded XDP object assets
│   └── scripts/               ipset helper scripts and service files
├── backend/                   Go Fiber API and gRPC backend
│   ├── cmd/api/               backend entrypoint
│   ├── internal/api/          HTTP, auth, WebSocket, gRPC, block APIs
│   ├── internal/analysis/     workers, blocking, retention, reports
│   ├── internal/database/     sqlc generated queries and helpers
│   ├── internal/email/        Mailtrap email service
│   ├── internal/geoip/        MaxMind GeoIP service
│   └── migrations/            PostgreSQL migrations
├── dashboard/                 React dashboard app
├── kerneleye-landing-page/    React landing page app
├── proto/                     protobuf definitions and generated Go code
├── shared/
│   ├── scoring/            shared threat scoring Go module
│   └── cmdsigning/         HMAC command signing and nonce tracking
├── docs/                      additional project documentation
├── tests/                     traffic simulation shell scripts
├── docker/                    frontend nginx and install script templates
├── Dockerfile.backend         backend container build
├── Dockerfile.frontend        landing + dashboard + agent download image
├── docker-compose.yml         production-oriented compose stack
└── Makefile                   generation, build, and docker targets
```

## Tech Stack

| Layer | Technologies |
| --- | --- |
| Agent | Go, cilium/ebpf, XDP, TC, gRPC, SQLite local stores, zap |
| Backend | Go, Fiber, gRPC, PostgreSQL, sqlc, Redis, Mailtrap |
| Dashboard | React, TypeScript, Vite, Ant Design, React Query, Recharts |
| Landing page | React, TypeScript, Vite, Tailwind CSS |
| Protocols | Protobuf, gRPC |
| Deployment | Docker, Docker Compose, nginx, Traefik labels |

## Tested On

The KernelEye agent has been tested on the following configurations. This table is updated as new environments are validated.

| OS                   | Kernel          | CPU                    | RAM   | Arch   | Notes           |
|----------------------|-----------------|------------------------|-------|--------|-----------------|
| Ubuntu 26.04 LTS     | 7.0.0-15-generic| AMD EPYC-Genoa (2 vCPU)| 3.7 GB| x86_64 | —               |

> We use [ebpf-go](https://ebpf-go.dev/guides/getting-started/) for the eBPF userspace integration.

## Build and Generation

Common Make targets:

```bash
make gen-proto
make gen-sql
make gen-ebpf
make build-backend
make build-agent
make build
make docker-build
```

The frontend Docker image builds the landing page, dashboard, and a downloadable Linux agent binary.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Development Guide](docs/development.md)
- [Codebase Index](docs/codebase-index.md)
- [Security Architecture](docs/SECURITY_ARCHITECTURE.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Trust Model](docs/TRUST_MODEL.md)
- [Scoring System Analysis](docs/scoring-system-analysis.md)
- [Agent Architecture](agent/README.md)
- [Remediation](agent/remediation/README.md)
- [Database Migrations](backend/migrations/)

## Contact

- Website: https://example.com
- Email: abdeljalil.aitetaleb@gmail.com

## License

KernelEye is open source under the **Apache License, Version 2.0** (`Apache-2.0`). See [LICENSE](LICENSE).

Copyright 2026 Abdeljalil Aitetaleb.

The KernelEye name, logos, and visual identity are not licensed under the Apache License. See [TRADEMARKS.md](TRADEMARKS.md) for brand-use terms.
