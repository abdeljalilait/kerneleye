# KernelEye Trust Model

## Principle

KernelEye is designed around explicit trust boundaries. It does not treat
eBPF maps, runtime state, agent/backend communication, or remediation logic
as opaque data — each is classified as an integrity-sensitive component.

## Trust Assumptions

### Who trusts whom?

**Agent trusts Backend** for:
- Remediation commands (block, unblock, rate-limit)
- Signed by `CMD_SIGNING_KEY` (Phase 2)
- Transport authenticated by mTLS (Phase 1)
- Replay-protected by monotonic nonces (Phase 2)

**Backend trusts Agent** for:
- Telemetry data (traffic events, blocked IP reports)
- Authenticated by HMAC-signed API key
- Integrity validated by periodic attestation reports (Phase 4)
- Transport authenticated by mTLS (Phase 1)

**Dashboard trusts Backend**:
- Authenticated by HTTPS + JWT
- Authorized by OAuth (GitHub/Google) with owner email restriction

**Agent does NOT trust:**
- The network (all traffic encrypted and authenticated)
- Unauthenticated gRPC requests (plaintext disabled)
- Unsigned commands (signature verification required)
- Arbitrary map mutations (trust-level classification)

**Backend does NOT trust:**
- Agent telemetry without API key validation
- Agent status without periodic heartbeat verification
- Agent integrity without attestation reports

### What is the trust boundary?

```
┌─── Untrusted ──────────────────────────────────────────────┐
│  Network (internet)                                         │
│  Other processes on the agent host (non-root)                │
│  Dashboard users (unauthenticated)                          │
├─── Conditional Trust ───────────────────────────────────────┤
│  Agent ↔ Backend connection (mTLS authenticated)            │
│  Backend ↔ Agent command stream (HMAC signed)               │
│  Dashboard users (OAuth authenticated, JWT authorized)      │
├─── Trusted ─────────────────────────────────────────────────┤
│  Agent root process (must have CAP_BPF, CAP_NET_ADMIN)      │
│  eBPF programs loaded by the agent                          │
│  Pinned maps at /sys/fs/bpf/kerneleye/ (owned by agent)     │
│  Backend process (runs the API and analysis workers)        │
│  PostgreSQL (accessed only by backend)                      │
└─────────────────────────────────────────────────────────────┘
```

## eBPF Map Trust Classification

KernelEye maps are classified into four trust levels. Each level defines
who can write to the map, whether writes are audited, and whether the map
is frozen after initialization.

| Trust Level | Map Examples | Writers | Audited | Frozen |
|-------------|-------------|---------|---------|--------|
| **Very High** | `xdp_rate_config` | Agent (init only) | Yes | Yes |
| **High** | `xdp_blocklist`, `xdp_cidr_blocklist` | Agent + backend commands | Yes | No |
| **Medium** | `events`, `xdp_stats`, `ip_stats` | Kernel (eBPF) | No | No |
| **Low** | `rate_limiter`, `syn_tracker`, `debug_counters` | Kernel (eBPF) | No | No |

## Failure Behavior

### What happens when trust is broken?

KernelEye follows a **fail-closed** principle:

| Trust Failure | Behavior |
|--------------|----------|
| TLS handshake fails | Agent retries with exponential backoff; never falls back to plaintext |
| mTLS client cert missing/invalid | Backend rejects connection |
| Command signature invalid | Agent refuses to execute; logs to audit trail; sends alert to backend |
| Nonce replayed | Agent rejects command; logs to audit trail |
| Frozen map mutates | Agent logs integrity violation; periodic report flags it to backend |
| API key invalid | Backend returns UNAUTHENTICATED; agent retries registration |
| Agent heartbeat lost (>2 min) | Backend marks server offline; dashboard shows disconnected |
| Agent binary hash mismatch | Integrity report includes mismatch; backend generates alert |

### What does NOT cause a failure?

These conditions are tolerated but logged:

- GeoIP database missing (telemetry enriched without location)
- Email service not configured (alerts through dashboard only)
- Rate limiter not initialized (backend operates without rate limiting)
- History store unavailable (scoring works without persistent context)

## Command Authorization Flow

```
Dashboard user clicks "Block IP"
        │
        ▼
Backend REST endpoint (JWT auth)
        │
        ▼
BlockManager.sendBlockCommand()
        │
        ▼
signCommand() — HMAC-SHA256 with CMD_SIGNING_KEY + nonce
        │
        ▼
Hub.SendCommandToAgent() — via agent command channel
        │
        ▼
block_grpc.go StreamBlockCommands — reads channel, sends proto
        │
        ▼
gRPC stream (TLS/mTLS encrypted)
        │
        ▼
Agent block_command_client.go receiveLoop()
        │
        ▼
verifyCommand() — HMAC verification + nonce check
        │
        ├─ FAIL: AuditLogCommandRejected() — do not execute
        │
        └─ PASS: AuditLogCommandAccepted() — execute block
```

## Key Management

| Key | Scope | Rotation |
|-----|-------|----------|
| `JWT_SECRET` | Dashboard session tokens | Restart backend |
| `API_KEY_SECRET` | Agent API key HMAC | Regenerate keys per server |
| `CMD_SIGNING_KEY` | Command HMAC signing | Restart both agent and backend |
| TLS certificates | gRPC transport encryption | Standard cert renewal |
| mTLS client certs | Per-agent identity | Regenerate per agent |

## Deployment Recommendations

### Production (self-hosted)

```bash
# Generate all secrets
export JWT_SECRET="$(openssl rand -base64 32)"
export API_KEY_SECRET="$(openssl rand -base64 32)"
export CMD_SIGNING_KEY="$(openssl rand -base64 32)"

# Generate TLS certificates (Let's Encrypt or internal CA)
# server.crt + server.key for backend gRPC
# agent.crt + agent.key for each agent (mTLS)
# ca.crt for both sides

# Set file permissions
chmod 600 /etc/kerneleye/agent.env
chmod 600 /var/log/kerneleye-audit.log

# Run agent with TLS
sudo kerneleye-agent \
  --server grpcs://backend.example.com \
  --tls-ca-file /etc/kerneleye/ca.crt \
  --tls-cert-file /etc/kerneleye/agent.crt \
  --tls-key-file /etc/kerneleye/agent.key
```

### Development (non-production)

```bash
# Agent in insecure mode (plaintext gRPC)
kerneleye-agent --server localhost --insecure

# Backend without TLS (plaintext gRPC server)
# Leave GRPC_TLS_CERT_FILE and GRPC_TLS_KEY_FILE unset
```

Always set `CMD_SIGNING_KEY` even in development to test command signing.
