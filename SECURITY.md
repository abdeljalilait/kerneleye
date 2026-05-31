# Security Policy

KernelEye is a self-hosted, open-source eBPF/XDP security and observability tool.
It runs with kernel privileges. Security is a fundamental design constraint,
not an afterthought.

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected vulnerabilities.**

Email: abdeljalil.aitetaleb@gmail.com

Include:
- Affected component, version, or commit
- Impact summary
- Reproduction steps or proof-of-concept
- Any relevant logs or environment details

### Response Timeline

- Acknowledgement within 72 hours
- Status update within 7 days
- Disclosure coordinated with reporter

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| main    | :white_check_mark: |
| latest release  | :white_check_mark: |
| older releases   | :x:                |

Only the current default branch and the latest tagged release receive security
patches. Upgrade guidance is included in each release note.

## Architecture & Scope

KernelEye consists of four primary components:

1. **Agent** — eBPF/XDP programs running in kernel space + a Go userspace daemon.
   The agent loads and manages eBPF maps, collects traffic telemetry, and executes
   remediation actions (block/unblock/rate-limit).

2. **Backend** — Go HTTP + gRPC server. Receives telemetry, runs analysis,
   manages block lists, and issues remediation commands to agents.

3. **Dashboard** — React SPA. Displays telemetry, alerts, and block management UI.

4. **Protocol** — gRPC (protobuf) between agent and backend. REST + WebSocket
   between dashboard and backend.

### Security Boundaries

| Boundary | Description |
|----------|-------------|
| Kernel ↔ Agent userspace | eBPF map access, ring buffer reads. Maps pinned to `/sys/fs/bpf/`. |
| Agent ↔ Backend | gRPC over mTLS. Agent identity per-machine. |
| Backend ↔ Dashboard | HTTPS + JWT auth. |
| Agent ↔ BPF filesystem | Pinned map files at `/sys/fs/bpf/kerneleye/`. |
| Agent configuration | `/etc/kerneleye/agent.env` (must be root-readable only). |

### What KernelEye Protects Against

- Network-level attacks detected via eBPF traffic probes (SYN floods, port scans,
  brute-force patterns, data exfiltration patterns)
- Attack traffic blocked via XDP (fast-path) or iptables/ipset

### What KernelEye Does NOT Protect Against

KernelEye is not:
- A host intrusion detection system (HIDS)
- A file integrity monitor
- A kernel rootkit detector
- A replacement for OS-level access controls (SELinux, AppArmor)
- A network firewall (it augments, does not replace)

### Known Limitations

- **eBPF privilege requirement**: The agent requires `CAP_BPF`, `CAP_NET_ADMIN`,
  and `CAP_SYS_ADMIN` (or runs as root). This is inherent to eBPF/XDP operation.
- **IPv4 primary**: IPv6 support exists but is less battle-tested.
- **XDP driver mode**: Falls back to generic SKB mode on unsupported NICs,
  reducing throughput.
- **Single backend**: The current architecture has one backend. No federation
  or peer-to-peer agent communication.
- **No remote attestation**: Agent integrity is validated via periodic reports
  but there is no hardware-rooted (TPM) attestation in this version.

## Responsible Disclosure

We follow [CVD (Coordinated Vulnerability Disclosure)](https://www.cisa.gov/coordinated-vulnerability-disclosure-process).

1. Reporter submits privately via email.
2. Maintainer acknowledges within 72 hours.
3. Maintainer investigates and develops a fix.
4. Fix is released. CVE may be requested if applicable.
5. Public disclosure after the fix is available (typically within 90 days).

## Security Roadmap

See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for the
current architecture and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the
threat model. The security roadmap covers:

1. **Transport hardening** — mTLS between agent and backend, certificate
   validation, removal of plaintext fallback (Phase 1)
2. **Command authorization** — signed block commands, nonce-based replay
   protection, capability allowlists per agent (Phase 2)
3. **Map trust model** — eBPF map classification by trust level, frozen
   config maps, mutation detection (Phase 3)
4. **State attestation** — periodic integrity reports for loaded eBPF
   programs, pinned maps, and agent binary hash (Phase 4)
