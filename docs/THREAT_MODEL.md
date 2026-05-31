# KernelEye Threat Model

## Scope

This document models threats against the KernelEye system as a whole:
the agent (eBPF + userspace daemon), the backend server, the dashboard,
and the communication channels between them.

**Out of scope:**
- Physical access to the monitored host
- Kernel vulnerabilities (CVEs in the Linux kernel itself)
- Compromise of the CI/CD pipeline
- Social engineering of operators

## Attacker Profiles

| Profile | Capabilities | Motivation |
|---------|-------------|------------|
| **Remote network attacker** | Can send arbitrary packets to monitored hosts | Evade detection, degrade service |
| **Compromised backend** | Full control of the KernelEye backend server | Issue malicious block commands, exfiltrate telemetry |
| **Compromised agent host** | Root access on the monitored machine | Disable agent, modify eBPF programs, tamper with maps |
| **Network MITM** | Can intercept/modify traffic between agent and backend | Inject block commands, read telemetry, impersonate backend |
| **Malicious insider** | Authenticated dashboard access | Unblock known threat IPs, weaken detection thresholds |

## Threat Matrix

### T1: Backend Impersonation

| Field | Detail |
|-------|--------|
| **Attacker** | Network MITM or DNS hijacker |
| **Attack** | Attacker intercepts agent↔backend gRPC traffic and impersonates the backend |
| **Impact** | Attacker can push fake block/unblock commands, read telemetry |
| **Likelihood** | Medium (without TLS), Low (with TLS) |
| **Mitigation** | mTLS (Phase 1) — agent verifies backend certificate. Command signing (Phase 2) — even if TLS is bypassed, commands must be HMAC-signed. |

### T2: Command Replay Attack

| Field | Detail |
|-------|--------|
| **Attacker** | Network MITM recording gRPC streams |
| **Attack** | Replay a previously valid BLOCK command to re-block an IP after unblock |
| **Impact** | Undesired blocking of legitimate IPs |
| **Likelihood** | Medium (without nonce), Low (with nonce) |
| **Mitigation** | Nonce-based replay protection (Phase 2) — agent rejects nonces ≤ last seen. |

### T3: Malicious Block Command Injection

| Field | Detail |
|-------|--------|
| **Attacker** | Compromised backend or dashboard |
| **Attack** | Issue BLOCK command for legitimate IPs (e.g., infrastructure IPs) |
| **Impact** | Denial of service for legitimate traffic |
| **Likelihood** | Low |
| **Mitigation** | Agent allowlist for backend capabilities. Dashboard auth scoping. Audit log of every command. Whitelist enforcement. |

### T4: eBPF Map Tampering

| Field | Detail |
|-------|--------|
| **Attacker** | Compromised agent host (root) or malicious process |
| **Attack** | Write to pinned BPF maps to add/remove blocklist entries or modify config |
| **Impact** | Bypass blocking, weaken rate limits, disable detection |
| **Likelihood** | Medium (if agent host is compromised) |
| **Mitigation** | Map trust classification (Phase 3) — config maps frozen. Periodic integrity checks. Audit all writes to high-trust maps. |

### T5: Pinned Map Hijack

| Field | Detail |
|-------|--------|
| **Attacker** | Root process on agent host |
| **Attack** | Replace pinned map file at `/sys/fs/bpf/kerneleye/` with a spoofed version |
| **Impact** | Undetectable blocklist manipulation |
| **Likelihood** | Low |
| **Mitigation** | Pinned path monitoring (Phase 3-4). Periodic filesystem checks for unexpected changes. |

### T6: Agent Binary Tampering

| Field | Detail |
|-------|--------|
| **Attacker** | Compromised agent host (root) |
| **Attack** | Replace the agent binary with a modified version that reports false telemetry or ignores commands |
| **Impact** | Complete loss of trust in agent reports |
| **Likelihood** | Medium |
| **Mitigation** | Agent binary hash self-check and reporting (Phase 4). Integrity report alerts on hash mismatch. |

### T7: eBPF Program Replacement

| Field | Detail |
|-------|--------|
| **Attacker** | Root process on agent host |
| **Attack** | Unload KernelEye eBPF programs and load malicious replacements |
| **Impact** | Telemetry corruption, traffic interception |
| **Likelihood** | Low |
| **Mitigation** | Program ID + hash verification in integrity reports (Phase 4). Backend alerts on program count or hash changes. |

### T8: Telemetry Interception

| Field | Detail |
|-------|--------|
| **Attacker** | Network MITM |
| **Attack** | Read gRPC traffic between agent and backend |
| **Impact** | Exposure of source IPs, ports, protocols (metadata only — no payloads) |
| **Likelihood** | Medium (without TLS), Low (with TLS) |
| **Mitigation** | TLS encryption (Phase 1). mTLS adds identity verification. |

### T9: Denial of Service Against Agent

| Field | Detail |
|-------|--------|
| **Attacker** | Remote attacker |
| **Attack** | Flood agent gRPC port, exhaust agent resources |
| **Impact** | Agent loses connectivity to backend, telemetry loss |
| **Likelihood** | Low |
| **Mitigation** | Agent gRPC port not exposed externally (localhost/Traefik proxy). Backend rate limiting. |

### T10: API Key Extraction

| Field | Detail |
|-------|--------|
| **Attacker** | Non-root process on agent host |
| **Attack** | Read `/etc/kerneleye/agent.env` if permissions are weak |
| **Impact** | Attacker can register as a fake agent |
| **Likelihood** | Low (if permissions are correct) |
| **Mitigation** | File permissions (0600). Environment file readable only by root. API key rotation support. |

### T11: Dashboard Session Hijacking

| Field | Detail |
|-------|--------|
| **Attacker** | Network MITM or XSS |
| **Attack** | Steal JWT or refresh cookie |
| **Impact** | Unauthorized dashboard access |
| **Likelihood** | Low (with HTTPS + HttpOnly) |
| **Mitigation** | HTTPS, HttpOnly cookies, short-lived JWTs (24h), refresh token rotation. |

## Residual Risks

These are risks that cannot be fully mitigated within the current architecture:

1. **Compromised agent host with root access**: An attacker with root on the monitored host can disable the agent, modify eBPF programs directly, or tamper with kernel memory. KernelEye can detect some of this (Phase 4) but cannot prevent it.

2. **Kernel-level rootkits**: A kernel rootkit can intercept eBPF helper calls or modify loaded programs. KernelEye cannot detect this without hardware-backed attestation (e.g., TPM).

3. **Compromised backend with signing key**: If the backend is fully compromised and the `CMD_SIGNING_KEY` is extracted, the attacker can sign arbitrary commands. Defense-in-depth: rotate keys, monitor backend integrity separately.

4. **Supply chain attacks**: If the agent binary is replaced before deployment (e.g., compromised package repository), the binary hash self-check only helps detect this *after* deployment.
