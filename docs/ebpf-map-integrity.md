# eBPF Map Integrity & Tamper-Proofing

How KernelEye keeps eBPF maps untampered and immutable.

---

## Layered Defense Architecture

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Agent Self-Attestation (SHA-256 binary hash)   │
├─────────────────────────────────────────────────────────┤
│ Layer 6: Write Audit Trail (JSON log)                   │
├─────────────────────────────────────────────────────────┤
│ Layer 5: Pinned Map Path Monitoring (/sys/fs/bpf/...)   │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Periodic Integrity Verification (every 60s)    │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Kernel-Enforced Immutability (BPF_MAP_FREEZE)  │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Startup Identity Snapshots (MapID + SHA-256)   │
├─────────────────────────────────────────────────────────┤
│ Layer 1: Map Classification (TrustLevel system)         │
└─────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Map Classification

**File:** `agent/remediation/types.go:131-189`

Every BPF map is assigned a TrustLevel that determines audit, freeze, and verification behavior.

### Trust Levels

| Level | Value | Meaning | Audit Writes | Frozen |
|-------|-------|---------|:---:|:---:|
| `TrustLevelLow` | 0 | Telemetry/debug — no security impact | No | No |
| `TrustLevelMedium` | 1 | Event/stats — tampering degrades observability only | No | No |
| `TrustLevelHigh` | 2 | Blocking/policy — tampering allows/denies traffic | **Yes** | No |
| `TrustLevelVeryHigh` | 3 | Configuration — must be immutable after init | **Yes** | **Yes** |

### Map Classification Table

| Map Name | TrustLevel | Frozen | AuditWrites |
|----------|:---:|:---:|:---:|
| `events` | Medium | No | No |
| `rate_limiter` | Low | No | No |
| `global_rate_limiter` | Low | No | No |
| `syn_tracker` | Low | No | No |
| `debug_counters` | Low | No | No |
| `ip_stats` | Medium | No | No |
| `xdp_blocklist` | **High** | No | **Yes** |
| `xdp_blocklist_v6` | **High** | No | **Yes** |
| `xdp_cidr_blocklist` | **High** | No | **Yes** |
| `xdp_rate_limit` | **High** | No | **Yes** |
| `xdp_stats` | Medium | No | No |
| `xdp_block_events` | Medium | No | No |
| `xdp_rate_config` | **VeryHigh** | **Yes** | **Yes** |

### Go Struct

```go
type MapClassification struct {
    Name        string
    TrustLevel  MapTrustLevel
    Frozen      bool  // read-only after init
    AuditWrites bool  // all writes logged
}
```

---

## Layer 2 — Startup Identity Snapshots

**File:** `agent/remediation/xdp_integrity.go:21-76`

Immediately after XDP programs load (`LoadAndAssign` succeeds), `captureMapSnapshots()` records the identity of every map.

### Captured for each map

| Field | Description |
|-------|-------------|
| `MapID` | Kernel-assigned BPF map ID (unique per map instance) |
| `ContentHash` | SHA-256 of all key/value entries (High+ only) |
| `Frozen` | Whether `BPF_MAP_FREEZE` was applied |
| `PinnedPath` | Expected path under `/sys/fs/bpf/kerneleye/` |
| `EntryCount` | Number of entries at capture time |
| `CapturedAt` | Timestamp of capture |

### Snapshot struct

```go
type MapStateSnapshot struct {
    Name        string
    MapID       ebpf.MapID
    PinnedPath  string
    Frozen      bool
    TrustLevel  MapTrustLevel
    ContentHash string   // SHA-256 of all entries (blank for Low)
    EntryCount  int
    CapturedAt  time.Time
}
```

### Content hash (deterministic)

```go
func hashMapContents(m *ebpf.Map) string {
    // Collect all key-value pairs
    // Sort by key for determinism
    // Feed sequentially into SHA-256
}
```

---

## Layer 3 — Kernel-Enforced Immutability (BPF_MAP_FREEZE)

**File:** `agent/remediation/xdp_rate.go:37-42`

`xdp_rate_config` (TrustLevel VeryHigh) is permanently frozen after the first write.

### Behavior

```go
// First write succeeds
r.objs.XdpRateConfig.Update(key, value)

// Freeze — irreversible
r.objs.XdpRateConfig.Freeze()
// Logs: "🔒 Frozen xdp_rate_config — rate limit config is now immutable"

// All subsequent writes fail at kernel level
r.objs.XdpRateConfig.Update(key, newValue)
// → EPERM (Operation not permitted)
// Not even root can override this — only a full reload (program restart) resets it
```

### Userspace frozen gate

**File:** `agent/remediation/xdp_block.go:21-27`

Before any write, a userspace check blocks the attempt early:

```go
if cls, ok := MapClassificationByName("xdp_blocklist"); ok && cls.Frozen {
    return fmt.Errorf("map xdp_blocklist is frozen (trust level: %s) — writes are not allowed", cls.TrustLevel)
}
```

---

## Layer 4 — Periodic Integrity Verification

**File:** `agent/map_integrity.go:15-69`, `agent/remediation/xdp_integrity.go:122-168`

Every 60 seconds, all High+ maps are re-verified against their startup snapshots.

### Schedule

```go
// In main.go:357-380
time.Sleep(15 * time.Second)   // First check 15s after startup
ticker := time.NewTicker(60 * time.Second)  // Then every 60s
```

### Checks performed

| Check | How | Detects |
|-------|-----|---------|
| **Map ID unchanged** | Compare current `info.ID()` vs snapshot `MapID` | Map was replaced (unpinned then re-pinned with different map) |
| **Frozen status matches** | `info.Frozen()` vs classification | Freeze not applied or was somehow removed |
| **Content hash matches** | Recompute SHA-256 of all entries, compare vs snapshot | Unauthorized insert/delete/update |
| **Pinned file accessible** | `os.Stat(pinnedPath)` | Map was unpinned or path removed |

### Tampering detection logic

```go
// xdp_integrity.go:122-168
func (r *XDPRemediator) verifyMapSnapshot(name string, snap *MapStateSnapshot) []string {
    m, err := ebpf.LoadPinnedMap(filepath.Join(r.pinPath, name), &ebpf.LoadPinOptions{ReadOnly: true})
    if err != nil {
        return []string{fmt.Sprintf("map %s: pinned file not accessible — possible tampering", name)}
    }

    info, _ := m.Info()
    
    if info.ID() != snap.MapID {
        warnings = append(warnings, fmt.Sprintf("map %s: ID changed (%d→%d) — map was replaced", name, snap.MapID, info.ID()))
    }
    
    if snap.Frozen && !info.Frozen() {
        warnings = append(warnings, fmt.Sprintf("map %s: classified as frozen but BPF_MAP_FREEZE not applied", name))
    }
    
    newHash := hashMapContents(m)
    if newHash != snap.ContentHash {
        warnings = append(warnings, fmt.Sprintf("map %s: content hash mismatch — unauthorized modification detected", name))
    }
    
    return warnings
}
```

---

## Layer 5 — Pinned Map Path Monitoring

**File:** `agent/map_integrity.go:50-55`, `agent/remediation/xdp_integrity.go:125-133`

All High+ maps are pinned to `/sys/fs/bpf/kerneleye/`. The integrity verification checks that each pinned file still exists and is accessible.

```go
// map_integrity.go:50-55
pinnedPath := filepath.Join(r.pinPath, snap.Name)
if _, err := os.Stat(pinnedPath); os.IsNotExist(err) {
    warnings = append(warnings, fmt.Sprintf("map %s: pinned path %s not found", name, pinnedPath))
}
```

The pin path is also reported to the backend so it can be cross-referenced:

```go
// In buildIntegrityReport()
lm.PinnedPath = snap.PinnedPath
lm.PinnedPathChanged = !pinnedFileAccessible
```

---

## Layer 6 — Write Audit Trail

**File:** `agent/audit.go:64-74`, `agent/remediation/xdp_helpers.go:170-182`

Every write to a High+ map creates a structured JSON audit entry.

### Audit log path

```
/var/log/kerneleye-audit.log
```

Override with: `KERNELEYE_AUDIT_LOG`

### Audit entry format

```json
{
  "timestamp": "2026-06-01T20:30:00Z",
  "map": "xdp_blocklist",
  "action": "insert",
  "key": "10.0.0.5",
  "source": "block_command",
  "signature_valid": true,
  "error": ""
}
```

### What gets audited

| Action | Source | Map |
|--------|--------|-----|
| Block IP (IPv4) | `block_command` | `xdp_blocklist` |
| Block IP (IPv6) | `block_command` | `xdp_blocklist_v6` |
| Unblock IP (IPv4) | `block_command` | `xdp_blocklist` |
| Unblock IP (IPv6) | `block_command` | `xdp_blocklist_v6` |
| Unblock CIDR | `block_command` | `xdp_cidr_blocklist` |
| Set rate limit | `local_setup` | `xdp_rate_config` |

### Backend command audit (separate file)

`agent/audit.go` also logs backend-originated commands with HMAC verification status:

```go
AuditLogCommandAccepted(ip, action, duration)   // Command passed HMAC verification
AuditLogCommandRejected(ip, action, duration)   // Command failed HMAC — possible tampering
AuditLogLocalBlock(ip, blockType, duration)     // Auto-blocker action
AuditLogLocalUnblock(ip, blockType)              // Local unblock
```

---

## Layer 7 — Agent Self-Attestation

**File:** `agent/map_integrity.go:83-95`

The agent computes SHA-256 of its own binary at startup and includes it in every integrity report.

```go
func computeAgentBinaryHash() string {
    exe, _ := os.Executable()
    data, _ := os.ReadFile(exe)
    hash := sha256.Sum256(data)
    return hex.EncodeToString(hash[:])
}
```

The backend receives this hash via gRPC `ReportIntegrity` and can detect if the agent binary was replaced with a tampered version (different SHA-256).

---

## Integrity Report Flow

```
  [Agent]                              [Backend]
     │                                     │
     │  Startup: captureMapSnapshots()     │
     │  computeAgentBinaryHash()            │
     │                                     │
     │  ═══ Every 60s ═══                 │
     │  verifyMapIntegrity()                │
     │    ├─ verifySnapshot() x7 maps      │
     │    ├─ detect tampering              │
     │    └─ collect findings              │
     │                                     │
     │  buildIntegrityReport()              │
     │    ├─ AgentBinaryHash               │
     │    ├─ LoadedMaps[] (per map):       │
     │    │    ├─ MapId                    │
     │    │    ├─ ContentHashMatch          │
     │    │    ├─ FrozenStatusMatch         │
     │    │    ├─ PinnedPathChanged         │
     │    │    └─ ConfigHashChanged         │
     │    └─ Status (OK/WARNING)           │
     │                                     │
     │  ReportIntegrity() ──────gRPC──────►│
     │                                     │  Store in DB
     │                                     │  Alert on WARNING
```

---

## Coverage

### Currently covered (XDP remediation maps)

| Map | TrustLevel | Integrity Check | Audit | Frozen |
|-----|:---:|:---:|:---:|:---:|
| `xdp_blocklist` | High | Yes | Yes | No |
| `xdp_blocklist_v6` | High | Yes | Yes | No |
| `xdp_cidr_blocklist` | High | Yes | Yes | No |
| `xdp_rate_limit` | High | Yes | Yes | No |
| `xdp_rate_config` | VeryHigh | Yes | Yes | **Yes** |
| `xdp_stats` | Medium | No | No | No |
| `xdp_block_events` | Medium | No | No | No |

### Not yet covered (traffic probe maps)

These maps are ephemeral (recreated on each agent start), not pinned, and not classified High+:

- `events` (ring buffer)
- `ip_byte_counters`
- `ip_byte_counters_v6`
- `ip_port_bytes`
- `icmp_counters`
- `tcp_syn_tracker` / `tcp_syn_tracker_v6`
- `rate_limiter` / `global_rate_limiter`
- `debug_counters`

To extend integrity coverage to these maps, they would need:
1. Classification entries in `ClassifyMaps()`
2. Pinning via `opts.Maps.PinPath`
3. Snapshot capture in `captureMapSnapshots()`
4. Periodic verification in the 60s loop
