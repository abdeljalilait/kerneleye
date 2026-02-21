# KernelEye Remediation System

Phase-based implementation of threat blocking: IPSet → XDP → ML

## Phase 1: IPSet (Current) - PRODUCTION READY ✅

IPTables + IPSet blocking - works everywhere, survives reboots.

### Features
- ✅ **Universal compatibility** - Works on all Linux systems
- ✅ **IPv4 + IPv6** - Full dual-stack support
- ✅ **Docker support** - Integrates with DOCKER-USER chain
- ✅ **Persistence** - Survives reboots via state file
- ✅ **Auto-blocking** - Configurable threat-based blocking
- ✅ **Rate limiting** - Connection-level rate limiting
- ✅ **CIDR blocking** - Block entire IP ranges
- ✅ **Escalation** - Repeat offenders get longer blocks
- ✅ **Safelist** - Never block internal networks

### Quick Start

```bash
# 1. Install dependencies
sudo apt-get install ipset iptables

# 2. Build agent with blocking
cd agent
go build -o kerneleye-agent .

# 3. Enable auto-blocking (edit config or env)
export KERNELEYE_AUTO_BLOCK=true
export KERNELEYE_BLOCK_THRESHOLD=80

# 4. Run agent
sudo ./kerneleye-agent
```

### Configuration

```go
// In your agent config
blocking := remediation.AutoBlockerConfig{
    Enabled:              true,           // Enable auto-blocking
    BlockThreshold:       80,             // Score >= 80 triggers block
    BaseBlockDuration:    1 * time.Hour,  // First block: 1 hour
    MaxBlockDuration:     24 * time.Hour, // Cap at 24 hours
    EscalationMultiplier: 2.0,            // 2x duration for repeats
    MaxBlocksPerMinute:   60,             // Rate limit blocks
}
```

### Management CLI

```bash
# Install helper script
sudo cp scripts/kerneleye-ipset.sh /usr/local/bin/kerneleye-ipset
sudo chmod +x /usr/local/bin/kerneleye-ipset

# View stats
sudo kerneleye-ipset stats

# Manual block
sudo kerneleye-ipset block 192.0.2.100 3600

# Unblock
sudo kerneleye-ipset unblock 192.0.2.100

# Check health
sudo kerneleye-ipset health
```

### Systemd Service (Persistence)

```bash
# Install service
sudo cp scripts/kerneleye-ipset.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kerneleye-ipset
sudo systemctl start kerneleye-ipset
```

---

## Phase 2: XDP (Next) - HIGH PERFORMANCE

XDP blocking for 10-100x better performance under DDoS.

### When to Add XDP
- High PPS attacks (>10k packets/sec)
- Bare metal or VMs with XDP support
- Performance-critical deployments

### Integration Strategy

```go
// XDP will be a transparent upgrade
remediator := remediation.NewHybridRemediator(remediation.HybridConfig{
    EnableXDP:     true,
    InterfaceName: "eth0",
})

// Same API, better performance
remediator.Block(ip, duration)  // Tries XDP first, falls back to IPSet
```

### Requirements
- Linux 4.8+ with BTF support
- NIC driver with XDP support (ixgbe, i40e, mlx5, virtio_net, etc.)
- Root/CAP_BPF privileges

### Deployment Checklist
- [ ] Test XDP on target NIC
- [ ] Benchmark: `pktgen-dpdk` or `hping3`
- [ ] Verify fallback to IPSet works
- [ ] Monitor: `bpftool prog list`

---

## Phase 3: ML/AI (Future) - SMART DETECTION

Machine learning for anomaly detection and reduced false positives.

### ML Features
- Behavioral baselines per server
- Anomaly scoring
- Novel attack detection
- False positive learning

### Implementation

```go
// ML will enhance scoring, not replace it
scorer := scoring.NewEnsembleScorer(
    heuristicScorer,     // Current rule-based
    mlAnomalyDetector,   // Isolation Forest
    0.6, 0.4,           // Weights
)

score := scorer.CalculateScore(metrics)
// Combines heuristic + ML scores
```

### Training Pipeline
1. Collect 30 days of normal traffic
2. Train Isolation Forest on features
3. Deploy model to agents
4. Collect feedback (false positives)
5. Retrain monthly

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Traffic Analyzer                      │
│  ┌──────────────┐      ┌──────────────┐                │
│  │   Heuristic   │      │   ML Model   │  (Phase 3)    │
│  │    Scorer     │      │   (Future)   │                │
│  └──────┬───────┘      └──────┬───────┘                │
│         └──────────┬──────────┘                        │
│                    ▼                                    │
│            ┌──────────────┐                            │
│            │   Decision   │  Block?                    │
│            └──────┬───────┘                            │
└───────────────────┼─────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌──────────────┐      ┌──────────────────┐
│  XDP (Fast)  │      │  IPSet (Reliable)│
│   ~50ns      │      │   ~10μs          │
│  Phase 2     │      │   Phase 1 ✅     │
└──────────────┘      └──────────────────┘
```

---

## Testing

```bash
# Test blocking
cd agent/remediation
go test -v ./...

# Integration test
sudo go run test/block_test.go

# Load test (requires hping3)
sudo hping3 -S -p 80 --flood --rand-source localhost
```

## File Structure

```
agent/remediation/
├── ipset_remediator.go    # IPSet implementation ✅
├── auto_blocker.go        # Auto-blocking logic ✅
├── xdp_remediator.go      # XDP implementation (Phase 2)
├── hybrid_remediator.go   # XDP + IPSet combo (Phase 2)
├── analyzer.go            # Threat analysis
├── types.go               # Interfaces
└── README.md              # This file

agent/scripts/
├── kerneleye-ipset.sh     # Management CLI ✅
└── kerneleye-ipset.service # Systemd service ✅
```

## Migration Path

| Phase | Version | What's New | Migration |
|-------|---------|------------|-----------|
| 1.0 | MVP | IPSet blocking | Fresh install |
| 1.1 | + | Auto-blocking | Enable in config |
| 2.0 | + | XDP support | `EnableXDP: true` |
| 3.0 | + | ML detection | Automatic model download |

## Security Considerations

1. **Never block internal IPs** - Safelist enforced
2. **Rate limit blocks** - Prevent block storms
3. **Max block duration** - Cap at 24 hours default
4. **Escalation limits** - Don't grow forever
5. **Audit logging** - All blocks logged
6. **Manual override** - CLI unblock always works

## Performance

| Method | Latency | Throughput | Use Case |
|--------|---------|------------|----------|
| IPSet | ~10μs | 100k PPS | Universal |
| XDP | ~50ns | 10M+ PPS | High PPS |

*PPS = packets per second*
