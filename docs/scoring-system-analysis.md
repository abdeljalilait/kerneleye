# KernelEye Scoring System Analysis

**Date**: 2026-02-20  
**Status**: Phase 1 (IPSet) - Production Ready  
**Next**: Phase 2 (XDP), Phase 3 (ML/AI)

---

## Executive Summary

KernelEye's scoring system is **intermediate-level** - better than basic rule-based tools like Fail2ban, but not yet at advanced ML-powered levels like CrowdSec's behavioral analysis.

| Aspect | Rating | Status |
|--------|--------|--------|
| Sophistication | ⭐⭐⭐☆☆ | Good rules, no ML yet |
| False Positive Control | ⭐⭐⭐⭐☆ | Confidence + whitelisting |
| Explainability | ⭐⭐⭐⭐⭐ | Clear reasons per score |
| Adaptability | ⭐⭐☆☆☆ | Fixed thresholds |
| Production Ready | ⭐⭐⭐⭐☆ | Solid for most use cases |

**Classification**: "Smart Heuristic" - well-engineered rule-based scoring.

---

## What's Advanced (Better than Basic Tools)

| Feature | KernelEye | Basic Tools (Fail2ban) |
|---------|-----------|------------------------|
| **Rate-normalized scoring** | ✅ Yes (SYN/sec, ports/sec) | ❌ Raw counts only |
| **Multi-factor analysis** | ✅ 4 components | ❌ 1-2 factors |
| **Confidence weighting** | ✅ Time-based (0-1) | ❌ Binary |
| **Score decay/memory** | ✅ 70/30 blend | ❌ No memory |
| **Service whitelisting** | ✅ HTTP/HTTPS/SSH/DNS | ❌ Manual only |
| **Adaptive thresholds** | ✅ Dynamic | ❌ Fixed |
| **RST storm detection** | ✅ Yes | ❌ Rare |
| **Hysteresis** | ✅ Adjusts for confidence | ❌ No |

---

## What's Missing (vs. Advanced Systems)

| Feature | KernelEye | Advanced (CrowdSec/Suricata) |
|---------|-----------|------------------------------|
| **Machine Learning** | ❌ No | ✅ Behavioral baselines |
| **Deep Protocol Analysis** | ⚠️ Basic TCP flags | ✅ DPI |
| **GeoIP Correlation** | ⚠️ DB field only | ✅ Geo anomaly detection |
| **Threat Intel Feeds** | ❌ No | ✅ Known bad IPs |
| **Peer Consensus** | ❌ No | ✅ Community blocklists |
| **Temporal Patterns** | ⚠️ Simple | ✅ Time-series analysis |
| **Connection State Machine** | ⚠️ Basic | ✅ Full TCP state tracking |

---

## Scoring Algorithm

### Formula
```
Raw Score = (SYN_Component × 10) + 
            (Port_Component × 2) + 
            (Failed_Component × 15) + 
            Burst_Component

Adjustments:
- Service whitelist: ×0.8 if >50% traffic to HTTP/HTTPS/SSH/DNS
- Confidence penalty: ×confidence (0.1-1.0)
- Decay blend: (previous × 0.7) + (current × 0.3)

Final Score = min(100, adjusted)
```

### Score Levels

| Score | Level | Action |
|-------|-------|--------|
| 0-29 | Normal | Monitor |
| 30-59 | Suspicious | Alert only |
| 60-79 | Malicious | Alert + Log |
| 80-100 | Critical | Auto-block eligible |

### Component Details

| Component | Detection | Scaling |
|-----------|-----------|---------|
| **SYN** | SYN flood, half-open | Logarithmic |
| **Port Scan** | Horizontal scanning | Square root |
| **Failed Handshake** | Brute force | Linear with ratio |
| **Burst** | Connection floods | Log10 |

---

## Key Strengths

### 1. False Positive Reduction
```go
// SYN/ACK ratio check
if synRatio < 0.65 && metrics.FailedHandshakes < 3 {
    return 0 // Likely legitimate
}

// Service whitelisting
if serviceHits >= metrics.UniquePorts/2 {
    rawScore *= 0.8 // 20% reduction
}
```

### 2. Confidence-Based Scoring
Short observation windows = lower confidence = higher effective thresholds.

### 3. Rate Normalization
Detects attacks regardless of window size:
```go
synRate := float64(metrics.SYNCount) / windowDuration.Seconds()
```

---

## Known Weaknesses

### 1. No Baseline Learning
```go
// Current: Fixed
NormalSYNRate: 1.0  // Hardcoded

// Advanced: Learned
NormalSYNRate: learnFrom30Days(metrics)  // Per-server
```

### 2. No Protocol-Specific Rules
Only TCP flags, no HTTP/DNS/SMTP analysis.

### 3. No Peer Correlation
Each IP scored independently. Missing coordinated attack detection.

### 4. Limited Temporal Analysis
Only has `PreviousScore`. Missing:
- Day-of-week patterns
- Hour-of-day baselines
- Trend detection

---

## Industry Comparison

```
KernelEye (Current)
├─ Rule-based:     ████████░░ 80%
├─ Statistical:    █████░░░░░ 50%
├─ Temporal:       █████░░░░░ 50%
├─ Behavioral:     ██░░░░░░░░ 20%
└─ ML/AI:          ░░░░░░░░░░ 0%

CrowdSec (Reference)
├─ Rule-based:     ██████████ 100%
├─ Statistical:    ██████████ 100%
├─ Temporal:       █████████░ 90%
├─ Behavioral:     ████████░░ 80%
└─ ML/AI:          █████░░░░░ 50%
```

---

## Roadmap

### Phase 1 (Current) ✅ COMPLETE
- Deterministic heuristic scoring
- Multi-factor analysis
- Confidence weighting

### Phase 2 (Next) - Statistical Enhancements
```go
// Per-server baselines
type Baseline struct {
    AvgSYNRate     float64
    StdDevSYNRate  float64
    PeakHour       int
    LearningDays   int
}

// Z-score detection
if (synRate - baseline.Avg) / baseline.StdDev > 3 {
    score += 30  // 3-sigma anomaly
}
```

### Phase 3 - ML/AI
```go
// Isolation Forest
features := []float64{
    synRate / baseline.Avg,
    float64(uniquePorts) / baseline.AvgPorts,
    failedRate,
}
anomalyScore := isolationForest.Score(features)
```

---

## Configuration Reference

```go
// Current defaults
threatScorer := &ThreatScorer{
    SYNRateWeight:         10.0,
    UniquePortsWeight:     2.0,
    FailedHandshakeWeight: 15.0,
    
    NormalSYNRate:       1.0,  // SYN/sec
    SuspiciousSYNRate:   5.0,  // SYN/sec
    PortScanThreshold:   20,   // unique ports
    FailedHandshakeRate: 2.0,  // failed/sec
    
    SuspiciousThreshold: 30,
    MaliciousThreshold:  60,
    AutoBlockThreshold:  80,
    
    MinWindowDuration: 10 * time.Second,
}
```

---

## Related Files

- `agent/internal/scoring/scorer.go` - Agent scoring implementation
- `backend/internal/scoring/scorer.go` - Backend scoring
- `agent/remediation/auto_blocker.go` - Auto-blocking based on scores

---

## Notes

- Last reviewed: 2026-02-20
- Scoring is deterministic (same input = same output)
- No randomness or ML - fully explainable
- Perfect for compliance/audit requirements
- ML upgrade in Phase 3 will add behavioral layer, not replace heuristics
