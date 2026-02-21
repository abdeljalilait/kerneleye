# Phase 2 Implementation Plan: Auto-Blocking

## Overview
Wire up the IPSet auto-blocking system we just built into the production agent.

---

## Week 1: Agent Integration

### Task 1.1: Update Agent Config
**File**: `agent/config.go`

Add auto-blocking configuration:

```go
type Config struct {
    // ... existing fields ...
    
    // NEW: Auto-blocking
    AutoBlock           bool
    AutoBlockThreshold  int
    BlockDuration       time.Duration
}

func parseConfig() Config {
    // ... existing ...
    
    // NEW: Parse auto-blocking env vars
    cfg.AutoBlock = os.Getenv("KERNELEYE_AUTO_BLOCK") == "true"
    cfg.AutoBlockThreshold = getEnvInt("KERNELEYE_BLOCK_THRESHOLD", 80)
    cfg.BlockDuration = getEnvDuration("KERNELEYE_BLOCK_DURATION", time.Hour)
    
    return cfg
}
```

**Environment Variables**:
```bash
export KERNELEYE_AUTO_BLOCK=true
export KERNELEYE_BLOCK_THRESHOLD=80
export KERNELEYE_BLOCK_DURATION=1h
```

---

### Task 1.2: Wire Up AutoBlocker in Main
**File**: `agent/main.go`

```go
func main() {
    // ... existing setup ...
    
    // NEW: Initialize IPSet remediator (always, for blocking)
    ipsetRemediator := remediation.NewIPSetRemediator()
    if err := ipsetRemediator.Setup(); err != nil {
        log.Printf("⚠️  IPSet setup failed: %v", err)
    } else {
        defer ipsetRemediator.Teardown()
    }
    
    // NEW: Initialize auto-blocker if enabled
    var autoBlocker *remediation.AutoBlocker
    if cfg.AutoBlock && ipsetRemediator != nil {
        scorer := scoring.NewThreatScorer()
        
        blockConfig := remediation.DefaultAutoBlockerConfig()
        blockConfig.Enabled = true
        blockConfig.BlockThreshold = cfg.AutoBlockThreshold
        blockConfig.BaseBlockDuration = cfg.BlockDuration
        
        var err error
        autoBlocker, err = remediation.NewAutoBlocker(blockConfig, scorer, ipsetRemediator)
        if err != nil {
            log.Printf("⚠️  Auto-blocker init failed: %v", err)
        }
    }
    
    // ... rest of setup ...
}
```

---

### Task 1.3: Integrate with Aggregator
**File**: `agent/aggregator.go`

```go
type Aggregator struct {
    // ... existing fields ...
    autoBlocker *remediation.AutoBlocker  // NEW
}

func (agg *Aggregator) ProcessEvent(e Event) {
    // ... existing processing ...
    
    // NEW: Calculate threat score and auto-block
    if agg.autoBlocker != nil {
        metrics := scoring.IPMetrics{
            SYNCount:         int(e.SynCount),
            ACKCount:         int(e.AckCount),
            FailedHandshakes: int(e.FailedHandshakes),
            UniquePorts:      int(e.UniquePortsCount),
            WindowStart:      e.FirstSeen,
            WindowEnd:        e.LastSeen,
        }
        
        score := agg.scorer.CalculateScore(metrics)
        ipStr := intToIP(e.Saddr).String()
        
        if err := agg.autoBlocker.ProcessScore(ipStr, score); err != nil {
            log.Printf("❌ Auto-block failed: %v", err)
        }
    }
}
```

---

### Task 1.4: Report Blocks to Backend
**File**: `agent/aggregator.go`

Add gRPC reporting:

```go
func (agg *Aggregator) reportBlockToBackend(ip string, duration time.Duration, score int, reasons []string) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    _, err := agg.grpcClient.ReportBlock(ctx, &pb.BlockReport{
        ApiKey:      agg.apiKey,
        Ip:          ip,
        DurationSec: int64(duration.Seconds()),
        Score:       int32(score),
        Reasons:     reasons,
        Timestamp:   timestamppb.Now(),
    })
    
    if err != nil {
        log.Printf("⚠️  Failed to report block: %v", err)
    }
}
```

---

## Week 2: Backend API

### Task 2.1: Database Schema
**File**: `backend/migrations/003_blocks.sql`

```sql
-- Blocks table
CREATE TABLE blocks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    score INTEGER NOT NULL,
    reasons TEXT[] NOT NULL,
    duration INTERVAL NOT NULL,
    blocked_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    unblocked_at TIMESTAMPTZ,
    unblocked_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_blocks_server ON blocks(server_id);
CREATE INDEX idx_blocks_active ON blocks(server_id, is_active) WHERE is_active = TRUE;
CREATE INDEX idx_blocks_ip ON blocks(ip_address);
CREATE INDEX idx_blocks_expires ON blocks(expires_at);
```

---

### Task 2.2: gRPC Handler
**File**: `backend/internal/api/grpc_handlers.go`

```go
func (h *GrpcIngestHandler) ReportBlock(ctx context.Context, req *pb.BlockReport) (*pb.BlockResponse, error) {
    // Authenticate
    server, err := h.queries.GetServerByAPIKey(ctx, database.ToPgText(req.ApiKey))
    if err != nil {
        return nil, status.Errorf(codes.Unauthenticated, "invalid API key")
    }
    
    // Store block in DB
    block, err := h.queries.CreateBlock(ctx, database.CreateBlockParams{
        ServerID:    server.ID,
        IpAddress:   database.ToInetAddr(req.Ip),
        Score:       req.Score,
        Reasons:     req.Reasons,
        Duration:    pgtype.Interval{Microseconds: req.DurationSec * 1000000, Valid: true},
        ExpiresAt:   database.ToPgTimestamptz(time.Now().Add(time.Duration(req.DurationSec) * time.Second)),
    })
    
    if err != nil {
        return nil, status.Errorf(codes.Internal, "failed to record block: %v", err)
    }
    
    // Broadcast to other agents of same user
    h.hub.BroadcastBlock(server.UserID, BlockEvent{
        IP:       req.Ip,
        Duration: time.Duration(req.DurationSec) * time.Second,
        Reason:   strings.Join(req.Reasons, ", "),
    })
    
    // WebSocket push to dashboard
    h.hub.BroadcastToUser(server.UserID, "new_block", map[string]interface{}{
        "ip":       req.Ip,
        "score":    req.Score,
        "reasons":  req.Reasons,
        "server":   server.Hostname,
        "blocked_at": time.Now(),
    })
    
    return &pb.BlockResponse{Success: true, BlockId: block.ID.String()}, nil
}
```

---

### Task 2.3: REST API Endpoints
**File**: `backend/internal/api/handlers.go`

```go
// GET /api/blocks - List blocked IPs
func HandleListBlocks(queries *database.Queries) fiber.Handler {
    return func(c *fiber.Ctx) error {
        user := c.Locals("user").(User)
        
        blocks, err := queries.ListBlocks(c.Context(), user.ID)
        if err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "failed to fetch blocks")
        }
        
        return c.JSON(blocks)
    }
}

// DELETE /api/blocks/:ip - Unblock IP
func HandleUnblock(queries *database.Queries, hub *Hub) fiber.Handler {
    return func(c *fiber.Ctx) error {
        user := c.Locals("user").(User)
        ip := c.Params("ip")
        
        // Mark as unblocked in DB
        err := queries.UnblockIP(c.Context(), database.UnblockIPParams{
            UserID: user.ID,
            IpAddress: database.ToInet(ip),
            UnblockedAt: database.ToPgTimestamptz(time.Now()),
        })
        if err != nil {
            return fiber.NewError(fiber.StatusInternalServerError, "failed to unblock")
        }
        
        // Send unblock command to agents
        hub.BroadcastUnblock(user.ID, ip)
        
        return c.JSON(fiber.Map{"success": true})
    }
}
```

---

## Week 3: Dashboard UI

### Task 3.1: Blocked IPs Page
**File**: `dashboard/src/pages/BlockedIPs.tsx`

```tsx
import { useQuery, useMutation } from '@tanstack/react-query';
import { Table, Button, Tag, Tooltip } from 'antd';
import { UnlockOutlined } from '@ant-design/icons';

export function BlockedIPs() {
  const { data: blocks, refetch } = useQuery({
    queryKey: ['blocks'],
    queryFn: fetchBlocks,
  });

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => api.unblockIP(ip),
    onSuccess: () => refetch(),
  });

  const columns = [
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip',
    },
    {
      title: 'Threat Score',
      dataIndex: 'score',
      key: 'score',
      render: (score: number) => (
        <Tag color={score >= 80 ? 'red' : score >= 60 ? 'orange' : 'yellow'}>
          {score}
        </Tag>
      ),
    },
    {
      title: 'Reasons',
      dataIndex: 'reasons',
      key: 'reasons',
      render: (reasons: string[]) => (
        <Tooltip title={reasons.join('\n')}>
          {reasons.slice(0, 2).join(', ')}
          {reasons.length > 2 && '...'}
        </Tooltip>
      ),
    },
    {
      title: 'Blocked At',
      dataIndex: 'blocked_at',
      key: 'blocked_at',
      render: (date: string) => new Date(date).toLocaleString(),
    },
    {
      title: 'Expires',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (date: string) => {
        const hours = Math.ceil((new Date(date).getTime() - Date.now()) / (1000 * 60 * 60));
        return hours > 0 ? `${hours}h` : 'Expired';
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Button
          icon={<UnlockOutlined />}
          onClick={() => unblockMutation.mutate(record.ip_address)}
          loading={unblockMutation.isPending}
        >
          Unblock
        </Button>
      ),
    },
  ];

  return (
    <div>
      <h1>Blocked IPs</h1>
      <Table
        dataSource={blocks}
        columns={columns}
        rowKey="id"
      />
    </div>
  );
}
```

---

### Task 3.2: Real-time Updates
**File**: `dashboard/src/context/WebSocketContext.tsx`

```typescript
// Add handler for block events
socket.on('new_block', (data) => {
  notification.warning({
    message: 'IP Blocked',
    description: `${data.ip} blocked on ${data.server} (score: ${data.score})`,
  });
  
  // Invalidate blocks query to refresh list
  queryClient.invalidateQueries({ queryKey: ['blocks'] });
});
```

---

## Testing Checklist

### Agent Tests
```bash
# Test auto-blocking
cd agent
sudo KERNELEYE_AUTO_BLOCK=true ./kerneleye-agent

# Simulate attack in another terminal
hping3 -S -p 80 --flood <target_ip>

# Check blocks
sudo kerneleye-ipset stats
sudo kerneleye-ipset list
```

### Backend Tests
```bash
# Test block report API
curl -X POST http://localhost:8080/api/blocks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ip": "192.0.2.1", "duration": 3600}'

# List blocks
curl http://localhost:8080/api/blocks \
  -H "Authorization: Bearer $TOKEN"
```

### Dashboard Tests
- [ ] Blocked IPs page loads
- [ ] New blocks appear in real-time
- [ ] Unblock button works
- [ ] Block details show correctly

---

## Deployment

### Install Helper Script
```bash
sudo cp agent/scripts/kerneleye-ipset.sh /usr/local/bin/kerneleye-ipset
sudo chmod +x /usr/local/bin/kerneleye-ipset

sudo cp agent/scripts/kerneleye-ipset.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kerneleye-ipset
```

### Environment Variables
```bash
# Required
export KERNELEYE_AUTO_BLOCK=true

# Optional (defaults shown)
export KERNELEYE_BLOCK_THRESHOLD=80
export KERNELEYE_BLOCK_DURATION=1h
export KERNELEYE_MAX_BLOCKS_PER_MINUTE=60
```

---

## Summary

| Week | Task | Deliverable |
|------|------|-------------|
| 1 | Agent integration | Auto-blocking works locally |
| 2 | Backend API | Blocks stored, broadcast to agents |
| 3 | Dashboard UI | Users can view/unblock IPs |

**Result**: Complete auto-blocking pipeline from detection → blocking → visibility → manual override.
