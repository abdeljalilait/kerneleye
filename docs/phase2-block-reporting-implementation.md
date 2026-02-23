# Phase 2: Block Reporting Implementation Guide

## Overview
Complete implementation for:
1. Agent reports blocked IPs to backend via gRPC
2. Backend stores blocks with service & GeoIP details
3. Dashboard shows blocked IPs with filtering and management
4. Dynamic agent configuration during API key generation

---

## Files Created

### Backend

| File | Purpose |
|------|---------|
| `backend/migrations/003_blocks.sql` | Database schema for blocks with GeoIP |
| `proto/kerneleye/v1/blocks.proto` | gRPC protocol for block reporting |
| `backend/internal/api/block_handlers.go` | gRPC handlers for block service |
| `backend/internal/api/block_rest.go` | REST API for dashboard |
| `backend/internal/api/apikey_builder.go` | Dynamic API key generation with options |
| `backend/internal/database/queries/blocks.sql` | SQL queries for blocks |

### Dashboard

| File | Purpose |
|------|---------|
| `dashboard/src/components/AgentConfigurator.tsx` | Dynamic agent configuration UI |
| `dashboard/src/pages/BlockedIPs.tsx` | Blocked IPs management page |

---

## Database Schema

### blocks table
```sql
- IP address & version (IPv4/IPv6)
- Threat score & level
- Service targeted (SSH, HTTP, etc.) + port
- GeoIP: country, city, ASN, coordinates
- Flags: is_vpn, is_tor, is_datacenter
- Timing: blocked_at, expires_at, duration
- Status: is_active, unblocked tracking
```

---

## API Endpoints

### gRPC (Agent → Backend)

```protobuf
service BlockService {
  rpc ReportBlock(BlockReportRequest) returns (BlockReportResponse);
  rpc GetBlockStatus(BlockStatusRequest) returns (BlockStatusResponse);
  rpc StreamBlockCommands(StreamBlockRequest) returns (stream BlockCommand);
}
```

### REST (Dashboard)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/deployment-modes` | GET | Available agent modes |
| `/api/agent-features` | GET | Configurable features with explanations |
| `/api/servers` | POST | Generate API key with config |
| `/api/blocks` | GET | List blocks with filters |
| `/api/blocks/stats` | GET | Dashboard statistics |
| `/api/blocks/:ip/unblock` | POST | Manually unblock IP |

---

## Dynamic Agent Configuration

### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `monitor` | Alerts only, no blocking | Testing, compliance |
| `block_ipset` | IPSet/iptables blocking | Universal compatibility |
| `block_xdp` | XDP kernel blocking | High performance |
| `block_hybrid` | XDP + IPSet | Recommended (best of both) |

### Configurable Features

| Feature | Flag | Description |
|---------|------|-------------|
| Auto-blocking | `--auto-block` | Auto-block high threat IPs |
| Block threshold | `--block-threshold` | Score to trigger block (40-95) |
| Block duration | `--block-duration` | 1h, 4h, 24h |
| Rate limiting | `--rate-limit` | Throttle instead of block |
| GeoIP | `--geoip` | Add location data |
| Bandwidth | `--bandwidth` | Track per-IP bandwidth |

---

## User Flow

### 1. Generate API Key with Configuration

```
User clicks "Add Server"
  ↓
Enter server name
  ↓
Choose protection mode (Monitor/IPSet/XDP/Hybrid)
  ↓
Toggle features (auto-block, geoip, etc.)
  ↓
Set threshold (40=aggressive, 80=conservative)
  ↓
Generate API key + install command
  ↓
Copy Docker/systemd/binary command
```

### 2. Block Reporting Flow

```
Agent detects threat (score >= threshold)
  ↓
Block IP via IPSet/XDP
  ↓
Report to backend via gRPC
  ↓
Backend stores with GeoIP enrichment
  ↓
Broadcast to user's other agents
  ↓
WebSocket push to dashboard
  ↓
User sees real-time block in UI
```

### 3. Dashboard Management

```
User views "Blocked IPs" page
  ↓
See: IP, threat score, service targeted, country, server
  ↓
Filter by: service, country, server, status
  ↓
Click "Details" for full info
  ↓
Click "Unblock" to remove block
  ↓
Unblock command sent to all agents
```

---

## Installation Commands Generated

### Docker
```bash
docker run -d \
  --name kerneleye-agent \
  --privileged \
  --net=host \
  -e KERNELEYE_API_KEY=ke_xxx \
  -e KERNELEYE_SERVER=api.kerneleye.net \
  -e KERNELEYE_AUTO_BLOCK=true \
  -e KERNELEYE_BLOCK_THRESHOLD=80 \
  kerneleye/agent:latest
```

### Systemd
```bash
sudo curl -o /usr/local/bin/kerneleye-agent \
  https://releases.kerneleye.net/agent/latest/kerneleye-agent
sudo chmod +x /usr/local/bin/kerneleye-agent

# Create environment file
cat << 'EOF' | sudo tee /etc/kerneleye/agent.env
KERNELEYE_API_KEY=ke_xxx
KERNELEYE_SERVER=api.kerneleye.net
KERNELEYE_AUTO_BLOCK=true
KERNELEYE_BLOCK_THRESHOLD=80
EOF

sudo kerneleye-agent install
sudo systemctl enable --now kerneleye-agent
```

---

## UI Components

### Agent Configurator
- Step 1: Server name
- Step 2: Protection mode selection (with performance/compatibility info)
- Step 3: Feature toggles with detailed explanations
- Step 4: Generated command with tabs (Docker/Systemd/Binary)

### Blocked IPs Page
- Statistics cards (active blocks, today, countries, services)
- Filter bar (server, service, country, status, date range)
- Table with: IP, threat, service, location, server, time, status
- Expandable rows showing threat reasons
- Detail drawer with GeoIP map and full timeline
- Unblock button with confirmation

---

## Next Steps to Deploy

1. **Generate SQLC code**
   ```bash
   cd backend
   sqlc generate
   ```

2. **Run migration**
   ```bash
   psql -d kerneleye -f migrations/003_blocks.sql
   ```

3. **Generate protobuf**
   ```bash
   make gen-proto
   ```

4. **Build & deploy**
   ```bash
   make build
   docker-compose up -d
   ```

---

## Testing Checklist

- [ ] Generate API key with different modes
- [ ] Verify command includes correct env vars
- [ ] Agent reports block to backend
- [ ] GeoIP enrichment works
- [ ] Dashboard shows new block in real-time
- [ ] Filters work (service, country, server)
- [ ] Unblock removes from all agents
- [ ] Statistics update correctly

---

## Key Features Delivered

✅ Dynamic agent configuration (4 modes, 7+ features)  
✅ Service detection (SSH, HTTP, HTTPS, DBs, etc.)  
✅ GeoIP enrichment (country, city, ASN)  
✅ Per-server view and filtering  
✅ Real-time block notifications  
✅ Cross-server block sync  
✅ Manual unblock with audit trail  
✅ Detailed threat explanations  
✅ Statistics dashboard  
