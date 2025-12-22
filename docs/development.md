# Development Quick Start

## Prerequisites

- Docker & Docker Compose
- Go 1.21+ (for agent development)
- Node.js 18+ (for dashboard development)
- Linux with kernel 5.8+ (for agent)

## Local Development Setup

### 1. Clone and Setup

```bash
git clone <repository>
cd kerneleye
cp .env.example .env
```

### 2. Start Infrastructure

```bash
# Start PostgreSQL
docker-compose up -d postgres

# Wait for database to be ready
sleep 5

# Run migrations
docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < backend/migrations/001_initial_schema.sql
```

### 3. Start Backend API

```bash
cd backend
go mod download
go run cmd/api/main.go
```

The API will be available at `http://localhost:8080`

### 4. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

The dashboard will be available at `http://localhost:3000`

### 5. Test Agent (Linux only)

```bash
cd agent

# Generate vmlinux.h (one-time setup)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# Generate eBPF code
go generate

# Build and run (requires root)
go build -o kerneleye-agent
sudo ./kerneleye-agent
```

## Production Deployment

### Using Docker Compose

```bash
# Set production environment variables
cp .env.example .env
# Edit .env with production values

# Start all services
docker-compose up -d

# Check logs
docker-compose logs -f
```

### Manual Deployment

See [docs/deployment.md](docs/deployment.md) for detailed deployment instructions.

## Testing

Generate test traffic to see the system in action:

```bash
# Terminal 1: Run agent
cd agent
sudo ./kerneleye-agent

# Terminal 2: Generate connections (port scan simulation)
for port in {1..50}; do 
  nc -zv localhost $port 2>&1 | grep -q "succeeded" && echo "Port $port open"
done
```

Check the agent logs and dashboard to see threat scores appear!

## Architecture

```
┌──────────────┐     gRPC/HTTPS     ┌──────────────┐
│ Go Agent     │ ─────────────────> │ Backend API  │
│ (eBPF)       │                    │ (Go/Fiber)   │
└──────────────┘                    └──────┬───────┘
                                           │
                                           ▼
                                    ┌──────────────┐
                                    │ PostgreSQL   │
                                    └──────────────┘
                                           ▲
                                           │
┌──────────────┐     REST API       ┌──────┴───────┐
│ Dashboard    │ ─────────────────> │ Backend API  │
│ (React)      │                    └──────────────┘
└──────────────┘
```

## Troubleshooting

### Agent Issues

**"Failed to load eBPF objects"**
- Check kernel version: `uname -r` (need 5.8+)
- Verify BTF: `ls /sys/kernel/btf/vmlinux`
- Run as root: `sudo ./kerneleye-agent`

**"No such symbol: inet_csk_accept"**
- Your kernel might not export this symbol
- Check available symbols: `sudo cat /proc/kallsyms | grep inet_csk`

### Backend Issues

**"Database connection failed"**
- Ensure PostgreSQL is running: `docker-compose ps`
- Check connection string in `.env`
- Run migrations: see step 2 above

### Dashboard Issues

**"API connection failed"**
- Ensure backend is running on port 8080
- Check CORS settings in backend `.env`
- Verify `VITE_API_URL` in dashboard

## Next Steps

1. **Enable UDP monitoring** - Uncomment UDP probe in agent
2. **Add real-time updates** - Implement WebSocket for live dashboard
3. **Deploy agents** - Install on production servers
4. **Configure alerts** - Set up email/Slack notifications
5. **Phase 2 features** - Implement auto-blocking

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Email: support@kerneleye.io
