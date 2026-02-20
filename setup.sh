#!/bin/bash

# KernelEye - Development Setup Script

set -e

echo "╔════════════════════════════════════════╗"
echo "║   KernelEye Development Setup          ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose found"
echo ""

# Create .env file
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp .env.example .env
    echo "✅ .env created (edit this file to customize)"
else
    echo "ℹ️  .env file already exists"
fi
echo ""

# Start PostgreSQL
echo "🐘 Starting PostgreSQL..."
docker-compose up -d postgres

echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Check if database is ready
until docker exec kerneleye-db pg_isready -U kerneleye &> /dev/null; do
    echo "   Waiting for database..."
    sleep 2
done

echo "✅ PostgreSQL is ready"
echo ""

# Run migrations
echo "🗄️  Running database migrations..."
docker exec -i kerneleye-db psql -U kerneleye -d kerneleye < backend/migrations/001_initial_schema.sql

echo "✅ Database migrations complete"
echo ""

# Backend setup
echo "🔧 Setting up backend..."
cd backend

if command -v go &> /dev/null; then
    echo "   Downloading Go dependencies..."
    go mod download
    echo "✅ Backend dependencies ready"
else
    echo "⚠️  Go is not installed. You'll need it to run the backend."
    echo "   Install from: https://go.dev/dl/"
fi

cd ..
echo ""

# Dashboard setup
echo "🎨 Setting up dashboard..."
cd dashboard

if command -v npm &> /dev/null; then
    echo "   Installing npm dependencies..."
    npm install
    echo "✅ Dashboard dependencies ready"
else
    echo "⚠️  Node.js/npm is not installed. You'll need it to run the dashboard."
    echo "   Install from: https://nodejs.org/"
fi

cd ..
echo ""

# Agent note
echo "🔍 Agent setup notes:"
if [ "$(uname)" = "Linux" ]; then
    echo "   You're on Linux! The agent can run here."
    echo ""
    echo "   To build the agent:"
    echo "   1. Install dependencies:"
    echo "      sudo apt-get install clang llvm libbpf-dev bpftool"
    echo ""
    echo "   2. Generate vmlinux.h:"
    echo "      cd agent"
    echo "      bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h"
    echo ""
    echo "   3. Build:"
    echo "      go generate"
    echo "      go build -o kerneleye-agent"
    echo ""
    echo "   4. Run (requires root):"
    echo "      sudo ./kerneleye-agent"
else
    echo "   ⚠️  You're not on Linux. The eBPF agent requires Linux to run."
    echo "   The backend and dashboard will work on any OS."
fi
echo ""

# Summary
echo "╔════════════════════════════════════════╗"
echo "║   Setup Complete! 🎉                   ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo ""
echo "1. Start the backend:"
echo "   cd backend"
echo "   go run cmd/api/main.go"
echo ""
echo "2. Start the dashboard (in another terminal):"
echo "   cd dashboard"
echo "   npm run dev"
echo ""
echo "3. Open your browser:"
echo "   http://localhost:3000"
echo ""
echo "4. Login with demo credentials:"
echo "   Email: demo@kerneleye.cloud"
echo "   Password: demo"
echo ""
echo "5. (Optional) Run the agent on Linux:"
echo "   cd agent"
echo "   sudo ./kerneleye-agent"
echo ""
echo "📚 Documentation: docs/development.md"
echo "🐛 Issues: GitHub Issues"
echo ""
echo "Happy coding! 🚀"
