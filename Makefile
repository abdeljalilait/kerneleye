# Default target
.PHONY: all
all: generate build
	@echo "Build complete!"

# Variables
PROTO_DIR = proto
GEN_GO_DIR = proto/gen/go
BACKEND_DIR = backend
AGENT_DIR = agent

# Docker Registry
# Override via: make docker-build REGISTRY=registry.example.com
REGISTRY ?= localhost
NAMESPACE ?= kerneleye
BACKEND_IMAGE = $(REGISTRY)/$(NAMESPACE)/backend
FRONTEND_IMAGE = $(REGISTRY)/$(NAMESPACE)/frontend
TAG ?= latest

# Production build configuration (optional)
# Create .env.build from .env.build.example and customize for your deployment.
BUILD_ENV_FILE = .env.build

# Read build-time env vars from dashboard/.env.production (single source of truth)
VITE_API_URL ?= $(shell grep -E '^VITE_API_URL=' dashboard/.env.production | cut -d= -f2-)
VITE_INSTALL_DOMAIN ?= $(shell grep -E '^VITE_INSTALL_DOMAIN=' dashboard/.env.production | cut -d= -f2-)
VITE_GRPC_HOST ?= $(shell grep -E '^VITE_GRPC_HOST=' dashboard/.env.production | cut -d= -f2-)

# Protobuf Generation
.PHONY: gen-proto
gen-proto:
	@echo "Generating Protobuf files..."
	@mkdir -p $(GEN_GO_DIR)
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_GO_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_GO_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/kerneleye/v1/*.proto
	@echo "Cleaning up generated file location..."
	@# The go_package option in .proto file creates a directory structure.
	@# We need to ensure the files are in the right place where the module expects them.
	@# currently go_package = "github.com/kerneleye/proto/gen/go/kerneleye/v1;kerneleyev1"
	@# protoc with paths=source_relative will output to proto/gen/go/kerneleye/v1/
	@# We want the module root at proto/gen/go, so let's tidy up.
	cd $(GEN_GO_DIR) && go mod tidy

# SQLC Generation
.PHONY: gen-sql
gen-sql:
	@echo "Generating SQLC code..."
	cd $(BACKEND_DIR) && sqlc generate

# eBPF Generation (traffic probe + XDP firewall)
.PHONY: gen-ebpf
gen-ebpf:
	@echo "Generating eBPF programs..."
	cd $(AGENT_DIR) && go generate ./...
	@cp $(AGENT_DIR)/ebpf/xdp_firewall_bpfel.o $(AGENT_DIR)/assets/
	@echo "eBPF programs compiled successfully"

# Build Backend
.PHONY: build-backend
build-backend:
	@echo "Building Backend..."
	cd $(BACKEND_DIR) && go build -o kerneleye-api ./cmd/api

# Build Agent
.PHONY: build-agent
build-agent: gen-ebpf
	@echo "Building Agent..."
	cd $(AGENT_DIR) && go build -o kerneleye-agent .

# Run everything (Dev mode)
.PHONY: dev
dev:
	@echo "Starting dev environment..."
	# This is a placeholder. In reality, you'd likely want to run these in separate terminals or use a process manager.
	@echo "Run 'cd backend && go run cmd/api/main.go' in one terminal"
	@echo "Run 'cd agent && sudo ./kerneleye-agent' in another terminal"

# Update deps
.PHONY: deps
deps:
	cd $(GEN_GO_DIR) && go get -u ./... && go mod tidy
	cd $(BACKEND_DIR) && go get -u ./... && go mod tidy
	cd $(AGENT_DIR) && go get -u ./... && go mod tidy

# ==========================================
# Systemd Service
# ==========================================

# Install systemd service for the agent (delegates to agent/Makefile)
.PHONY: install-service
install-service:
	@echo "Installing systemd service..."
	cd $(AGENT_DIR) && $(MAKE) install-service

# Remove systemd service for the agent
.PHONY: uninstall-service
uninstall-service:
	@echo "Removing systemd service..."
	cd $(AGENT_DIR) && $(MAKE) uninstall-service

# ==========================================
# TLS Certificates
# ==========================================

# Generate self-signed TLS certificates for gRPC
.PHONY: gen-certs
gen-certs:
	@echo "Generating gRPC TLS certificates..."
	@if [ -z "$(GRPC_DOMAIN)" ]; then \
		echo "Usage: make gen-certs GRPC_DOMAIN=grpc.kerneleye.net"; \
		exit 1; \
	fi
	./scripts/generate-grpc-certs.sh $(GRPC_DOMAIN)

# All generation tasks
.PHONY: generate
generate: gen-proto gen-sql gen-ebpf

# Production build — reads .env.build for domain overrides
.PHONY: build-production
build-production:
	@if [ ! -f $(BUILD_ENV_FILE) ]; then \
		echo "Error: $(BUILD_ENV_FILE) not found."; \
		echo "  cp .env.build.example .env.build"; \
		echo "  # Edit .env.build with your production domains"; \
		exit 1; \
	fi
	@echo "Loading production configuration from $(BUILD_ENV_FILE)..."
	@set -a; . ./$(BUILD_ENV_FILE); set +a; \
	if echo "$$KERNELEYE_SERVER" | grep -q "example.com"; then \
		echo "Error: KERNELEYE_SERVER in $(BUILD_ENV_FILE) still contains placeholder 'example.com'."; \
		echo "  Please customize all domains in $(BUILD_ENV_FILE) before building for production."; \
		exit 1; \
	fi; \
	echo "Production domains validated. Building..."; \
	$(MAKE) build-agent GRPC_URL="$$KERNELEYE_GRPC_HOST"; \
	$(MAKE) build-backend; \
	echo "Production build complete!"

# All build tasks
.PHONY: build
build: build-backend build-agent

# Clean generated files
.PHONY: clean
clean:
	@echo "Cleaning generated files..."
	rm -f $(AGENT_DIR)/bpf_bpfel_x86.o $(AGENT_DIR)/bpf_bpfel_x86.go
	rm -f $(AGENT_DIR)/ebpf/xdp_firewall_bpfel.o
	rm -f $(AGENT_DIR)/assets/xdp_firewall_bpfel.o
	rm -f $(BACKEND_DIR)/kerneleye-api
	rm -f $(AGENT_DIR)/kerneleye-agent
	@echo "Clean complete"

# ==========================================
# Docker Build Targets
# ==========================================

# Build backend Docker image
.PHONY: docker-build-backend
docker-build-backend:
	@echo "Building backend Docker image..."
	docker build -f Dockerfile.backend \
		--build-arg VERSION=$(shell cat $(BACKEND_DIR)/VERSION 2>/dev/null || echo "0.0.0") \
		-t $(BACKEND_IMAGE):$(TAG) .
	@echo "Built: $(BACKEND_IMAGE):$(TAG)"

# Build frontend Docker image
.PHONY: docker-build-frontend
docker-build-frontend:
	@echo "Building frontend Docker image..."
	docker build -f Dockerfile.frontend \
		--build-arg VITE_API_URL=$(VITE_API_URL) \
		--build-arg VITE_INSTALL_DOMAIN=$(VITE_INSTALL_DOMAIN) \
		--build-arg VITE_GRPC_HOST=$(VITE_GRPC_HOST) \
		--build-arg VERSION=$(shell cat $(AGENT_DIR)/VERSION 2>/dev/null || echo "0.0.0") \
		--build-arg GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown") \
		--build-arg BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ") \
		-t $(FRONTEND_IMAGE):$(TAG) .
	@echo "Built: $(FRONTEND_IMAGE):$(TAG)"

# Build all Docker images
.PHONY: docker-build
docker-build: docker-build-backend docker-build-frontend
	@echo "All Docker images built!"

# ==========================================
# Docker Push Targets
# ==========================================

# Push backend Docker image
.PHONY: docker-push-backend
docker-push-backend:
	@echo "Pushing backend image to $(REGISTRY)..."
	docker push $(BACKEND_IMAGE):$(TAG)

# Push frontend Docker image
.PHONY: docker-push-frontend
docker-push-frontend:
	@echo "Pushing frontend image to $(REGISTRY)..."
	docker push $(FRONTEND_IMAGE):$(TAG)

# Push all Docker images
.PHONY: docker-push
docker-push: docker-push-backend docker-push-frontend
	@echo "All Docker images pushed!"

# ==========================================
# Combined Build & Push
# ==========================================

# Build and push backend
.PHONY: docker-deploy-backend
docker-deploy-backend: docker-build-backend docker-push-backend

# Build and push frontend
.PHONY: docker-deploy-frontend
docker-deploy-frontend: docker-build-frontend docker-push-frontend

# Build and push all images
.PHONY: docker-deploy
docker-deploy: docker-build docker-push

# ==========================================
# Multi-arch Build (requires buildx)
# ==========================================

# Build and push multi-arch backend image
.PHONY: docker-buildx-backend
docker-buildx-backend:
	@echo "Building multi-arch backend image..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile.backend \
		-t $(BACKEND_IMAGE):$(TAG) \
		--push .

# Build and push multi-arch frontend image
.PHONY: docker-buildx-frontend
docker-buildx-frontend:
	@echo "Building multi-arch frontend image..."
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile.frontend \
		--build-arg VITE_API_URL=$(VITE_API_URL) \
		--build-arg VITE_INSTALL_DOMAIN=$(VITE_INSTALL_DOMAIN) \
		--build-arg VITE_GRPC_HOST=$(VITE_GRPC_HOST) \
		-t $(FRONTEND_IMAGE):$(TAG) \
		--push .

# Build and push all multi-arch images
.PHONY: docker-buildx
docker-buildx: docker-buildx-backend docker-buildx-frontend

# ==========================================
# Docker Compose
# ==========================================

# Pull latest images and start with docker-compose
.PHONY: compose-up
compose-up:
	docker-compose pull
	docker-compose up -d

# Stop docker-compose
.PHONY: compose-down
compose-down:
	docker-compose down

# Restart docker-compose
.PHONY: compose-restart
compose-restart: compose-down compose-up

# View logs
.PHONY: compose-logs
compose-logs:
	docker-compose logs -f

# ==========================================
# Help
# ==========================================

.PHONY: help
help:
	@echo "KernelEye Makefile Commands"
	@echo ""
	@echo "Development:"
	@echo "  make build              Build backend and agent binaries"
	@echo "  make build-backend      Build backend binary only"
	@echo "  make build-agent        Build agent binary only"
	@echo "  make generate           Generate all code (proto, sql, ebpf)"
	@echo "  make dev                Show dev environment instructions"
	@echo ""
	@echo "Systemd Service (requires root):"
	@echo "  make install-service    Install agent systemd service with auto-capabilities"
	@echo "  make uninstall-service  Remove agent systemd service"
	@echo "  make gen-certs          Generate gRPC TLS certificates (GRPC_DOMAIN=hostname)"
	@echo ""
	@echo "Docker Build:"
	@echo "  make docker-build-backend     Build backend Docker image"
	@echo "  make docker-build-frontend    Build frontend Docker image"
	@echo "  make docker-build             Build all Docker images"
	@echo ""
	@echo "Docker Push:"
	@echo "  make docker-push-backend      Push backend image to registry"
	@echo "  make docker-push-frontend     Push frontend image to registry"
	@echo "  make docker-push              Push all images to registry"
	@echo ""
	@echo "Docker Deploy (build + push):"
	@echo "  make docker-deploy-backend    Build and push backend"
	@echo "  make docker-deploy-frontend   Build and push frontend"
	@echo "  make docker-deploy            Build and push all images"
	@echo ""
	@echo "Multi-arch Build:"
	@echo "  make docker-buildx-backend    Build and push multi-arch backend"
	@echo "  make docker-buildx-frontend   Build and push multi-arch frontend"
	@echo "  make docker-buildx            Build and push all multi-arch"
	@echo ""
	@echo "Docker Compose:"
	@echo "  make compose-up               Pull and start services"
	@echo "  make compose-down             Stop services"
	@echo "  make compose-restart          Restart services"
	@echo "  make compose-logs             View logs"
	@echo ""
	@echo "Production Build:"
	@echo "  make build-production   Build agent + backend with .env.build domains"
	@echo ""
	@echo "Variables:"
	@echo "  TAG=<tag>               Set image tag (default: latest)"
	@echo "  REGISTRY=<url>          Set registry (default: localhost)"
	@echo ""
	@echo "Examples:"
	@echo "  make build-production                 # Build for production (.env.build required)"
	@echo "  make docker-build TAG=v1.0.0          # Build Docker images"
	@echo "  make docker-deploy TAG=prod REGISTRY=registry.example.com"
	@echo "  make docker-buildx TAG=latest"
