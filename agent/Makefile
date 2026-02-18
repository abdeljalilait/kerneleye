# KernelEye Agent Makefile
# Semantic Versioning (SemVer) build system

# Binary name
BINARY_NAME := kerneleye-agent

# Installation directories
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
LOGDIR := /var/log/kerneleye
CONFIGDIR := /etc/kerneleye

# Version information (Semantic Versioning: MAJOR.MINOR.PATCH-PRERELEASE+BUILD)
# Read from VERSION file or use default
VERSION_FILE := VERSION
VERSION := $(shell cat $(VERSION_FILE) 2>/dev/null || echo "0.2.0")

# Build metadata
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_USER := $(shell whoami 2>/dev/null || echo "unknown")
BUILD_HOST := $(shell hostname 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | cut -d' ' -f3)

# Version components for semver
VERSION_MAJOR := $(shell echo $(VERSION) | cut -d. -f1)
VERSION_MINOR := $(shell echo $(VERSION) | cut -d. -f2)
VERSION_PATCH := $(shell echo $(VERSION) | cut -d. -f3 | cut -d- -f1 | cut -d+ -f1)
VERSION_PRERELEASE := $(shell echo $(VERSION) | grep -oP '\-\K[^+]+' || echo "")
VERSION_BUILD := $(shell echo $(VERSION) | grep -oP '\+\K.*' || echo "$(GIT_COMMIT)")

# Full version string
FULL_VERSION := $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
ifneq ($(VERSION_PRERELEASE),)
FULL_VERSION := $(FULL_VERSION)-$(VERSION_PRERELEASE)
endif
FULL_VERSION := $(FULL_VERSION)+$(VERSION_BUILD)

# gRPC URL - can be set at build time via environment variable
GRPC_URL ?= ""

# Go build flags
LDFLAGS := -ldflags "\
	-X 'main.Version=$(FULL_VERSION)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.GitBranch=$(GIT_BRANCH)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.BuildUser=$(BUILD_USER)' \
	-X 'main.BuildHost=$(BUILD_HOST)' \
	-X 'main.GoVersion=$(GO_VERSION)' \
	-X 'main.DefaultGRPCURL=$(GRPC_URL)' \
	-s -w"

# Build flags for different modes
GCFLAGS :=
ifeq ($(DEBUG),1)
GCFLAGS := -gcflags="all=-N -l"
LDFLAGS :=
endif

# eBPF generation
EBPF_SOURCE := ebpf/traffic_probe.c
EBPF_GENERATED := bpf_bpfel_x86.go bpf_bpfel_x86.o

# Source files
SOURCES := $(wildcard *.go) $(EBPF_GENERATED)

# Colors for output
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
NC := \033[0m # No Color

.PHONY: all help version info build build-release clean install uninstall \
        gen-ebpf check-deps release-major release-minor release-patch \
        docker-build test lint fmt check-root

# Default target
all: check-deps gen-ebpf build

# Help target
help:
	@echo "$(BLUE)KernelEye Agent Build System$(NC)"
	@echo ""
	@echo "$(GREEN)Usage:$(NC)"
	@echo "  make [target] [VARIABLE=value]"
	@echo ""
	@echo "$(GREEN)Main Targets:$(NC)"
	@echo "  $(YELLOW)all$(NC)              Build the agent (default)"
	@echo "  $(YELLOW)build$(NC)            Build the agent binary (debug mode)"
	@echo "  $(YELLOW)build-release$(NC)    Build optimized release binary"
	@echo "  $(YELLOW)clean$(NC)            Clean build artifacts"
	@echo "  $(YELLOW)install$(NC)          Install binary to system (requires root)"
	@echo "  $(YELLOW)uninstall$(NC)        Remove binary from system (requires root)"
	@echo "  $(YELLOW)gen-ebpf$(NC)         Generate eBPF Go bindings"
	@echo "  $(YELLOW)version$(NC)          Display version information"
	@echo "  $(YELLOW)info$(NC)             Display build configuration"
	@echo ""
	@echo "$(GREEN)Version Management:$(NC)"
	@echo "  $(YELLOW)release-major$(NC)    Bump major version (X.0.0)"
	@echo "  $(YELLOW)release-minor$(NC)    Bump minor version (x.Y.0)"
	@echo "  $(YELLOW)release-patch$(NC)    Bump patch version (x.y.Z)"
	@echo "  $(YELLOW)set-version$(NC)      Set specific version (VERSION=X.Y.Z)"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  $(YELLOW)test$(NC)             Run tests"
	@echo "  $(YELLOW)lint$(NC)             Run linter"
	@echo "  $(YELLOW)fmt$(NC)              Format Go code"
	@echo ""
	@echo "$(GREEN)Variables:$(NC)"
	@echo "  $(YELLOW)DEBUG=1$(NC)          Build with debug symbols"
	@echo "  $(YELLOW)PREFIX=$(NC)          Installation prefix (default: /usr/local)"
	@echo "  $(YELLOW)VERSION=$(NC)         Override version string"
	@echo "  $(YELLOW)GRPC_URL=$(NC)        Default gRPC URL (e.g., grpc.kerneleye.io:443)"

# Display version information
version:
	@echo "$(BLUE)KernelEye Agent Version Information$(NC)"
	@echo "  Version:        $(FULL_VERSION)"
	@echo "  Major:          $(VERSION_MAJOR)"
	@echo "  Minor:          $(VERSION_MINOR)"
	@echo "  Patch:          $(VERSION_PATCH)"
	@echo "  Prerelease:     $(VERSION_PRERELEASE)"
	@echo "  Build:          $(VERSION_BUILD)"
	@echo "  Git Commit:     $(GIT_COMMIT)"
	@echo "  Git Branch:     $(GIT_BRANCH)"
	@echo "  Build Date:     $(BUILD_DATE)"
	@echo "  Go Version:     $(GO_VERSION)"

# Display build configuration
info: version
	@echo ""
	@echo "$(BLUE)Build Configuration$(NC)"
	@echo "  Binary Name:    $(BINARY_NAME)"
	@echo "  Install Prefix: $(PREFIX)"
	@echo "  Binary Dir:     $(BINDIR)"
	@echo "  Config Dir:     $(CONFIGDIR)"
	@echo "  Log Dir:        $(LOGDIR)"
	@echo "  DEBUG Mode:     $(if $(DEBUG),Yes,No)"

# Check dependencies
check-deps:
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@which go > /dev/null || (echo "$(RED)Error: Go is not installed$(NC)" && exit 1)
	@echo "  $(GREEN)✓$(NC) Go: $(GO_VERSION)"
	@which clang > /dev/null || (echo "$(RED)Error: clang is not installed$(NC)" && exit 1)
	@echo "  $(GREEN)✓$(NC) clang"
	@which bpftool > /dev/null || echo "  $(YELLOW)⚠$(NC) bpftool not found (may be needed for eBPF dev)"
	@echo "$(GREEN)All required dependencies found$(NC)"

# Generate eBPF Go bindings
gen-ebpf: $(EBPF_GENERATED)

$(EBPF_GENERATED): $(EBPF_SOURCE) ebpf/*.c ebpf/*.h
	@echo "$(BLUE)Generating eBPF bindings...$(NC)"
	go generate ./...
	@echo "$(GREEN)eBPF bindings generated$(NC)"

# Build the agent (debug mode)
build: $(SOURCES)
	@echo "$(BLUE)Building KernelEye Agent...$(NC)"
	@echo "  Version: $(FULL_VERSION)"
	@echo "  Commit:  $(GIT_COMMIT)"
	CGO_ENABLED=0 go build $(GCFLAGS) $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "$(GREEN)Build complete: $(BINARY_NAME)$(NC)"

# Build optimized release binary
build-release: LDFLAGS += -ldflags "\
	-X 'main.Version=$(FULL_VERSION)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.GitBranch=$(GIT_BRANCH)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.BuildUser=$(BUILD_USER)' \
	-X 'main.BuildHost=$(BUILD_HOST)' \
	-X 'main.GoVersion=$(GO_VERSION)' \
	-X 'main.DefaultGRPCURL=$(GRPC_URL)' \
	-s -w \
	-extldflags '-static'"
build-release: $(SOURCES)
	@echo "$(BLUE)Building release binary...$(NC)"
	@echo "  Version: $(FULL_VERSION)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-a -installsuffix cgo \
		$(LDFLAGS) \
		-o $(BINARY_NAME) .
	@echo "$(GREEN)Release build complete: $(BINARY_NAME)$(NC)"
	@echo "Binary size: $$(ls -lh $(BINARY_NAME) | awk '{print $$5}')"

# Build for multiple architectures
build-all:
	@echo "$(BLUE)Building for multiple architectures...$(NC)"
	@mkdir -p dist
	@echo "  Building for linux/amd64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .
	@echo "  Building for linux/arm64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 .
	@echo "$(GREEN)All builds complete in dist/$(NC)"

# Run tests
test:
	@echo "$(BLUE)Running tests...$(NC)"
	go test -v ./... -race

# Run linter
lint:
	@echo "$(BLUE)Running linter...$(NC)"
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "$(YELLOW)golangci-lint not installed, using go vet$(NC)"; \
		go vet ./...; \
	fi

# Format code
fmt:
	@echo "$(BLUE)Formatting code...$(NC)"
	gofmt -w .

# Create necessary directories
create-dirs:
	@mkdir -p $(DESTDIR)$(BINDIR)
	@mkdir -p $(DESTDIR)$(CONFIGDIR)
	@mkdir -p $(DESTDIR)$(LOGDIR)

# Install the binary and required files
install: check-root build-release create-dirs
	@echo "$(BLUE)Installing KernelEye Agent...$(NC)"
	@echo "  Installing binary to $(DESTDIR)$(BINDIR)/"
	@install -m 0755 $(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	@echo "  Creating config directory $(DESTDIR)$(CONFIGDIR)/"
	@mkdir -p $(DESTDIR)$(CONFIGDIR)
	@echo "  Creating log directory $(DESTDIR)$(LOGDIR)/"
	@mkdir -p $(DESTDIR)$(LOGDIR)
	@if [ ! -f $(DESTDIR)$(CONFIGDIR)/agent.env ]; then \
		echo "  Creating default config file..."; \
		echo "# KernelEye Agent Configuration" > $(DESTDIR)$(CONFIGDIR)/agent.env; \
		echo "KERNELEYE_API_KEY=your-api-key-here" >> $(DESTDIR)$(CONFIGDIR)/agent.env; \
		echo "KERNELEYE_SERVER=api.kerneleye.io:443" >> $(DESTDIR)$(CONFIGDIR)/agent.env; \
		echo "# KERNELEYE_GRPC_URL=grpc.kerneleye.io:443" >> $(DESTDIR)$(CONFIGDIR)/agent.env; \
		chmod 0600 $(DESTDIR)$(CONFIGDIR)/agent.env; \
	fi
	@echo "$(GREEN)Installation complete!$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Edit configuration: $(DESTDIR)$(CONFIGDIR)/agent.env"
	@echo "  2. Run the agent: sudo $(DESTDIR)$(BINDIR)/$(BINARY_NAME)"
	@echo "  3. View logs: tail -f $(DESTDIR)$(LOGDIR)/agent.log"

# Uninstall
uninstall: check-root
	@echo "$(BLUE)Uninstalling KernelEye Agent...$(NC)"
	@rm -f $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	@echo "  Removed binary from $(DESTDIR)$(BINDIR)/"
	@echo "$(YELLOW)Note: Config files in $(DESTDIR)$(CONFIGDIR)/ and logs in $(DESTDIR)$(LOGDIR)/ were not removed.$(NC)"
	@echo "      Remove manually if desired:"
	@echo "        sudo rm -rf $(DESTDIR)$(CONFIGDIR) $(DESTDIR)$(LOGDIR)"

# Check if running as root for install/uninstall
check-root:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "$(RED)Error: This target requires root privileges$(NC)"; \
		echo "       Run with: sudo make $(MAKECMDGOALS)"; \
		exit 1; \
	fi

# Version bump targets
release-major:
	@echo "$(BLUE)Bumping major version...$(NC)"
	@echo "$$(( $(VERSION_MAJOR) + 1 )).0.0" > $(VERSION_FILE)
	@echo "$(GREEN)New version: $(shell cat $(VERSION_FILE))$(NC)"

release-minor:
	@echo "$(BLUE)Bumping minor version...$(NC)"
	@echo "$(VERSION_MAJOR).$$(( $(VERSION_MINOR) + 1 )).0" > $(VERSION_FILE)
	@echo "$(GREEN)New version: $(shell cat $(VERSION_FILE))$(NC)"

release-patch:
	@echo "$(BLUE)Bumping patch version...$(NC)"
	@echo "$(VERSION_MAJOR).$(VERSION_MINOR).$$(( $(VERSION_PATCH) + 1 ))" > $(VERSION_FILE)
	@echo "$(GREEN)New version: $(shell cat $(VERSION_FILE))$(NC)"

set-version:
	@if [ -z "$(VERSION)" ]; then \
		echo "$(RED)Error: VERSION not specified$(NC)"; \
		echo "Usage: make set-version VERSION=X.Y.Z"; \
		exit 1; \
	fi
	@echo "$(BLUE)Setting version to $(VERSION)...$(NC)"
	@echo "$(VERSION)" > $(VERSION_FILE)
	@echo "$(GREEN)Version set to: $(VERSION)$(NC)"

# Clean build artifacts
clean:
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@rm -f $(BINARY_NAME)
	@rm -f $(EBPF_GENERATED)
	@rm -rf dist/
	@echo "$(GREEN)Clean complete$(NC)"

# Docker build (for CI/CD)
docker-build:
	@echo "$(BLUE)Building in Docker container...$(NC)"
	@docker build -f Dockerfile.build -t kerneleye-agent-builder .
	@docker run --rm -v $$(pwd):/output kerneleye-agent-builder \
		cp /app/kerneleye-agent /output/
	@echo "$(GREEN)Docker build complete$(NC)"

# Development run (requires root)
run: build
	@echo "$(BLUE)Running KernelEye Agent...$(NC)"
	sudo ./$(BINARY_NAME) $(ARGS)

# Print available make variables
print-vars:
	@echo "$(BLUE)Makefile Variables:$(NC)"
	@echo "  BINARY_NAME: $(BINARY_NAME)"
	@echo "  VERSION: $(VERSION)"
	@echo "  FULL_VERSION: $(FULL_VERSION)"
	@echo "  GIT_COMMIT: $(GIT_COMMIT)"
	@echo "  BUILD_DATE: $(BUILD_DATE)"
	@echo "  GRPC_URL: $(GRPC_URL)"
	@echo "  LDFLAGS: $(LDFLAGS)"
