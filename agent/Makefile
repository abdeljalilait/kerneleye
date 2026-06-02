# KernelEye Agent Makefile

.PHONY: all gen-ebpf build build-release test lint fmt clean run \
	install uninstall install-service uninstall-service check-root help

BINARY_NAME := kerneleye-agent
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
CONFIGDIR := /etc/kerneleye
LOGDIR := /var/log/kerneleye
SYSTEMD_DIR := /etc/systemd/system

VERSION ?= $(shell cat VERSION 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_USER := $(shell whoami 2>/dev/null || echo "unknown")
BUILD_HOST := $(shell hostname 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | cut -d' ' -f3)
GRPC_URL ?=

LDFLAGS := -ldflags "\
	-X 'main.Version=$(VERSION)' \
	-X 'main.GitCommit=$(GIT_COMMIT)' \
	-X 'main.GitBranch=$(GIT_BRANCH)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.BuildUser=$(BUILD_USER)' \
	-X 'main.BuildHost=$(BUILD_HOST)' \
	-X 'main.GoVersion=$(GO_VERSION)' \
	-X 'main.DefaultGRPCURL=$(GRPC_URL)'"

all: build
	@echo "Agent build complete!"

gen-ebpf:
	@echo "Generating eBPF programs..."
	go generate ./...
	@cp ebpf/xdp_firewall_bpfel.o assets/
	@echo "eBPF programs compiled successfully"

build: gen-ebpf
	@echo "Building agent..."
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY_NAME) .

build-release: gen-ebpf
	@echo "Building release agent..."
	CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o $(BINARY_NAME) .

test:
	go test ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		go vet ./...; \
	fi

fmt:
	gofmt -w .

clean:
	@echo "Cleaning agent artifacts..."
	rm -f $(BINARY_NAME)
	rm -f bpf_bpfel_x86.go bpf_bpfel_x86.o
	rm -f bpf_x86_bpfel.go bpf_x86_bpfel.o
	rm -f ebpf/xdp_firewall_bpfel.o assets/xdp_firewall_bpfel.o
	rm -rf dist/
	@echo "Clean complete"

run: build
	sudo ./$(BINARY_NAME) $(ARGS)

install: check-root build-release
	@echo "Installing agent..."
	@install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(CONFIGDIR) $(DESTDIR)$(LOGDIR)
	@install -m 0755 $(BINARY_NAME) $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	@setcap cap_bpf,cap_perfmon,cap_net_admin,cap_net_raw,cap_sys_resource+ip $(DESTDIR)$(BINDIR)/$(BINARY_NAME) 2>/dev/null || true
	@if [ ! -f $(DESTDIR)$(CONFIGDIR)/agent.env ]; then \
		echo "KERNELEYE_API_KEY=your-api-key-here" > $(DESTDIR)$(CONFIGDIR)/agent.env; \
		echo "KERNELEYE_SERVER=api.kerneleye.net:443" >> $(DESTDIR)$(CONFIGDIR)/agent.env; \
		chmod 0600 $(DESTDIR)$(CONFIGDIR)/agent.env; \
	fi
	@echo "Installed $(DESTDIR)$(BINDIR)/$(BINARY_NAME)"

uninstall: check-root
	@echo "Uninstalling agent..."
	@setcap -r $(DESTDIR)$(BINDIR)/$(BINARY_NAME) 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY_NAME)
	@echo "Removed $(DESTDIR)$(BINDIR)/$(BINARY_NAME)"

install-service: check-root
	@echo "Installing systemd service..."
	@install -d $(DESTDIR)$(SYSTEMD_DIR)
	@install -m 0644 scripts/kerneleye-agent.service $(DESTDIR)$(SYSTEMD_DIR)/kerneleye-agent.service
	systemctl daemon-reload
	@echo "Service installed. Enable with: sudo systemctl enable kerneleye-agent"

uninstall-service: check-root
	@echo "Removing systemd service..."
	-systemctl stop kerneleye-agent 2>/dev/null || true
	-systemctl disable kerneleye-agent 2>/dev/null || true
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/kerneleye-agent.service
	systemctl daemon-reload
	@echo "Service removed"

check-root:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: this target requires root privileges"; \
		echo "Run with: sudo make $(MAKECMDGOALS)"; \
		exit 1; \
	fi

help:
	@echo "KernelEye Agent Makefile Commands"
	@echo ""
	@echo "Development:"
	@echo "  make build              Generate eBPF and build the agent"
	@echo "  make gen-ebpf           Generate eBPF programs"
	@echo "  make test               Run agent tests"
	@echo "  make lint               Run golangci-lint or go vet"
	@echo "  make fmt                Format Go code"
	@echo "  make clean              Remove generated artifacts"
	@echo "  make run ARGS='...'     Build and run agent with sudo"
	@echo ""
	@echo "Install:"
	@echo "  sudo make install            Install binary and default config"
	@echo "  sudo make uninstall          Remove installed binary"
	@echo "  sudo make install-service    Install systemd service"
	@echo "  sudo make uninstall-service  Remove systemd service"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION=<value>         Override version from VERSION file"
	@echo "  GRPC_URL=<host:port>    Inject default gRPC URL"
	@echo "  PREFIX=<path>           Install prefix (default: /usr/local)"
