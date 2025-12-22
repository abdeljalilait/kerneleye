# Default target
.PHONY: all
all: generate build
	@echo "Build complete!"

# Variables
PROTO_DIR = proto
GEN_GO_DIR = proto/gen/go
BACKEND_DIR = backend
AGENT_DIR = agent

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

# All generation tasks
.PHONY: generate
generate: gen-proto gen-sql gen-ebpf

# All build tasks
.PHONY: build
build: build-backend build-agent

# Clean generated files
.PHONY: clean
clean:
	@echo "Cleaning generated files..."
	rm -f $(AGENT_DIR)/bpf_bpfel_x86.o $(AGENT_DIR)/bpf_bpfel_x86.go
	rm -f $(AGENT_DIR)/ebpf/xdp_firewall_bpfel.o
	rm -f $(BACKEND_DIR)/kerneleye-api
	rm -f $(AGENT_DIR)/kerneleye-agent
	@echo "Clean complete"

