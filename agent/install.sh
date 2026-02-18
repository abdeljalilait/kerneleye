#!/bin/bash
#
# KernelEye Agent Installation Script
# This script installs the KernelEye Agent with logging support
#

set -e

# ==============================================================================
# Configuration
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# Default installation paths
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-$PREFIX/bin}"
CONFIGDIR="${CONFIGDIR:-/etc/kerneleye}"
LOGDIR="${LOGDIR:-/var/log/kerneleye}"

# Log file (can be overridden)
LOG_FILE="${LOG_FILE:-$LOGDIR/install.log}"

# Binary name
BINARY_NAME="kerneleye-agent"
REPO_URL="${REPO_URL:-https://github.com/kerneleye/kerneleye}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================================================================
# Logging Functions
# ==============================================================================

# Ensure log directory exists
init_logging() {
    # Create log directory if it doesn't exist (use sudo if needed)
    if [ ! -d "$LOGDIR" ]; then
        if [ "$EUID" -eq 0 ]; then
            mkdir -p "$LOGDIR"
        else
            sudo mkdir -p "$LOGDIR"
        fi
    fi
    
    # Initialize log file
    if [ "$EUID" -eq 0 ]; then
        touch "$LOG_FILE" 2>/dev/null || true
    else
        sudo touch "$LOG_FILE" 2>/dev/null || true
    fi
    
    log "INFO" "=== KernelEye Agent Installation Started ==="
    log "INFO" "Script: $SCRIPT_DIR/$SCRIPT_NAME"
    log "INFO" "User: $(whoami)"
    log "INFO" "Host: $(hostname)"
    log "INFO" "Date: $(date -Iseconds)"
    log "INFO" "Working Directory: $SCRIPT_DIR"
}

# Log to file and optionally stdout
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"
    
    # Always write to log file (with sudo if needed)
    if [ -w "$LOG_FILE" ] 2>/dev/null || [ "$EUID" -eq 0 ]; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    else
        echo "$log_entry" | sudo tee -a "$LOG_FILE" > /dev/null 2>&1 || true
    fi
    
    # Also print to stdout for interactive sessions
    case "$level" in
        ERROR)
            echo -e "${RED}✗ $message${NC}" >&2
            ;;
        WARN)
            echo -e "${YELLOW}⚠ $message${NC}"
            ;;
        SUCCESS)
            echo -e "${GREEN}✓ $message${NC}"
            ;;
        INFO)
            echo -e "${BLUE}ℹ $message${NC}"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# ==============================================================================
# Utility Functions
# ==============================================================================

# Print banner
print_banner() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}         ${GREEN}KernelEye Agent Installer${NC}                       ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}         Real-time Linux Security Monitoring              ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check OS compatibility
check_os() {
    log "INFO" "Checking operating system compatibility..."
    
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        log "ERROR" "KernelEye Agent requires Linux. Detected: $OSTYPE"
        exit 1
    fi
    
    # Check kernel version (need 5.8+ for BTF support)
    local kernel_version
    kernel_version=$(uname -r | cut -d- -f1)
    local major minor
    major=$(echo "$kernel_version" | cut -d. -f1)
    minor=$(echo "$kernel_version" | cut -d. -f2)
    
    log "INFO" "Kernel version: $kernel_version"
    
    if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 8 ]; }; then
        log "WARN" "Kernel version $kernel_version detected. Kernel 5.8+ recommended for full functionality."
    else
        log "SUCCESS" "Kernel version $kernel_version is supported"
    fi
    
    # Check for BTF support
    if [ -f /sys/kernel/btf/vmlinux ]; then
        log "SUCCESS" "BTF support detected"
    else
        log "WARN" "BTF not detected. Some eBPF features may not work."
    fi
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    local missing_deps=()
    
    # Check for Go
    if ! command_exists go; then
        missing_deps+=("go")
        log "WARN" "Go not found. Will attempt to install from release binary."
    else
        local go_version
        go_version=$(go version | awk '{print $3}')
        log "SUCCESS" "Go found: $go_version"
    fi
    
    # Check for clang (only needed for building from source)
    if ! command_exists clang; then
        log "WARN" "clang not found. Required only for building from source."
    else
        log "SUCCESS" "clang found"
    fi
    
    # Check for required capabilities
    if [ "$EUID" -ne 0 ]; then
        log "WARN" "Not running as root. Installation may require sudo privileges."
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log "INFO" "Missing optional dependencies: ${missing_deps[*]}"
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command_exists lsb_release; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Install dependencies for building from source
install_build_deps() {
    log "INFO" "Installing build dependencies..."
    
    local distro
    distro=$(detect_distro)
    log "INFO" "Detected distribution: $distro"
    
    case "$distro" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential
            ;;
        fedora|rhel|centos)
            sudo dnf install -y clang llvm libbpf-devel kernel-headers make gcc
            ;;
        arch|manjaro)
            sudo pacman -S --needed clang llvm libbpf linux-headers base-devel
            ;;
        alpine)
            sudo apk add clang llvm-dev libbpf-dev linux-headers make gcc
            ;;
        *)
            log "WARN" "Unknown distribution. Please install dependencies manually:"
            log "INFO" "  - clang"
            log "INFO" "  - llvm"
            log "INFO" "  - libbpf-dev (or libbpf-devel)"
            log "INFO" "  - linux-headers"
            ;;
    esac
}

# ==============================================================================
# Build Functions
# ==============================================================================

# Build from source
build_from_source() {
    log "INFO" "Building KernelEye Agent from source..."
    log "INFO" "Working directory: $SCRIPT_DIR"
    
    cd "$SCRIPT_DIR"
    
    # Check if Makefile exists
    if [ ! -f Makefile ]; then
        log "ERROR" "Makefile not found in $SCRIPT_DIR"
        log "INFO" "Please run this script from the agent directory"
        exit 1
    fi
    
    # Build using Makefile
    log "INFO" "Running make build-release..."
    if make build-release 2>&1 | tee -a "$LOG_FILE"; then
        log "SUCCESS" "Build completed successfully"
    else
        log "ERROR" "Build failed. Check $LOG_FILE for details"
        exit 1
    fi
    
    # Verify binary exists
    if [ ! -f "$BINARY_NAME" ]; then
        log "ERROR" "Binary not found after build"
        exit 1
    fi
    
    log "SUCCESS" "Binary location: $SCRIPT_DIR/$BINARY_NAME"
}

# ==============================================================================
# Installation Functions
# ==============================================================================

# Install binary
install_binary() {
    log "INFO" "Installing binary to $BINDIR..."
    
    # Create directories
    sudo mkdir -p "$BINDIR"
    sudo mkdir -p "$CONFIGDIR"
    sudo mkdir -p "$LOGDIR"
    
    # Install binary
    if [ -f "$SCRIPT_DIR/$BINARY_NAME" ]; then
        sudo install -m 0755 "$SCRIPT_DIR/$BINARY_NAME" "$BINDIR/$BINARY_NAME"
        log "SUCCESS" "Binary installed to $BINDIR/$BINARY_NAME"
    else
        log "ERROR" "Binary not found at $SCRIPT_DIR/$BINARY_NAME"
        exit 1
    fi
    
    # Create default config if it doesn't exist
    if [ ! -f "$CONFIGDIR/agent.env" ]; then
        log "INFO" "Creating default configuration..."
        sudo tee "$CONFIGDIR/agent.env" > /dev/null <<EOF
# KernelEye Agent Configuration
# Generated on $(date)

# Your API key from the KernelEye dashboard
KERNELEYE_API_KEY=your-api-key-here

# Backend server address
KERNELEYE_SERVER=api.kerneleye.io:443

# Enable active remediation (requires root)
# ENABLE_REMEDIATION=true

# Enable XDP fast-path blocking
# ENABLE_XDP=true

# Network interface for XDP (auto-detected if not set)
# INTERFACE=eth0
EOF
        sudo chmod 0600 "$CONFIGDIR/agent.env"
        log "SUCCESS" "Configuration file created at $CONFIGDIR/agent.env"
    fi
}

# Create systemd service
create_systemd_service() {
    log "INFO" "Setting up systemd service..."
    
    local service_file="/etc/systemd/system/kerneleye-agent.service"
    
    if [ -d /etc/systemd/system ]; then
        sudo tee "$service_file" > /dev/null <<EOF
[Unit]
Description=KernelEye Agent - Real-time Linux Security Monitoring
Documentation=https://github.com/kerneleye/kerneleye
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-$CONFIGDIR/agent.env
ExecStart=$BINDIR/$BINARY_NAME -enable-remediation
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOGDIR/agent.log
StandardError=append:$LOGDIR/agent.log

# Security hardening
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$LOGDIR

# Required capabilities for eBPF
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_RESOURCE

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        log "SUCCESS" "Systemd service created"
        log "INFO" "  Enable on boot: sudo systemctl enable kerneleye-agent"
        log "INFO" "  Start service:  sudo systemctl start kerneleye-agent"
        log "INFO" "  View status:    sudo systemctl status kerneleye-agent"
    else
        log "WARN" "systemd not detected. Skipping service creation."
    fi
}

# Create wrapper script for easy execution
create_wrapper_script() {
    log "INFO" "Creating wrapper script..."
    
    local wrapper_file="$BINDIR/kerneleye"
    
    sudo tee "$wrapper_file" > /dev/null <<'EOF'
#!/bin/bash
# KernelEye Agent Wrapper Script
# This wrapper makes it easy to run kerneleye-agent from anywhere

CONFIGDIR="/etc/kerneleye"
LOGDIR="/var/log/kerneleye"

# Load environment if exists
if [ -f "$CONFIGDIR/agent.env" ]; then
    export $(grep -v '^#' "$CONFIGDIR/agent.env" | xargs)
fi

# Function to show help
show_help() {
    echo "KernelEye Agent - Usage:"
    echo ""
    echo "  kerneleye start          Start the agent in foreground"
    echo "  kerneleye start-bg       Start the agent in background (with logging)"
    echo "  kerneleye stop           Stop the background agent"
    echo "  kerneleye status         Check if agent is running"
    echo "  kerneleye logs           View agent logs"
    echo "  kerneleye config         Edit configuration"
    echo "  kerneleye version        Show version information"
    echo "  kerneleye help           Show this help message"
    echo ""
    echo "Direct agent options:"
    kerneleye-agent -help 2>&1 | tail -n +2
}

# Handle commands
case "$1" in
    start)
        shift
        exec sudo kerneleye-agent "$@"
        ;;
    start-bg)
        log_file="$LOGDIR/agent.log"
        echo "Starting KernelEye Agent in background..."
        echo "Logs will be written to: $log_file"
        nohup sudo kerneleye-agent -enable-remediation > "$log_file" 2>&1 &
        echo $! > /tmp/kerneleye-agent.pid
        echo "Agent started with PID: $(cat /tmp/kerneleye-agent.pid)"
        ;;
    stop)
        if [ -f /tmp/kerneleye-agent.pid ]; then
            pid=$(cat /tmp/kerneleye-agent.pid)
            echo "Stopping KernelEye Agent (PID: $pid)..."
            sudo kill "$pid" 2>/dev/null && echo "Agent stopped" || echo "Agent not running"
            rm -f /tmp/kerneleye-agent.pid
        else
            echo "Agent PID file not found. Checking for running processes..."
            sudo pkill -f kerneleye-agent && echo "Agent stopped" || echo "Agent not running"
        fi
        ;;
    status)
        if pgrep -x "kerneleye-agent" > /dev/null; then
            echo "KernelEye Agent is running"
            pgrep -x "kerneleye-agent" | xargs ps -fp
        else
            echo "KernelEye Agent is not running"
        fi
        ;;
    logs)
        if [ -f "$LOGDIR/agent.log" ]; then
            tail -f "$LOGDIR/agent.log"
        else
            echo "Log file not found at $LOGDIR/agent.log"
        fi
        ;;
    config)
        if command -v nano > /dev/null; then
            sudo nano "$CONFIGDIR/agent.env"
        elif command -v vim > /dev/null; then
            sudo vim "$CONFIGDIR/agent.env"
        else
            sudo cat "$CONFIGDIR/agent.env"
        fi
        ;;
    version)
        kerneleye-agent -version 2>/dev/null || kerneleye-agent --help 2>&1 | head -1
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        # Pass through to actual binary
        exec sudo kerneleye-agent "$@"
        ;;
esac
EOF
    
    sudo chmod +x "$wrapper_file"
    log "SUCCESS" "Wrapper script created at $wrapper_file"
}

# Show post-installation instructions
show_post_install() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}         Installation Complete! 🎉                        ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log "INFO" "Installation log saved to: $LOG_FILE"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo ""
    echo "  1. ${YELLOW}Configure the agent:${NC}"
    echo "     Edit: sudo kerneleye config"
    echo "     Or:   sudo nano $CONFIGDIR/agent.env"
    echo ""
    echo "  2. ${YELLOW}Set your API key:${NC}"
    echo "     Get your API key from the KernelEye dashboard"
    echo "     Add it to the configuration file"
    echo ""
    echo "  3. ${YELLOW}Run the agent:${NC}"
    echo "     Foreground:  sudo kerneleye start"
    echo "     Background:  kerneleye start-bg"
    echo "     With XDP:    sudo kerneleye start -xdp -interface eth0"
    echo ""
    echo "  4. ${YELLOW}View logs:${NC}"
    echo "     Real-time:   kerneleye logs"
    echo "     File:        sudo tail -f $LOGDIR/agent.log"
    echo ""
    echo "  5. ${YELLOW}Manage the service (if systemd):${NC}"
    echo "     Enable:      sudo systemctl enable kerneleye-agent"
    echo "     Start:       sudo systemctl start kerneleye-agent"
    echo "     Status:      sudo systemctl status kerneleye-agent"
    echo ""
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  kerneleye help       Show all available commands"
    echo "  kerneleye version    Show version information"
    echo "  kerneleye status     Check if agent is running"
    echo ""
    log "INFO" "For support, visit: $REPO_URL"
}

# ==============================================================================
# Uninstall Function
# ==============================================================================

uninstall() {
    log "INFO" "Uninstalling KernelEye Agent..."
    
    # Stop service if running
    if command_exists systemctl; then
        sudo systemctl stop kerneleye-agent 2>/dev/null || true
        sudo systemctl disable kerneleye-agent 2>/dev/null || true
        sudo rm -f /etc/systemd/system/kerneleye-agent.service
        sudo systemctl daemon-reload
    fi
    
    # Remove binary
    sudo rm -f "$BINDIR/$BINARY_NAME"
    sudo rm -f "$BINDIR/kerneleye"
    log "SUCCESS" "Binaries removed"
    
    log "INFO" "Note: Configuration at $CONFIGDIR and logs at $LOGDIR were preserved."
    log "INFO" "To remove completely: sudo rm -rf $CONFIGDIR $LOGDIR"
    
    log "SUCCESS" "Uninstallation complete"
}

# ==============================================================================
# Main Script
# ==============================================================================

main() {
    # Parse arguments
    local action="install"
    local build_from_source=true
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall|-u)
                action="uninstall"
                shift
                ;;
            --prefix)
                PREFIX="$2"
                BINDIR="$PREFIX/bin"
                shift 2
                ;;
            --no-build)
                build_from_source=false
                shift
                ;;
            --install-deps)
                install_build_deps
                exit 0
                ;;
            --help|-h)
                echo "KernelEye Agent Installation Script"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --help, -h          Show this help message"
                echo "  --uninstall, -u     Uninstall the agent"
                echo "  --prefix PATH       Set installation prefix (default: /usr/local)"
                echo "  --no-build          Skip building from source (use existing binary)"
                echo "  --install-deps      Install build dependencies only"
                echo ""
                echo "Environment Variables:"
                echo "  PREFIX              Installation prefix"
                echo "  LOG_FILE            Path to installation log file"
                echo "  KERNELEYE_API_KEY   Pre-configure API key"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    init_logging
    
    # Print banner
    print_banner
    
    # Perform action
    case "$action" in
        install)
            log "INFO" "Starting installation..."
            check_os
            check_prerequisites
            
            if [ "$build_from_source" = true ]; then
                build_from_source
            else
                log "INFO" "Skipping build, using existing binary"
            fi
            
            install_binary
            create_systemd_service
            create_wrapper_script
            show_post_install
            
            log "SUCCESS" "Installation completed successfully"
            ;;
            
        uninstall)
            uninstall
            ;;
    esac
}

# Run main function
main "$@"
