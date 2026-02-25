#!/bin/bash

# KernelEye Test Scripts
# =====================
# This directory contains scripts to test KernelEye's detection and blocking capabilities.
#
# Usage:
#   ./syn_flood.sh <target_ip> [rate] [duration]
#   ./ssh_bruteforce.sh <target_ip>
#   ./port_scan.sh <target_ip>
#   ./monitor.sh
#   ./cleanup.sh
#
# Prerequisites:
#   - hping3: sudo apt install hping3
#   - hydra:  sudo apt install hydra
#   - nmap:   sudo apt install nmap

export TARGET_IP="${1:-192.168.1.100}"
export RATE="${2:-10000}"
export DURATION="${3:-30}"

echo "========================================"
echo "  KernelEye Attack Simulation Scripts"
echo "========================================"
echo ""
echo "Target IP: $TARGET_IP"
echo "Default Rate: $RATE packets/sec"
echo "Default Duration: $DURATION seconds"
echo ""
echo "Available scripts:"
echo "  ./syn_flood.sh       - SYN flood attack"
echo "  ./ssh_bruteforce.sh - SSH brute force attack"
echo "  ./port_scan.sh      - Port scan detection"
echo "  ./ddos.sh           - Multi-vector DDoS"
echo "  ./monitor.sh        - Real-time monitoring"
echo "  ./cleanup.sh        - Cleanup test blocks"
echo ""
