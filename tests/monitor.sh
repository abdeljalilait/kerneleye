#!/bin/bash

# Real-time Monitoring Script for KernelEye
# ==========================================
# Monitor agent logs, traffic, and blocks in real-time
#
# Usage: ./monitor.sh [mode]
#
# Examples:
#   ./monitor.sh           # Full monitoring
#   ./monitor.sh agent     # Agent logs only
#   ./monitor.sh blocks    # Block list only
#   ./monitor.sh traffic  # Traffic only

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

MODE="${1:-full}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  KernelEye Real-Time Monitor${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Mode: $MODE"
echo ""

# Check for required tools
check_tools() {
	if ! command -v journalctl &>/dev/null; then
		echo -e "${RED}journalctl not found - cannot monitor agent logs${NC}"
	fi
}

# Monitor agent logs
monitor_agent() {
	echo -e "${CYAN}[*] Agent Logs (Ctrl+C to exit)${NC}"
	echo "─────────────────────────────────────────"
	sudo journalctl -u kerneleye-agent -f 2>/dev/null ||
		echo -e "${RED}Cannot access journalctl - try sudo${NC}"
}

# Monitor blocked packets
monitor_xdp() {
	echo -e "${CYAN}[*] XDP Blocked Packets${NC}"
	echo "─────────────────────────────────────────"
	sudo journalctl -u kerneleye-agent -f -g "XDP.*blocked" 2>/dev/null ||
		echo -e "${RED}Cannot access journalctl - try sudo${NC}"
}

# Monitor scoring
monitor_scoring() {
	echo -e "${CYAN}[*] Scoring Worker${NC}"
	echo "─────────────────────────────────────────"
	sudo journalctl -u kerneleye-agent -f -g "ScoringWorker" 2>/dev/null ||
		echo -e "${RED}Cannot access journalctl - try sudo${NC}"
}

# Monitor blocking
monitor_blocks() {
	echo -e "${CYAN}[*] Block Events${NC}"
	echo "─────────────────────────────────────────"
	sudo journalctl -u kerneleye-agent -f -g "Blocked|Block" 2>/dev/null ||
		echo -e "${RED}Cannot access journalctl - try sudo${NC}"
}

# Show dashboard hints
show_hints() {
	echo ""
	echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
	echo -e "${YELLOW}  Dashboard Checks${NC}"
	echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
	echo ""
	echo "1. Check Overview page for live traffic"
	echo "2. Check Threats page for high-score IPs"
	echo "3. Check Blocks page for auto-blocked IPs"
	echo "4. Check Alerts page for security alerts"
	echo "5. Look for toast notifications in top-right"
	echo "6. Check header badge for alert count"
	echo ""
	echo "Dashboard URL: https://dashboard.kerneleye.net"
	echo ""
}

case "$MODE" in
agent)
	monitor_agent
	;;
xdp)
	monitor_xdp
	;;
scoring)
	monitor_scoring
	;;
blocks)
	monitor_blocks
	;;
traffic)
	monitor_scoring &
	monitor_blocks &
	sleep 30
	;;
full)
	show_hints
	(
		while true; do
			clear
			echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
			echo -e "${BLUE}  KernelEye Real-Time Monitor${NC}"
			echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
			echo ""
			echo -e "${GREEN}[*] Latest Agent Events:${NC}"
			sudo journalctl -u kerneleye-agent -n 20 --no-pager 2>/dev/null | tail -20 || echo "Cannot access"
			sleep 2
		done
	) &
	MONPID=$!
	echo -e "${CYAN}[*] Press Ctrl+C to exit${NC}"
	trap "kill $MONPID 2>/dev/null" EXIT
	wait
	;;
*)
	echo -e "${RED}Unknown mode: $MODE${NC}"
	echo "Available modes: agent, xdp, scoring, blocks, traffic, full"
	exit 1
	;;
esac
