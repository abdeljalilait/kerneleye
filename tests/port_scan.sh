#!/bin/bash

# Port Scan Detection Test for KernelEye
# ========================================
# Tests port scan detection capabilities
#
# Usage: ./port_scan.sh <target_ip> [scan_type]
#
# Examples:
#   ./port_scan.sh 192.168.1.100           # Full port scan
#   ./port_scan.sh 192.168.1.100 syn       # SYN scan
#   ./port_scan.sh 192.168.1.100 connect   # TCP connect scan

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_IP="${1:-192.168.1.100}"
SCAN_TYPE="${2:-syn}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  Port Scan Detection Test${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Target: $TARGET_IP"
echo "Scan Type: $SCAN_TYPE"
echo ""

# Check if nmap is installed
if ! command -v nmap &>/dev/null; then
	echo -e "${RED}Error: nmap is not installed${NC}"
	echo "Install with: sudo apt install nmap"
	exit 1
fi

echo -e "${GREEN}[+] Starting port scan...${NC}"
echo -e "${YELLOW}[*] Watch the agent logs with: sudo journalctl -u kerneleye-agent -f${NC}"
echo -e "${YELLOW}[*] Check dashboard for traffic and blocks${NC}"
echo ""

case "$SCAN_TYPE" in
syn)
	echo -e "${GREEN}[+] Running SYN scan (requires sudo)${NC}"
	sudo nmap -sS -p 1-1000 "$TARGET_IP"
	;;
connect)
	echo -e "${GREEN}[+] Running TCP connect scan${NC}"
	nmap -sT -p 1-1000 "$TARGET_IP"
	;;
udp)
	echo -e "${GREEN}[+] Running UDP scan (slow)${NC}"
	sudo nmap -sU -p 1-100 "$TARGET_IP"
	;;
aggressive)
	echo -e "${GREEN}[+] Running aggressive scan${NC}"
	sudo nmap -A -p 1-500 "$TARGET_IP"
	;;
*)
	echo -e "${GREEN}[+] Running default SYN scan${NC}"
	sudo nmap -sS -p 1-1000 "$TARGET_IP"
	;;
esac

echo ""
echo -e "${GREEN}[✓] Port scan completed${NC}"
echo ""
echo -e "${YELLOW}[*] Expected results:${NC}"
echo "  - Multiple unique ports should appear in traffic"
echo "  - unique_ports count should increase significantly"
echo "  - Port scan pattern should be detected"
echo "  - IP may be auto-blocked based on port count and rate"
echo ""

echo -e "${GREEN}[*] Test complete!${NC}"
