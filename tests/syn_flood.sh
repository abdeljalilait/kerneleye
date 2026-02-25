#!/bin/bash

# SYN Flood Attack Test for KernelEye
# ====================================
# Generates SYN flood to trigger SYN-based detection and blocking
#
# Usage: ./syn_flood.sh <target_ip> [packets_count] [port]
#
# Examples:
#   ./syn_flood.sh 192.168.1.100           # Default: 10000 packets to port 80
#   ./syn_flood.sh 192.168.1.100 50000     # 50000 packets to port 80
#   ./syn_flood.sh 192.168.1.100 10000 22  # 10000 packets to port 22 (SSH)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TARGET_IP="${1:-192.168.1.100}"
PACKETS="${2:-10000}"
PORT="${3:-80}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SYN Flood Attack Test${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Target: $TARGET_IP"
echo "Port: $PORT"
echo "Packets: $PACKETS"
echo ""

# Check if hping3 is installed
if ! command -v hping3 &>/dev/null; then
	echo -e "${RED}Error: hping3 is not installed${NC}"
	echo "Install with: sudo apt install hping3"
	exit 1
fi

echo -e "${GREEN}[+] Starting SYN flood...${NC}"
echo -e "${YELLOW}[*] Watch the agent logs with: sudo journalctl -u kerneleye-agent -f${NC}"
echo -e "${YELLOW}[*] Check dashboard for traffic and blocks${NC}"
echo ""

# Run SYN flood
sudo hping3 -S -p "$PORT" -c "$PACKETS" --flood "$TARGET_IP" &

HPID=$!
echo -e "${GREEN}[+] Attack started with PID: $HPID${NC}"

# Wait for completion
wait $HPID

echo ""
echo -e "${GREEN}[✓] SYN flood completed${NC}"
echo ""
echo -e "${YELLOW}[*] Expected results:${NC}"
echo "  - SYN count should increase in traffic events"
echo "  - If score >= $SCORE_THRESHOLD, IP should be auto-blocked"
echo "  - Check dashboard for notification"
echo ""

# Show recent blocks
echo -e "${YELLOW}[*] Recent blocks in database:${NC}"
# psql command would go here if we had database access

echo ""
echo -e "${GREEN}[*] Test complete!${NC}"
