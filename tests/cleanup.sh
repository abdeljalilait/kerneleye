#!/bin/bash

# Cleanup Script for KernelEye Tests
# ===================================
# Remove test blocks and reset state
#
# Usage: ./cleanup.sh [target_ip]
#
# Examples:
#   ./cleanup.sh                 # Show cleanup options
#   ./cleanup.sh 192.168.1.100 # Unblock specific IP
#   ./cleanup.sh all            # Reset all test blocks

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET="${1:-menu}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  KernelEye Test Cleanup${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Note: Actual cleanup requires API access
# This script shows how to clean up

case "$TARGET" in
menu)
	echo -e "${CYAN}Cleanup Options:${NC}"
	echo ""
	echo "1. Via API (requires API key):"
	echo "   curl -X DELETE https://api.example.com/v1/blocks/\$IP \\"
	echo "     -H 'Authorization: Bearer \$API_KEY'"
	echo ""
	echo "2. Via Dashboard:"
	echo "   - Go to Blocks page"
	echo "   - Click unblock on test IPs"
	echo ""
	echo "3. Via Database (requires DB access):"
	echo "   DELETE FROM blocks WHERE source_ip = '\$IP';"
	echo ""
	echo "4. On Agent (iptables):"
	echo "   sudo iptables -D INPUT -s \$IP -j DROP"
	echo "   sudo ipset del kernel_eye_block \$IP"
	echo ""
	echo "5. Reset agent blocks (restart):"
	echo "   sudo systemctl restart kerneleye-agent"
	echo ""
	;;
all)
	echo -e "${YELLOW}[*] Would reset all test blocks...${NC}"
	echo -e "${YELLOW}[*] Use dashboard or API to unblock all IPs${NC}"
	;;
*)
	IP="$TARGET"
	echo -e "${GREEN}[+] Would unblock: $IP${NC}"
	echo ""
	echo "To unblock via API:"
	echo "  curl -X DELETE https://api.example.com/v1/blocks/$IP \\"
	echo "    -H 'Authorization: Bearer YOUR_API_KEY'"
	echo ""
	echo "To unblock on agent manually:"
	echo "  sudo ipset del kernel_eye_block $IP"
	echo "  sudo iptables -D INPUT -s $IP -j DROP"
	;;
esac

echo ""
echo -e "${GREEN}[*] Cleanup information displayed${NC}"
