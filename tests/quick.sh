#!/bin/bash

# Quick Test Reference
# =====================
# Copy this to /usr/local/bin for easy access
# or run from the tests directory

TARGET="${1:-192.168.1.100}"

echo "═══════════════════════════════════════════════════════════════"
echo "  KernelEye Quick Test Commands"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Target: $TARGET"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│ ATTACK TESTS                                                │"
echo "├─────────────────────────────────────────────────────────────┤"
echo "│ # SYN Flood (most common test)                              │"
echo "│ ./tests/syn_flood.sh $TARGET                                 │"
echo "│                                                              │"
echo "│ # SSH Brute Force                                           │"
echo "│ ./tests/ssh_bruteforce.sh $TARGET                           │"
echo "│                                                              │"
echo "│ # Port Scan                                                  │"
echo "│ ./tests/port_scan.sh $TARGET                                │"
echo "│                                                              │"
echo "│ # DDoS (all vectors)                                        │"
echo "│ ./tests/ddos.sh $TARGET                                     │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│ MONITORING                                                   │"
echo "├─────────────────────────────────────────────────────────────┤"
echo "│ # Full monitoring (tail all logs)                            │"
echo "│ ./tests/monitor.sh                                          │"
echo "│                                                              │"
echo "│ # Agent logs only                                            │"
echo "│ sudo journalctl -u kerneleye-agent -f                        │"
echo "│                                                              │"
echo "│ # Just blocking events                                        │"
echo "│ sudo journalctl -u kerneleye-agent -f -g Block               │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│ VERIFICATION                                                  │"
echo "├─────────────────────────────────────────────────────────────┤"
echo "│ # Check XDP blocks                                           │"
echo "│ sudo ipset list kernel_eye_block                             │"
echo "│                                                              │"
echo "│ # Check iptables rules                                       │"
echo "│ sudo iptables -L INPUT -n -v                                │"
echo "│                                                              │"
echo "│ # Check blocked packets (agent logs)                         │"
echo "│ sudo journalctl -u kerneleye-agent -g 'XDP.*blocked'          │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""

# Run requested test if first arg is a known command
if [ "$2" != "" ]; then
	case "$2" in
	syn)
		./tests/syn_flood.sh "$TARGET"
		;;
	ssh)
		./tests/ssh_bruteforce.sh "$TARGET"
		;;
	scan)
		./tests/port_scan.sh "$TARGET"
		;;
	ddos)
		./tests/ddos.sh "$TARGET"
		;;
	monitor)
		./tests/monitor.sh
		;;
	*)
		echo "Unknown test: $2"
		;;
	esac
fi
