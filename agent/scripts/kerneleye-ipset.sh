#!/bin/bash
# KernelEye IPSet management script
# Usage: kerneleye-ipset {restore|save|flush|stats|list}

STATE_FILE="/var/lib/kerneleye/ipset.state"
STATE_DIR="/var/lib/kerneleye"

# Ensure state directory exists
mkdir -p "$STATE_DIR"

case "$1" in
    restore)
        echo "Restoring KernelEye ipsets..."
        if [ -f "$STATE_FILE" ]; then
            ipset restore < "$STATE_FILE"
            echo "✅ Restored from $STATE_FILE"
        else
            echo "ℹ️  No state file found, starting fresh"
        fi
        ;;
    
    save)
        echo "Saving KernelEye ipsets..."
        ipset save | grep -E "^(create|add) kerneleye_" > "$STATE_FILE"
        echo "✅ Saved to $STATE_FILE"
        ;;
    
    flush)
        echo "Flushing KernelEye ipsets..."
        for set in kerneleye_block kerneleye_block_v6 kerneleye_ratelimit kerneleye_ratelimit_v6; do
            ipset flush "$set" 2>/dev/null && echo "  Flushed $set"
        done
        echo "✅ All ipsets flushed"
        ;;
    
    stats)
        echo "=== KernelEye Block Statistics ==="
        for set in kerneleye_block kerneleye_block_v6 kerneleye_ratelimit kerneleye_ratelimit_v6; do
            count=$(ipset list "$set" 2>/dev/null | grep -c "^\d" || echo "0")
            echo "  $set: $count entries"
        done
        
        echo ""
        echo "=== iptables DROP counters ==="
        iptables -L KERNELEYE -v -n -x 2>/dev/null | grep DROP || echo "  (no drops yet)"
        ;;
    
    list)
        echo "=== Blocked IPs (IPv4) ==="
        ipset list kerneleye_block 2>/dev/null | grep "^\d" || echo "  (none)"
        
        echo ""
        echo "=== Blocked IPs (IPv6) ==="
        ipset list kerneleye_block_v6 2>/dev/null | grep -E "^([0-9a-fA-F]|:)" || echo "  (none)"
        
        echo ""
        echo "=== Rate Limited IPs (IPv4) ==="
        ipset list kerneleye_ratelimit 2>/dev/null | grep "^\d" || echo "  (none)"
        ;;
    
    unblock)
        IP="$2"
        if [ -z "$IP" ]; then
            echo "Usage: kerneleye-ipset unblock <ip>"
            exit 1
        fi
        
        # Try IPv4 set
        if ipset del kerneleye_block "$IP" 2>/dev/null; then
            echo "✅ Unblocked $IP from IPv4 set"
        # Try IPv6 set
        elif ipset del kerneleye_block_v6 "$IP" 2>/dev/null; then
            echo "✅ Unblocked $IP from IPv6 set"
        else
            echo "❌ IP $IP not found in blocklists"
            exit 1
        fi
        ;;
    
    block)
        IP="$2"
        DURATION="${3:-3600}"  # Default 1 hour
        
        if [ -z "$IP" ]; then
            echo "Usage: kerneleye-ipset block <ip> [duration_seconds]"
            exit 1
        fi
        
        # Detect IPv4 vs IPv6
        if [[ "$IP" =~ : ]]; then
            SET="kerneleye_block_v6"
        else
            SET="kerneleye_block"
        fi
        
        if ipset add "$SET" "$IP" timeout "$DURATION" -exist; then
            echo "✅ Blocked $IP for ${DURATION}s"
        else
            echo "❌ Failed to block $IP"
            exit 1
        fi
        ;;
    
    health)
        echo "Checking KernelEye firewall health..."
        
        # Check if ipset exists
        if ! ipset list kerneleye_block &>/dev/null; then
            echo "❌ kerneleye_block ipset not found"
            exit 1
        fi
        
        # Check if iptables chain exists
        if ! iptables -L KERNELEYE &>/dev/null; then
            echo "❌ KERNELEYE iptables chain not found"
            exit 1
        fi
        
        # Check if jump rule exists
        if ! iptables -C INPUT -j KERNELEYE &>/dev/null; then
            echo "❌ INPUT jump rule not found"
            exit 1
        fi
        
        echo "✅ All health checks passed"
        ;;
    
    *)
        cat << EOF
KernelEye IPSet Management Tool

Usage: kerneleye-ipset <command> [options]

Commands:
  restore              Restore ipsets from state file
  save                 Save current ipsets to state file
  flush                Flush all entries (keep sets)
  stats                Show statistics
  list                 List all blocked IPs
  block <ip> [secs]    Manually block an IP (default: 3600s)
  unblock <ip>         Manually unblock an IP
  health               Check firewall health

Examples:
  kerneleye-ipset block 192.0.2.100 3600    # Block for 1 hour
  kerneleye-ipset unblock 192.0.2.100       # Unblock
  kerneleye-ipset stats                     # View statistics

State file: $STATE_FILE
EOF
        exit 1
        ;;
esac
