// SPDX-License-Identifier: GPL-2.0
// XDP Firewall for KernelEye - Fast-path packet filtering
// Drops packets from blocked IPs before they reach the network stack
//
// Features:
// - IP blocklist with TTL expiry
// - CIDR range blocking via LPM Trie
// - In-kernel PPS/BPS rate limiting
// - Per-CPU packet statistics

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

// ============================================
// Feature Flags (compile-time toggles)
// ============================================
// Uncomment to disable features for better performance

#define ENABLE_CIDR_BLOCKING    // LPM Trie for IP range drops
#define ENABLE_RATE_LIMITING    // Per-IP PPS/BPS tracking
// #define ENABLE_IPV6          // IPv6 support (disabled for performance)

// ============================================
// Constants
// ============================================

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_8021Q 0x8100
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

// XDP Actions
#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

// Stats indices
#define STATS_PASSED     0
#define STATS_DROPPED    1
#define STATS_ERRORS     2
#define STATS_RATELIMIT  3

// Rate limiting defaults
#define RL_WINDOW_NS     1000000000ULL  // 1 second in nanoseconds
#define RL_DEFAULT_PPS   1000           // Default max packets per second
#define RL_DEFAULT_BPS   10000000       // Default max bytes per second (10 MB/s)

// ============================================
// Data Structures
// ============================================

// Blocklist entry with expiry timestamp
struct block_entry {
    __u64 expires_ns;  // Nanoseconds since boot when block expires (0 = permanent)
};

// Packet counters
struct xdp_stats {
    __u64 packets;
    __u64 bytes;
};

// Rate limit state per IP
struct rate_limit_state {
    __u64 window_start;   // Start of current window (ns since boot)
    __u64 packet_count;   // Packets in current window
    __u64 byte_count;     // Bytes in current window
};

// Rate limit config (set from userspace)
struct rate_limit_config {
    __u64 max_pps;        // Max packets per second (0 = unlimited)
    __u64 max_bps;        // Max bytes per second (0 = unlimited)
    __u64 block_time_ns;  // How long to block if exceeded (0 = just drop)
};

// LPM Trie key for CIDR matching
struct lpm_key_v4 {
    __u32 prefix_len;     // CIDR prefix length (e.g., 24 for /24)
    __u32 addr;           // IPv4 address in network byte order
};

// Ethernet header
struct ethhdr_t {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

// VLAN header
struct vlan_hdr_t {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

// IPv4 header
struct iphdr_t {
    __u8  ihl:4, version:4;
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

// IPv6 header
struct ipv6hdr_t {
    __u8  priority:4, version:4;
    __u8  flow_lbl[3];
    __be16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

// ============================================
// BPF Maps
// ============================================

// IPv4 blocklist: source IP (network byte order) -> block entry
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);  // 256K entries
    __type(key, __u32);           // IPv4 address (network byte order)
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // Pin to /sys/fs/bpf/
} xdp_blocklist SEC(".maps");

// IPv6 blocklist: source IP -> block entry
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);   // 64K entries
    __type(key, struct in6_addr); // IPv6 address
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_blocklist_v6 SEC(".maps");

// Per-CPU statistics: [PASSED, DROPPED, ERRORS, RATELIMIT]
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats SEC(".maps");

#ifdef ENABLE_CIDR_BLOCKING
// LPM Trie for CIDR range blocking (e.g., 192.168.0.0/16)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);   // 16K CIDR ranges
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_cidr_blocklist SEC(".maps");
#endif

#ifdef ENABLE_RATE_LIMITING
// Per-IP rate limiting state
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);  // 128K IPs
    __type(key, __u32);           // IPv4 address
    __type(value, struct rate_limit_state);
} xdp_rate_limit SEC(".maps");

// Global rate limit config (index 0)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_rate_config SEC(".maps");
#endif

// ============================================
// Helper Functions
// ============================================

static __always_inline void update_stats(__u32 idx, __u32 bytes) {
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats, &idx);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, bytes);
    }
}

// Check if block entry is expired
static __always_inline int is_expired(struct block_entry *entry) {
    if (entry->expires_ns == 0) {
        return 0;  // Permanent block (expires_ns = 0 means never expires)
    }
    __u64 now = bpf_ktime_get_ns();
    return now > entry->expires_ns;
}

#ifdef ENABLE_RATE_LIMITING
// Check and update rate limit for an IP
// Returns 1 if rate limit exceeded, 0 otherwise
static __always_inline int check_rate_limit(__u32 src_ip, __u32 pkt_len) {
    __u32 cfg_key = 0;
    struct rate_limit_config *cfg = bpf_map_lookup_elem(&xdp_rate_config, &cfg_key);
    
    // If no config or both limits are 0, no rate limiting
    if (!cfg || (cfg->max_pps == 0 && cfg->max_bps == 0)) {
        return 0;
    }
    
    __u64 now = bpf_ktime_get_ns();
    
    struct rate_limit_state *state = bpf_map_lookup_elem(&xdp_rate_limit, &src_ip);
    
    if (state) {
        // Check if we're in a new window
        if (now - state->window_start >= RL_WINDOW_NS) {
            // Reset window
            state->window_start = now;
            state->packet_count = 1;
            state->byte_count = pkt_len;
            return 0;
        }
        
        // Check PPS limit
        if (cfg->max_pps > 0 && state->packet_count >= cfg->max_pps) {
            // Optionally add to blocklist
            if (cfg->block_time_ns > 0) {
                struct block_entry block = { .expires_ns = now + cfg->block_time_ns };
                bpf_map_update_elem(&xdp_blocklist, &src_ip, &block, BPF_ANY);
            }
            return 1;  // Rate limit exceeded
        }
        
        // Check BPS limit
        if (cfg->max_bps > 0 && state->byte_count >= cfg->max_bps) {
            if (cfg->block_time_ns > 0) {
                struct block_entry block = { .expires_ns = now + cfg->block_time_ns };
                bpf_map_update_elem(&xdp_blocklist, &src_ip, &block, BPF_ANY);
            }
            return 1;  // Rate limit exceeded
        }
        
        // Update counters
        __sync_fetch_and_add(&state->packet_count, 1);
        __sync_fetch_and_add(&state->byte_count, pkt_len);
    } else {
        // New IP - create state
        struct rate_limit_state new_state = {
            .window_start = now,
            .packet_count = 1,
            .byte_count = pkt_len,
        };
        bpf_map_update_elem(&xdp_rate_limit, &src_ip, &new_state, BPF_ANY);
    }
    
    return 0;
}
#endif

#ifdef ENABLE_CIDR_BLOCKING
// Check if IP is in a blocked CIDR range
static __always_inline int check_cidr_block(__u32 src_ip) {
    struct lpm_key_v4 key = {
        .prefix_len = 32,  // Full match first, LPM will find longest prefix
        .addr = src_ip,
    };
    
    struct block_entry *entry = bpf_map_lookup_elem(&xdp_cidr_blocklist, &key);
    if (entry && !is_expired(entry)) {
        return 1;  // Blocked
    }
    return 0;
}
#endif

// ============================================
// XDP Program
// ============================================

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    __u32 pkt_len = data_end - data;
    
    // Parse Ethernet header
    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end) {
        update_stats(STATS_ERRORS, pkt_len);
        return XDP_PASS;  // Don't drop malformed - let kernel handle
    }
    
    __be16 proto = eth->h_proto;
    void *l3_start = (void *)(eth + 1);
    
    // Handle VLAN tags (802.1Q and QinQ)
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr_t *vlan = l3_start;
        if ((void *)(vlan + 1) > data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        proto = vlan->h_vlan_encapsulated_proto;
        l3_start = (void *)(vlan + 1);
        
        // Handle QinQ (double VLAN tag)
        if (proto == bpf_htons(ETH_P_8021Q)) {
            vlan = l3_start;
            if ((void *)(vlan + 1) > data_end) {
                update_stats(STATS_ERRORS, pkt_len);
                return XDP_PASS;
            }
            proto = vlan->h_vlan_encapsulated_proto;
            l3_start = (void *)(vlan + 1);
        }
    }
    
    // Process IPv4
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr_t *ip = l3_start;
        if ((void *)(ip + 1) > data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        if (ip->version != 4 || ip->ihl < 5) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        __u32 src_ip = ip->saddr;
        
        // Check 1: IP blocklist (exact match)
        struct block_entry *entry = bpf_map_lookup_elem(&xdp_blocklist, &src_ip);
        if (entry && !is_expired(entry)) {
            update_stats(STATS_DROPPED, pkt_len);
            return XDP_DROP;
        }
        
#ifdef ENABLE_CIDR_BLOCKING
        // Check 2: CIDR range blocklist
        if (check_cidr_block(src_ip)) {
            update_stats(STATS_DROPPED, pkt_len);
            return XDP_DROP;
        }
#endif

#ifdef ENABLE_RATE_LIMITING
        // Check 3: Rate limiting
        if (check_rate_limit(src_ip, pkt_len)) {
            update_stats(STATS_RATELIMIT, pkt_len);
            return XDP_DROP;
        }
#endif
        
        update_stats(STATS_PASSED, pkt_len);
        return XDP_PASS;
    }
    
#ifdef ENABLE_IPV6
    // Process IPv6
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr_t *ip6 = l3_start;
        if ((void *)(ip6 + 1) > data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        if (ip6->version != 6) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Check source IP against IPv6 blocklist
        struct block_entry *entry = bpf_map_lookup_elem(&xdp_blocklist_v6, &ip6->saddr);
        if (entry && !is_expired(entry)) {
            update_stats(STATS_DROPPED, pkt_len);
            return XDP_DROP;
        }
        
        update_stats(STATS_PASSED, pkt_len);
        return XDP_PASS;
    }
#endif
    
    // Non-IP traffic: pass through
    update_stats(STATS_PASSED, pkt_len);
    return XDP_PASS;
}
