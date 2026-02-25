// SPDX-License-Identifier: GPL-2.0
// XDP Firewall for KernelEye - Fast-path packet filtering
//
// Strict verifier-compliant version for kernel 6.12+

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

// ============================================
// Feature Flags
// ============================================
#define ENABLE_CIDR_BLOCKING
#define ENABLE_RATE_LIMITING
#define ENABLE_IPV6

// ============================================
// Constants
// ============================================
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_8021Q 0x8100
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

#define STATS_PASSED     0
#define STATS_DROPPED    1
#define STATS_ERRORS     2
#define STATS_RATELIMIT  3

#define RL_WINDOW_NS     1000000000ULL

// ============================================
// Data Structures
// ============================================
struct block_entry {
    __u64 expires_ns;
};

struct xdp_stats {
    __u64 packets;
    __u64 bytes;
};

struct rate_limit_state {
    __u64 window_start;
    __u64 packet_count;
    __u64 byte_count;
};

struct rate_limit_config {
    __u64 max_pps;
    __u64 max_bps;
    __u64 block_time_ns;
};

struct lpm_key_v4 {
    __u32 prefix_len;
    __u32 addr;
};

// ============================================
// BPF Maps
// ============================================
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct in6_addr);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_blocklist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct xdp_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_stats SEC(".maps");

#ifdef ENABLE_CIDR_BLOCKING
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, struct block_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_cidr_blocklist SEC(".maps");
#endif

#ifdef ENABLE_RATE_LIMITING
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32);
    __type(value, struct rate_limit_state);
} xdp_rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_rate_config SEC(".maps");
#endif

struct block_event {
    __u32 src_ip;
    __u8 src_ip6[16];
    __u8 ip_version;
    __u16 dest_port;
    __u8 protocol;
    __u8 reason;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_block_events SEC(".maps");

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

static __always_inline void log_blocked_packet(__u32 src_ip, __u8 *src_ip6, __u8 ip_version, 
                                              __u16 dest_port, __u8 protocol, __u8 reason) {
    struct block_event *event = bpf_ringbuf_reserve(&xdp_block_events, sizeof(struct block_event), 0);
    if (!event)
        return;
    
    event->src_ip = src_ip;
    if (ip_version == 6 && src_ip6)
        __builtin_memcpy(event->src_ip6, src_ip6, 16);
    event->ip_version = ip_version;
    event->dest_port = dest_port;
    event->protocol = protocol;
    event->reason = reason;
    event->timestamp_ns = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int is_expired(struct block_entry *entry) {
    if (entry->expires_ns == 0)
        return 0;
    return bpf_ktime_get_ns() > entry->expires_ns;
}

#ifdef ENABLE_RATE_LIMITING
static __always_inline int check_rate_limit(__u32 src_ip, __u32 pkt_len) {
    __u32 cfg_key = 0;
    struct rate_limit_config *cfg = bpf_map_lookup_elem(&xdp_rate_config, &cfg_key);
    
    if (!cfg || (cfg->max_pps == 0 && cfg->max_bps == 0))
        return 0;
    
    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_state *state = bpf_map_lookup_elem(&xdp_rate_limit, &src_ip);
    
    if (state) {
        __u64 window_start = state->window_start;
        
        if (now - window_start >= RL_WINDOW_NS) {
            __u64 old = __sync_val_compare_and_swap(&state->window_start, window_start, now);
            if (old == window_start) {
                __sync_lock_test_and_set(&state->packet_count, 1);
                __sync_lock_test_and_set(&state->byte_count, pkt_len);
                return 0;
            }
        }
        
        if (cfg->max_pps > 0) {
            __u64 pkt_count = __sync_fetch_and_add(&state->packet_count, 1) + 1;
            if (pkt_count >= cfg->max_pps) {
                if (cfg->block_time_ns > 0) {
                    __u64 expires = now + cfg->block_time_ns;
                    if (expires < now) expires = (__u64)-1;
                    struct block_entry block = { .expires_ns = expires };
                    bpf_map_update_elem(&xdp_blocklist, &src_ip, &block, BPF_ANY);
                }
                return 1;
            }
        }
        
        if (cfg->max_bps > 0) {
            __u64 byte_count = __sync_fetch_and_add(&state->byte_count, pkt_len) + pkt_len;
            if (byte_count > cfg->max_bps) {
                if (cfg->block_time_ns > 0) {
                    __u64 expires = now + cfg->block_time_ns;
                    if (expires < now) expires = (__u64)-1;
                    struct block_entry block = { .expires_ns = expires };
                    bpf_map_update_elem(&xdp_blocklist, &src_ip, &block, BPF_ANY);
                }
                return 1;
            }
        }
    } else {
        struct rate_limit_state new_state = {
            .window_start = now,
            .packet_count = 1,
            .byte_count = pkt_len,
        };
        long ret = bpf_map_update_elem(&xdp_rate_limit, &src_ip, &new_state, BPF_NOEXIST);
        if (ret == -17) {
            state = bpf_map_lookup_elem(&xdp_rate_limit, &src_ip);
            if (state) {
                __sync_fetch_and_add(&state->packet_count, 1);
                __sync_fetch_and_add(&state->byte_count, pkt_len);
            }
        }
    }
    
    return 0;
}
#endif

#ifdef ENABLE_CIDR_BLOCKING
static __always_inline int check_cidr_block(__u32 src_ip) {
    struct lpm_key_v4 key = {
        .prefix_len = 32,
        .addr = src_ip,
    };
    
    struct block_entry *entry = bpf_map_lookup_elem(&xdp_cidr_blocklist, &key);
    if (entry && !is_expired(entry))
        return 1;
    return 0;
}
#endif

// ============================================
// XDP Program - Ultra-conservative for strict verifiers
// ============================================

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Bounds check for packet length calculation
    if (data >= data_end)
        return XDP_PASS;
    
    __u32 pkt_len = (__u32)(data_end - data);
    if (pkt_len > 9000)
        pkt_len = 9000;
    
    // Need at least Ethernet header (14 bytes)
    if (data + 14 > data_end) {
        update_stats(STATS_PASSED, pkt_len);
        return XDP_PASS;
    }
    
    // Parse Ethernet protocol - direct byte access
    // Use a fresh pointer for each access to avoid verifier confusion
    __u8 *pkt_ptr = (__u8 *)data;
    __u16 eth_proto = ((__u16)pkt_ptr[12] << 8) | pkt_ptr[13];
    
    // Current offset into packet
    __u32 offset = 14;
    
    // Handle VLAN (802.1Q = 0x8100, 802.1AD = 0x88A8)
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        // Check VLAN header fits - must access data + offset each time
        if ((__u8 *)data + offset + 4 > (__u8 *)data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Read encapsulated protocol from VLAN header bytes 2-3
        pkt_ptr = (__u8 *)data + offset;
        eth_proto = ((__u16)pkt_ptr[2] << 8) | pkt_ptr[3];
        offset += 4;
        
        // Handle QinQ (double VLAN)
        if (eth_proto == bpf_htons(ETH_P_8021Q)) {
            if ((__u8 *)data + offset + 4 > (__u8 *)data_end) {
                update_stats(STATS_ERRORS, pkt_len);
                return XDP_PASS;
            }
            
            pkt_ptr = (__u8 *)data + offset;
            eth_proto = ((__u16)pkt_ptr[2] << 8) | pkt_ptr[3];
            offset += 4;
        }
    }
    
    // Process IPv4
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        // Minimum IPv4 header is 20 bytes (IHL=5)
        if ((__u8 *)data + offset + 20 > (__u8 *)data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Access IP header bytes
        pkt_ptr = (__u8 *)data + offset;
        
        // Read version and IHL from first byte
        __u8 version_ihl = pkt_ptr[0];
        __u8 version = version_ihl >> 4;
        __u8 ihl = version_ihl & 0x0f;
        
        if (version != 4 || ihl < 5 || ihl > 15) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Calculate IP header length and check bounds
        __u32 ip_hdr_len = (__u32)ihl * 4;
        if ((__u8 *)data + offset + ip_hdr_len > (__u8 *)data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Re-establish pointer after bounds check
        pkt_ptr = (__u8 *)data + offset;
        
        // Read source IP byte by byte to avoid unaligned access issues
        // Network byte order: bytes 12, 13, 14, 15
        __u32 src_ip = ((__u32)pkt_ptr[12] << 24) | 
                       ((__u32)pkt_ptr[13] << 16) | 
                       ((__u32)pkt_ptr[14] << 8)  | 
                       ((__u32)pkt_ptr[15]);
        
        // Read protocol (byte 9)
        __u8 protocol = pkt_ptr[9];
        
        // Parse destination port from L4 header
        __u16 dest_port = 0;
        __u32 l4_offset = offset + ip_hdr_len;
        
        // Check we have at least 4 bytes for port (TCP/UDP)
        if ((__u8 *)data + l4_offset + 4 <= (__u8 *)data_end) {
            __u8 *l4_ptr = (__u8 *)data + l4_offset;
            // Destination port is at bytes 2-3
            dest_port = ((__u16)l4_ptr[2] << 8) | l4_ptr[3];
        }
        
        // Check blocklist
        struct block_entry *entry = bpf_map_lookup_elem(&xdp_blocklist, &src_ip);
        if (entry && !is_expired(entry)) {
            update_stats(STATS_DROPPED, pkt_len);
            log_blocked_packet(src_ip, NULL, 4, dest_port, protocol, 1);
            return XDP_DROP;
        }
        
#ifdef ENABLE_CIDR_BLOCKING
        if (check_cidr_block(src_ip)) {
            update_stats(STATS_DROPPED, pkt_len);
            log_blocked_packet(src_ip, NULL, 4, dest_port, protocol, 2);
            return XDP_DROP;
        }
#endif

#ifdef ENABLE_RATE_LIMITING
        if (check_rate_limit(src_ip, pkt_len)) {
            update_stats(STATS_RATELIMIT, pkt_len);
            log_blocked_packet(src_ip, NULL, 4, 0, protocol, 3);
            return XDP_DROP;
        }
#endif
        
        update_stats(STATS_PASSED, pkt_len);
        return XDP_PASS;
    }
    
#ifdef ENABLE_IPV6
    // Process IPv6
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 header is fixed 40 bytes
        if ((__u8 *)data + offset + 40 > (__u8 *)data_end) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        pkt_ptr = (__u8 *)data + offset;
        
        // Check version (first 4 bits)
        __u8 version = pkt_ptr[0] >> 4;
        if (version != 6) {
            update_stats(STATS_ERRORS, pkt_len);
            return XDP_PASS;
        }
        
        // Read source address (bytes 8-23)
        struct in6_addr src_ip6;
        __builtin_memcpy(&src_ip6, pkt_ptr + 8, 16);
        
        // Read next header (byte 6)
        __u8 protocol = pkt_ptr[6];
        
        struct block_entry *entry = bpf_map_lookup_elem(&xdp_blocklist_v6, &src_ip6);
        if (entry && !is_expired(entry)) {
            update_stats(STATS_DROPPED, pkt_len);
            log_blocked_packet(0, (__u8 *)&src_ip6, 6, 0, protocol, 1);
            return XDP_DROP;
        }
        
        update_stats(STATS_PASSED, pkt_len);
        return XDP_PASS;
    }
#endif
    
    // Non-IP traffic
    update_stats(STATS_PASSED, pkt_len);
    return XDP_PASS;
}
