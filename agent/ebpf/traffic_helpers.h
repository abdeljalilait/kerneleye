// traffic_helpers.h provides shared inline helpers for event initialization,
// debug counters, socket address extraction, key construction, interface
// filtering, process metadata, and rate limiting.
#ifndef KERNELEYE_TRAFFIC_HELPERS_H
#define KERNELEYE_TRAFFIC_HELPERS_H

#include "traffic_maps.h"

static __always_inline void inc_debug_counter(u64 idx) {
    u32 key = 0;
    struct debug_stats *stats = bpf_map_lookup_elem(&debug_counters, &key);
    if (stats) {
        if (idx == 0) stats->syn_recv_events++;
        else if (idx == 1) stats->accept_events++;
        else if (idx == 2) stats->connect_events++;
        else if (idx == 3) stats->close_events++;
        else if (idx == 4) stats->udp_events++;
    }
}

// Helper: Zero every byte of a ring buffer event before filling fields.
// This prevents stale stack/ringbuf bytes from leaking through padding or
// inactive IPv4/IPv6 union members.
static __always_inline void init_event(struct event_t *e) {
    __builtin_memset(e, 0, sizeof(*e));
}

// ============================================
// Runtime Configuration (.rodata)
// ============================================
// Interface filter: if non-zero, only count packets on this interface.
// 0 means all interfaces (default for backward compatibility).
// Userspace can override at load time via bpftool map update on .rodata.
static volatile const u32 CONFIG_ALLOWED_IFINDEX = 0;

// ============================================
// Interface Filtering
// ============================================
static __always_inline int is_iface_allowed(struct __sk_buff *skb) {
    if (CONFIG_ALLOWED_IFINDEX == 0) {
        return 1; // No filter, allow all
    }
    // For ingress, use ingress_ifindex; for egress, use ifindex
    u32 ifindex = skb->ingress_ifindex ? skb->ingress_ifindex : skb->ifindex;
    return ifindex == CONFIG_ALLOWED_IFINDEX;
}

// Helper: Create 4-tuple connection key
static __always_inline void make_conn_key(struct conn_key *key, u32 saddr, u16 sport, u32 daddr, u16 dport) {
    key->saddr = saddr;
    key->daddr = daddr;
    key->sport = sport;
    key->dport = dport;
}

// Helper: Create IPv6 4-tuple connection key
static __always_inline void make_conn_key_v6(struct conn_key_v6 *key, struct in6_addr *saddr, u16 sport, struct in6_addr *daddr, u16 dport) {
    key->saddr = *saddr;
    key->daddr = *daddr;
    key->sport = sport;
    key->dport = dport;
}

// Helper: Extract addresses from socket (supports both IPv4 and IPv6)
static __always_inline int get_sock_addrs(struct sock *sk, u16 family,
                                          u32 *saddr4, u32 *daddr4,
                                          struct in6_addr *saddr6, struct in6_addr *daddr6,
                                          u16 *sport, u16 *dport) {
    if (family == AF_INET) {
        *saddr4 = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
        *daddr4 = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
        *sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    } else if (family == AF_INET6) {
        bpf_core_read(saddr6, sizeof(*saddr6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(daddr6, sizeof(*daddr6), &sk->__sk_common.skc_v6_daddr);
        *sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        *dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    } else {
        return 0;
    }
    return 1;
}

// Helper: Fill process info
static __always_inline void fill_process_info(struct event_t *e) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Helper: Check rate limit before emitting event.
// Returns 1 if event should be emitted, 0 if rate limited.
//
// Two-tier gating:
//   1. Per-CPU windowed limiter (10K/sec/CPU) — preemption-safe RMW, no atomics.
//      Handles single-core bursts efficiently.
//   2. Global atomic limiter (200K/sec system-wide) — __sync_fetch_and_add on
//      a shared counter. Prevents an attacker from multiplying the effective
//      rate by NR_CPUS via NIC multi-queue / RPS packet steering.
//
// Both limiters use the same 1-second sliding windows.
static __always_inline int check_rate_limit(void) {
    u32 key = 0;
    struct rate_limit_state *state = bpf_map_lookup_elem(&rate_limiter, &key);
    if (!state) {
        return 1;
    }
    
    u64 now = bpf_ktime_get_ns();
    u64 window_start = state->window_start;
    int per_cpu_ok = 1;
    
    // --- Tier 1: Per-CPU rate limit ---
    if (window_start == 0) {
        state->window_start = now;
        state->event_count = 1;
    } else if (now - window_start >= RATE_LIMIT_WINDOW_NS) {
        state->window_start = now;
        state->event_count = 1;
    } else {
        state->event_count++;
        if (state->event_count >= RATE_LIMIT_EVENTS_PER_SEC) {
            state->dropped_count++;
            per_cpu_ok = 0;
        }
    }
    
    if (!per_cpu_ok)
        return 0;
    
    // --- Tier 2: Global cross-CPU rate limit ---
    // Uses atomic fetch-and-add on a shared counter. Window reset is racy
    // (multiple CPUs may reset concurrently) but error is bounded to ±1 window
    // and the counter never overflows the limit by more than NR_CPUS events.
    {
        struct global_rate_state *g = bpf_map_lookup_elem(&global_rate_limiter, &key);
        if (g) {
            if (now - g->window_start >= RATE_LIMIT_WINDOW_NS) {
                g->window_start = now;
                g->event_count = 0;
            }
            u64 old = __sync_fetch_and_add(&g->event_count, 1);
            if (old >= GLOBAL_RATE_LIMIT_EVENTS_PER_SEC) {
                state->dropped_count++;
                return 0;
            }
        }
    }
    
    return 1;
}


#endif // KERNELEYE_TRAFFIC_HELPERS_H
