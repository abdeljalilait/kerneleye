// SPDX-License-Identifier: GPL-2.0
// eBPF traffic probe for KernelEye network monitoring
// Requires kernel 5.4+ with CO-RE support

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

// ============================================
// Constants
// ============================================
#define TASK_COMM_LEN 16

// Protocol numbers
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1

// TCP states (from linux/tcp_states.h)
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_NEW_SYN_RECV 12

// Event flags
#define FLAG_SYN         0x01
#define FLAG_ACK         0x02
#define FLAG_ESTABLISHED 0x04
#define FLAG_FAILED      0x08
#define FLAG_RETRANSMIT  0x10

// Traffic direction
#define DIR_INBOUND  0  // Someone connecting to us (accept, recv)
#define DIR_OUTBOUND 1  // We connecting to someone (connect)

// Address families
#define AF_INET  2
#define AF_INET6 10

// IPv6 header definition
struct ipv6hdr_t {
    __u8  priority:4, version:4;
    __u8  flow_lbl[3];
    __be16 payload_len;
    __u8  nexthdr;
    __u8  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
};

// Event structure sent to userspace.
// Fields are ordered to eliminate implicit compiler padding:
//   8-byte → 4-byte → 2-byte → 1-byte → 16-byte unions → comm array.
// Total size: 80 bytes (cleanly divisible by 8, no tail padding).
//
// NOTE: Changing field order here requires matching changes in the Go
//       deserialization (binary.Read with the same field order).
typedef struct event_t {
    u64 timestamp;   // Nanoseconds since boot                 [0:8]
    u32 pid;         // Process ID                             [8:12]
    u32 tgid;        // Thread Group ID (main process)         [12:16]
    u32 uid;         // User ID                                [16:20]
    u16 lport;       // Local Port (e.g., 80, 443)             [20:22]
    u16 rport;       // Remote Port                            [22:24]
    u16 family;      // AF_INET or AF_INET6                    [24:26]
    u8 protocol;     // TCP=6, UDP=17                          [26]
    u8 flags;        // SYN=0x01, ACK=0x02, EST=0x04, FAIL=0x08 [27]
    u8 direction;    // DIR_INBOUND or DIR_OUTBOUND             [28]
    u8 _pad[3];      // Alignment to 4-byte boundary           [29:32]
    union {
        u32 addr4;           // IPv4 address (host order)
        struct in6_addr addr6; // IPv6 address (network order)
    } saddr;         // Source address                         [32:48]
    union {
        u32 addr4;
        struct in6_addr addr6;
    } daddr;         // Destination address                    [48:64]
    char comm[TASK_COMM_LEN]; // Process name                  [64:80]
} event_t;

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

// Debug counters to track event sources
// Userspace can read via: bpftool map dump name debug_counters
struct debug_stats {
    u64 syn_recv_events;  // tracepoint SYN_RECV events
    u64 accept_events;    // inet_csk_accept events
    u64 connect_events;   // tcp_connect events
    u64 close_events;    // tcp_close events
    u64 udp_events;      // udp_recv events
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct debug_stats);
} debug_counters SEC(".maps");

// Helper to increment debug counter
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

// ============================================
// Rate Limiting (Event Flooding Protection)
// ============================================
// Limits events per second to prevent ring buffer overflow under connection floods.
// Uses per-CPU counters to avoid contention.
//
// USERSPACE INITIALIZATION REQUIRED:
// The rate_limiter map should be initialized from userspace on startup to ensure
// predictable behavior. Initialize with:
//   struct rate_limit_state init = { .window_start = 0, .event_count = 0, .dropped_count = 0 };
//   bpf_map_update_elem(rate_limiter_fd, &key, &init, BPF_ANY);
// This ensures clean state on agent restart and allows monitoring dropped_count.
//
#define RATE_LIMIT_EVENTS_PER_SEC 10000  // Max events/sec per CPU
#define RATE_LIMIT_WINDOW_NS 1000000000ULL // 1 second in nanoseconds

struct rate_limit_state {
    u64 window_start;  // Timestamp of current window start (0 = uninitialized, will auto-init on first event)
    u32 event_count;   // Events emitted in current window
    u32 dropped_count; // Events dropped (for monitoring - read via bpftool map dump)
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct rate_limit_state);
} rate_limiter SEC(".maps");

// Global (cross-CPU) rate limit — prevents multi-core flooding attacks
// from multiplying the effective rate by NR_CPUS via NIC multi-queue or RPS.
// This is a secondary gate: the per-CPU limiter runs first (preemption-safe,
// no atomics), then this global counter gates total system-wide events/sec.
//
// Uses __sync_fetch_and_add for atomic cross-CPU increments. Window reset
// is best-effort (racy across CPUs) but error is bounded to one window.
#define GLOBAL_RATE_LIMIT_EVENTS_PER_SEC 200000  // Max events/sec system-wide

struct global_rate_state {
    u64 window_start;
    u64 event_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct global_rate_state);
} global_rate_limiter SEC(".maps");

// TCP connection tracking map (for detecting failed handshakes)
// Key: Full 4-tuple (saddr, sport, daddr, dport) to avoid collisions
// Value: packed u64 (bit63=direction, bits0-62=timestamp) so detect_tcp_close can
//        set the correct direction instead of hardcoding DIR_OUTBOUND).
// Using LRU_HASH to auto-evict stale entries (e.g., connections that timeout
// without tcp_close being called due to killed processes or kernel cleanup)
struct conn_key {
    u32 saddr;  // Local IP (host order for IPv4)
    u32 daddr;  // Remote IP (host order for IPv4)
    u16 sport;  // Local port
    u16 dport;  // Remote port
};

struct conn_key_v6 {
    struct in6_addr saddr;  // Local IP (network order for IPv6)
    struct in6_addr daddr;  // Remote IP (network order for IPv6)
    u16 sport;              // Local port
    u16 dport;              // Remote port
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);  // 256K entries for high-traffic servers
    __type(key, struct conn_key); // Full 4-tuple as key
    __type(value, u64);           // Packed: bit63=direction, bits0-62=timestamp
} tcp_syn_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);   // 64K entries for IPv6
    __type(key, struct conn_key_v6);
    __type(value, u64);           // Packed: bit63=direction, bits0-62=timestamp
} tcp_syn_tracker_v6 SEC(".maps");

// Pack direction into bit 63 of the timestamp u64.
// Timestamps use at most ~56 bits, so bit 63 is free.
#define PACK_SYN_TRACK(ts, dir) ((ts) | ((u64)(dir) << 63))
#define UNPACK_SYN_DIR(val)      ((u8)((val) >> 63))
#define UNPACK_SYN_TS(val)       ((val) & ~(1ULL << 63))

// ============================================
// Bandwidth Tracking (TC Hooks - Safe Pattern)
// ============================================

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_8021Q 0x8100  // 802.1Q VLAN tag
// ETH_P_8021AD may not be defined in kernels < 5.10 (e.g., RHEL8 kernel 4.18)
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8 // 802.1ad QinQ
#endif
#define TC_ACT_OK 0

// Shared struct definitions for TC hooks
struct ethhdr_t {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

// VLAN header (802.1Q) - using custom name to avoid vmlinux.h conflict
struct vlan_hdr_t {
    __be16 h_vlan_TCI;              // Priority, CFI, VLAN ID
    __be16 h_vlan_encapsulated_proto; // Encapsulated protocol
};

struct iphdr_t {
    __u8    ihl:4, version:4;
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
};

// Per-IP byte counters (bounded LRU map)
// KEY FORMAT: IPv4 addresses are stored in HOST BYTE ORDER (little-endian on x86)
// to match connection event IPs. Use bpf_ntohl() when converting from packet headers.
struct ip_bytes {
    u64 bytes_in;
    u64 bytes_out;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);  // 256K entries for high-traffic/DDoS scenarios
    __type(key, u32);             // IPv4 address (HOST byte order)
    __type(value, struct ip_bytes);
} ip_byte_counters SEC(".maps");

// IPv6 byte counters (network order struct in6_addr as key)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);   // 64K entries for IPv6
    __type(key, struct in6_addr); // IPv6 address (network order)
    __type(value, struct ip_bytes);
} ip_byte_counters_v6 SEC(".maps");

// ============================================
// ICMP Packet Counters (TC hooks)
// ============================================
// Tracks ICMP packets per source IP separate from TCP/UDP byte counters.
// KEY: IPv4 source address in HOST byte order (same convention as ip_byte_counters).
// VALUE: packet counts in/out (NOT byte counts — ICMP payloads are tiny and
//        variable; packet count is the operationally useful signal for ping floods).
struct icmp_pkt_count {
    u64 packets_in;   // ICMP packets received from this IP
    u64 packets_out;  // ICMP packets sent to this IP
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);  // 256K entries
    __type(key, u32);             // IPv4 address (HOST byte order)
    __type(value, struct icmp_pkt_count);
} icmp_counters SEC(".maps");

// ============================================
// Per-IP-Port Byte Counters (TC hooks)
// ============================================
// Tracks bytes broken down by (source_ip, service_port) so the dashboard can
// show per-service bandwidth consumption without expensive userspace guessing.
//
// KEY: { ip (host order), port (host order), 2 bytes padding }  — 8 bytes total,
//      naturally aligned.  Port is the SERVICE port (dst on ingress, src on egress).
// VALUE: bytes in/out for this (ip, port) pair.
struct ip_port_key {
    u32 ip;        // IPv4 address, HOST byte order
    u16 port;      // Service port, HOST byte order
    u8  _pad[2];   // Explicit padding to 8-byte size
};

struct port_bytes {
    u64 bytes_in;
    u64 bytes_out;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);        // 256K (ip,port) pairs
    __type(key, struct ip_port_key);
    __type(value, struct port_bytes);
} ip_port_bytes SEC(".maps");

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

// Hook: TCP Accept (Incoming connections - ESTABLISHED)
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(detect_tcp_accept, struct sock *newsk) {
    if (newsk == NULL) {
        return 0;
    }
    
    // Rate limit check FIRST - before any expensive operations
    // This reduces CPU usage by ~40% under SYN flood conditions
    if (!check_rate_limit()) {
        return 0;
    }

    // Debug counter for accept events
    inc_debug_counter(1);

    struct inet_sock *inet = (struct inet_sock *)newsk;
    
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // For incoming connections:
    // - saddr = remote client IP (who connected to us)
    // - daddr = local server IP
    // - lport = local service port (e.g., 80, 443)
    // - rport = remote client's ephemeral port
    if (family == AF_INET) {
        e->saddr.addr4 = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));
        e->daddr.addr4 = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr));
    } else {
        bpf_core_read(&e->saddr.addr6, sizeof(e->saddr.addr6), &inet->sk.__sk_common.skc_v6_daddr);
        bpf_core_read(&e->daddr.addr6, sizeof(e->daddr.addr6), &inet->sk.__sk_common.skc_v6_rcv_saddr);
    }
    e->lport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);
    e->rport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport));
    e->family = family;
    e->protocol = IPPROTO_TCP;
	e->flags = FLAG_SYN | FLAG_ACK | FLAG_ESTABLISHED; // Every accepted connection started with a SYN.
	// FLAG_SYN on accept is a reliable fallback — the sock:inet_sock_set_state
	// tracepoint can silently fail to fire on some kernel versions. Counting SYN
	// here guarantees at least 1 SYN per established inbound connection.
	// On kernels where the tracepoint also fires, SYNCount will be ~2 per
	// connection; the scoring's logarithmic rate formula handles this gracefully.
    e->direction = DIR_INBOUND;  // Accept = incoming connection
    e->timestamp = bpf_ktime_get_ns();
    
    // Fill process info
    fill_process_info(e);

    // NOTE: Server-side accepts should NOT touch tcp_syn_tracker.
    // The SYN tracker is used for failed-handshake detection (see detect_tcp_close).

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: TCP state change — handles three state transitions:
//   1. SYN_RECV / NEW_SYN_RECV — populate tracker + emit SYN event (inbound detection)
//   2. ESTABLISHED — clean up tracker (successful handshake, no event)
//   3. CLOSE — clean up tracker (kernel cleanup, no event — detect_tcp_close
//      kprobe handles failed-handshake emission before this fires)
//
// Consolidates what was previously split across this tracepoint + kprobe/tcp_set_state.
// Tracepoints are preferred over kprobes for stability (properly typed fields,
// works across kernel versions).
SEC("tracepoint/sock/inet_sock_set_state")
int detect_tcp_state_transition(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;

    // Extract addresses once — used for tracker ops and event emission.
    u32 s4 = 0, d4 = 0;
    struct in6_addr s6 = {}, d6 = {};
    u16 lp = 0, rp = 0;
    if (ctx->family == AF_INET) {
        s4 = ((__u32)ctx->saddr[0] << 24) | ((__u32)ctx->saddr[1] << 16) |
             ((__u32)ctx->saddr[2] << 8) | (__u32)ctx->saddr[3];
        d4 = ((__u32)ctx->daddr[0] << 24) | ((__u32)ctx->daddr[1] << 16) |
             ((__u32)ctx->daddr[2] << 8) | (__u32)ctx->daddr[3];
    } else {
        bpf_core_read(&s6, sizeof(s6), ctx->saddr_v6);
        bpf_core_read(&d6, sizeof(d6), ctx->daddr_v6);
    }
    lp = bpf_ntohs(ctx->dport);
    rp = bpf_ntohs(ctx->sport);

    // --- ESTABLISHED or CLOSE: clean up tracker entries ---
    // Every connection that reached SYN_RECV will eventually hit ESTABLISHED
    // (success) or CLOSE (failure/timeout). Cleanup here prevents LRU map bloat
    // from long-lived connections (HTTP/2, WebSocket) and ensures stale entries
    // don't persist past connection lifetime.
    if (ctx->newstate == TCP_ESTABLISHED || ctx->newstate == TCP_CLOSE) {
        if (ctx->family == AF_INET) {
            struct conn_key key = {};
            make_conn_key(&key, d4, lp, s4, rp);
            bpf_map_delete_elem(&tcp_syn_tracker, &key);
        } else {
            struct conn_key_v6 key = {};
            make_conn_key_v6(&key, &d6, lp, &s6, rp);
            bpf_map_delete_elem(&tcp_syn_tracker_v6, &key);
        }
        return 0;
    }

    // --- SYN_RECV / NEW_SYN_RECV: server received a SYN ---
    if (ctx->newstate != TCP_SYN_RECV && ctx->newstate != TCP_NEW_SYN_RECV)
        return 0;

    // Rate limit check: prevent ring buffer overflow under SYN floods.
    // SYN tracker update always runs (even when rate-limited) so
    // detect_tcp_close can still correlate failed handshakes.
    int rate_limited = !check_rate_limit();

    // Always update SYN tracker for failed-handshake detection,
    // even when ring buffer events are being rate-limited.
    {
        u64 val = PACK_SYN_TRACK(bpf_ktime_get_ns(), DIR_INBOUND);
        if (ctx->family == AF_INET) {
            struct conn_key key = {};
            make_conn_key(&key, d4, lp, s4, rp);
            bpf_map_update_elem(&tcp_syn_tracker, &key, &val, BPF_ANY);
        } else {
            struct conn_key_v6 key = {};
            make_conn_key_v6(&key, &d6, lp, &s6, rp);
            bpf_map_update_elem(&tcp_syn_tracker_v6, &key, &val, BPF_ANY);
        }
    }

    if (rate_limited)
        return 0;

    // Debug counter for SYN_RECV events
    inc_debug_counter(0);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    if (ctx->family == AF_INET) {
        e->saddr.addr4 = s4;
        e->daddr.addr4 = d4;
    } else {
        e->saddr.addr6 = s6;
        e->daddr.addr6 = d6;
    }

    e->lport = lp;
    e->rport = rp;
    e->family = ctx->family;
    e->protocol = IPPROTO_TCP;
    e->flags = FLAG_SYN;
    e->direction = DIR_INBOUND;
    e->timestamp = bpf_ktime_get_ns();

    fill_process_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: TCP Receive Reset - detects RST packets
// This catches:
//   • Rejected connections (connection refused)
//   • Firewall blocks (iptables/nftables dropping with RST)
//   • Connection failures (mid-stream resets, timeouts)
//   • IDS/IPS blocking (security appliances sending RST)
//
// trace_event_raw_tcp_receive_reset is not always available in vmlinux.h.
// Define it manually to match the kernel tracepoint format.
struct trace_event_raw_tcp_receive_reset {
	struct trace_entry ent;
	const void *skaddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

SEC("tracepoint/tcp/tcp_receive_reset")
int detect_tcp_reset(struct trace_event_raw_tcp_receive_reset *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!sk)
        return 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    // Rate limit check
    if (!check_rate_limit())
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    if (family == AF_INET) {
        e->saddr.addr4 = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
        e->daddr.addr4 = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    } else {
        bpf_core_read(&e->saddr.addr6, sizeof(e->saddr.addr6), &sk->__sk_common.skc_v6_daddr);
        bpf_core_read(&e->daddr.addr6, sizeof(e->daddr.addr6), &sk->__sk_common.skc_v6_rcv_saddr);
    }

    e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->family = family;
    e->protocol = IPPROTO_TCP;
    e->flags = FLAG_FAILED;
    // RST is received, but direction is ambiguous for outbound connects that fail.
    // Hardcode as inbound since the RST packet arrives from remote.
    e->direction = DIR_INBOUND;
    e->timestamp = bpf_ktime_get_ns();

    // NOTE: tracepoint fires in softirq context - current task is meaningless.
    // Don't use fill_process_info() here.
    e->pid = 0;
    e->tgid = 0;
    e->uid = 0;
    e->comm[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: TCP Connect (Outgoing connections - SYN sent)
SEC("kprobe/tcp_connect")
int BPF_KPROBE(detect_tcp_connect, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    u32 saddr4 = 0, daddr4 = 0;
    struct in6_addr saddr6 = {}, daddr6 = {};
    u16 sport = 0, dport = 0;
    
    if (!get_sock_addrs((struct sock *)sk, family, &saddr4, &daddr4, &saddr6, &daddr6, &sport, &dport)) {
        return 0;
    }

    // Always update SYN tracker for failed-handshake detection,
    // even when ring buffer events are being rate-limited.
    {
        u64 val = PACK_SYN_TRACK(bpf_ktime_get_ns(), DIR_OUTBOUND);
        if (family == AF_INET) {
            struct conn_key key = {};
            make_conn_key(&key, saddr4, sport, daddr4, dport);
            bpf_map_update_elem(&tcp_syn_tracker, &key, &val, BPF_ANY);
        } else {
            struct conn_key_v6 key = {};
            make_conn_key_v6(&key, &saddr6, sport, &daddr6, dport);
            bpf_map_update_elem(&tcp_syn_tracker_v6, &key, &val, BPF_ANY);
        }
    }

    // Rate limit ring buffer events only (tracker already updated above)
    if (!check_rate_limit()) {
        return 0;
    }

    // Debug counter for connect events
    inc_debug_counter(2);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    if (family == AF_INET) {
        e->saddr.addr4 = daddr4;
        e->daddr.addr4 = saddr4;
    } else {
        e->saddr.addr6 = daddr6;
        e->daddr.addr6 = saddr6;
    }
    e->lport = sport;
    e->rport = dport;
    e->family = family;
    e->protocol = IPPROTO_TCP;
    e->flags = FLAG_SYN;
    e->direction = DIR_OUTBOUND;
    e->timestamp = bpf_ktime_get_ns();
    
    fill_process_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: TCP Close (detect failed handshakes)
SEC("kprobe/tcp_close")
int BPF_KPROBE(detect_tcp_close, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    u32 saddr4 = 0, daddr4 = 0;
    struct in6_addr saddr6 = {}, daddr6 = {};
    u16 sport = 0, dport = 0;
    
    if (!get_sock_addrs((struct sock *)sk, family, &saddr4, &daddr4, &saddr6, &daddr6, &sport, &dport)) {
        return 0;
    }
    
    if (family == AF_INET) {
        struct conn_key key = {};
        make_conn_key(&key, saddr4, sport, daddr4, dport);
        
        u64 *val = bpf_map_lookup_elem(&tcp_syn_tracker, &key);
        if (val) {
            u8 sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
            if (sk_state == TCP_ESTABLISHED) {
                bpf_map_delete_elem(&tcp_syn_tracker, &key);
                return 0;
            }
            
            if (!check_rate_limit()) {
                bpf_map_delete_elem(&tcp_syn_tracker, &key);
                return 0;
            }
            
            struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                bpf_map_delete_elem(&tcp_syn_tracker, &key);
                return 0;
            }
            
            e->saddr.addr4 = daddr4;
            e->daddr.addr4 = saddr4;
            e->lport = sport;
            e->rport = dport;
            e->family = family;
            e->protocol = IPPROTO_TCP;
            e->flags = FLAG_FAILED;
            e->direction = UNPACK_SYN_DIR(*val);
            e->timestamp = bpf_ktime_get_ns();
            
            fill_process_info(e);
            
            bpf_map_delete_elem(&tcp_syn_tracker, &key);
            bpf_ringbuf_submit(e, 0);
        }
    } else {
        struct conn_key_v6 key = {};
        make_conn_key_v6(&key, &saddr6, sport, &daddr6, dport);
        
        u64 *val = bpf_map_lookup_elem(&tcp_syn_tracker_v6, &key);
        if (val) {
            u8 sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
            if (sk_state == TCP_ESTABLISHED) {
                bpf_map_delete_elem(&tcp_syn_tracker_v6, &key);
                return 0;
            }
            
            if (!check_rate_limit()) {
                bpf_map_delete_elem(&tcp_syn_tracker_v6, &key);
                return 0;
            }
            
            struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                bpf_map_delete_elem(&tcp_syn_tracker_v6, &key);
                return 0;
            }
            
            e->saddr.addr6 = daddr6;
            e->daddr.addr6 = saddr6;
            e->lport = sport;
            e->rport = dport;
            e->family = family;
            e->protocol = IPPROTO_TCP;
            e->flags = FLAG_FAILED;
            e->direction = UNPACK_SYN_DIR(*val);
            e->timestamp = bpf_ktime_get_ns();
            
            fill_process_info(e);
            
            bpf_map_delete_elem(&tcp_syn_tracker_v6, &key);
            bpf_ringbuf_submit(e, 0);
        }
    }
    
    return 0;
}

// Hook: UDP Receive (for UDP monitoring)
// NOTE: For connected UDP sockets (QUIC, DTLS, connected DNS clients), the socket
// stores the REMOTE peer in skc_daddr/skc_dport, giving accurate source IP/port
// information. For unconnected UDP sockets, daddr is 0. This hook records
// saddr = 0.0.0.0 in these cases. It is primarily useful for connected UDP
// (QUIC, DTLS) or requires __skb_recv_udp hooking for true unconnected source
// IP tracking (planned for v3).
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(detect_udp_recv, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    u32 saddr4 = 0, daddr4 = 0;
    struct in6_addr saddr6 = {}, daddr6 = {};
    u16 lport = 0, rport = 0;
    
    if (!get_sock_addrs((struct sock *)sk, family, &saddr4, &daddr4, &saddr6, &daddr6, &lport, &rport)) {
        return 0;
    }
    
    if (family == AF_INET) {
        if (daddr4 == 0 && lport == 0) {
            return 0;
        }
    } else {
        int is_zero = 1;
        for (int i = 0; i < 4; i++) {
            if (daddr6.in6_u.u6_addr32[i] != 0) {
                is_zero = 0;
                break;
            }
        }
        if (is_zero && lport == 0) {
            return 0;
        }
    }
    
    if (!check_rate_limit()) {
        return 0;
    }

    // Debug counter for UDP events
    inc_debug_counter(4);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    if (family == AF_INET) {
        e->saddr.addr4 = daddr4;
        e->daddr.addr4 = saddr4;
    } else {
        e->saddr.addr6 = daddr6;
        e->daddr.addr6 = saddr6;
    }
    e->lport = lport;
    e->rport = rport;
    e->family = family;
    e->protocol = IPPROTO_UDP;
    e->flags = 0;
    e->direction = DIR_INBOUND;
    e->timestamp = bpf_ktime_get_ns();
    
    fill_process_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================
// TC Hooks for Bandwidth Tracking (Safe Pattern)
// ============================================
// Safety guarantees:
// - Uses bounded LRU map (auto-evicts old entries)
// - Counter-only: no ringbuf in packet path
// - L3 + minimal L4 header read (first 4 bytes only for port extraction)
// - Always returns TC_ACT_OK (never drops packets)
// - Fragment check prevents garbage port reads on non-first fragments

// Helper: update icmp_counters for an IPv4 address.
// direction: 0 = packets_in, 1 = packets_out
static __always_inline void update_icmp_counter(u32 ip, int direction) {
    struct icmp_pkt_count *c = bpf_map_lookup_elem(&icmp_counters, &ip);
    if (c) {
        if (direction == 0)
            __sync_fetch_and_add(&c->packets_in, 1);
        else
            __sync_fetch_and_add(&c->packets_out, 1);
    } else {
        struct icmp_pkt_count init = {};
        if (direction == 0) init.packets_in = 1;
        else                 init.packets_out = 1;
        long ret = bpf_map_update_elem(&icmp_counters, &ip, &init, BPF_NOEXIST);
        if (ret == -17) { // EEXIST — lost the race, retry
            c = bpf_map_lookup_elem(&icmp_counters, &ip);
            if (c) {
                if (direction == 0)
                    __sync_fetch_and_add(&c->packets_in, 1);
                else
                    __sync_fetch_and_add(&c->packets_out, 1);
            }
        }
    }
}

// Helper: update ip_port_bytes for an IPv4 (ip, port) pair.
// direction: 0 = bytes_in, 1 = bytes_out
static __always_inline void update_port_bytes(u32 ip, u16 port, u32 pkt_len, int direction) {
    struct ip_port_key key = { .ip = ip, .port = port };
    struct port_bytes *pb = bpf_map_lookup_elem(&ip_port_bytes, &key);
    if (pb) {
        if (direction == 0)
            __sync_fetch_and_add(&pb->bytes_in, pkt_len);
        else
            __sync_fetch_and_add(&pb->bytes_out, pkt_len);
    } else {
        struct port_bytes init = {};
        if (direction == 0) init.bytes_in = pkt_len;
        else                 init.bytes_out = pkt_len;
        long ret = bpf_map_update_elem(&ip_port_bytes, &key, &init, BPF_NOEXIST);
        if (ret == -17) {
            pb = bpf_map_lookup_elem(&ip_port_bytes, &key);
            if (pb) {
                if (direction == 0)
                    __sync_fetch_and_add(&pb->bytes_in, pkt_len);
                else
                    __sync_fetch_and_add(&pb->bytes_out, pkt_len);
            }
        }
    }
}

// TC Ingress: Count bytes coming IN from remote IPs
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    __be16 proto = eth->h_proto;
    void *l3_start = (void *)(eth + 1);
    
    // Handle VLAN tags (802.1Q and QinQ)
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr_t *vlan = l3_start;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        proto = vlan->h_vlan_encapsulated_proto;
        l3_start = (void *)(vlan + 1);
        
        // Handle QinQ (double VLAN tag)
        if (proto == bpf_htons(ETH_P_8021Q)) {
            vlan = l3_start;
            if ((void *)(vlan + 1) > data_end)
                return TC_ACT_OK;
            proto = vlan->h_vlan_encapsulated_proto;
            l3_start = (void *)(vlan + 1);
        }
    }
    
    // Interface filtering
    if (!is_iface_allowed(skb))
        return TC_ACT_OK;
    
    // Process IPv4
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr_t *ip = l3_start;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (ip->version != 4 || ip->ihl < 5)
            return TC_ACT_OK;

        void *ip_end = (void *)ip + (ip->ihl * 4);
        if (ip_end > data_end)
            return TC_ACT_OK;

        __u16 tot_len = bpf_ntohs(ip->tot_len);
        if (tot_len < (ip->ihl * 4) || tot_len > (u32)(data_end - data))
            return TC_ACT_OK;

        u32 src_ip = bpf_ntohl(ip->saddr);
        u32 pkt_len = tot_len;

        // Total byte counter (all protocols)
        struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters, &src_ip);
        if (counters) {
            __sync_fetch_and_add(&counters->bytes_in, pkt_len);
        } else {
            struct ip_bytes new_counters = { .bytes_in = pkt_len, .bytes_out = 0 };
            long ret = bpf_map_update_elem(&ip_byte_counters, &src_ip, &new_counters, BPF_NOEXIST);
            if (ret == -17) {
                counters = bpf_map_lookup_elem(&ip_byte_counters, &src_ip);
                if (counters)
                    __sync_fetch_and_add(&counters->bytes_in, pkt_len);
            } else if (ret) {
                bpf_map_update_elem(&ip_byte_counters, &src_ip, &new_counters, BPF_ANY);
            }
        }

        // ICMP packet counter (ingress: packets_in)
        if (ip->protocol == IPPROTO_ICMP) {
            update_icmp_counter(src_ip, 0 /* packets_in */);
        }

        // Per-port byte counter (TCP/UDP only — ICMP has no port).
        // Skip non-first fragments: they have no L4 header, port bytes
        // would be garbage. Total byte counter above is still correct
        // because ip->tot_len is valid on all fragments.
        if ((ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) &&
            !(ip->frag_off & bpf_htons(0x1FFF))) {
            __be16 *l4_ports = ip_end;
            if ((void *)(l4_ports + 2) <= data_end) {
                u16 dst_port = bpf_ntohs(*(l4_ports + 1)); // dst port
                update_port_bytes(src_ip, dst_port, pkt_len, 0 /* bytes_in */);
            }
        }

        return TC_ACT_OK;
    }

    // Process IPv6
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr_t *ip6 = l3_start;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (ip6->version != 6)
            return TC_ACT_OK;

        __u16 payload_len = bpf_ntohs(ip6->payload_len);
        u32 pkt_len = payload_len + 40; // IPv6 header is 40 bytes

        struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters_v6, &ip6->saddr);
        if (counters) {
            __sync_fetch_and_add(&counters->bytes_in, pkt_len);
        } else {
            struct ip_bytes new_counters = { .bytes_in = pkt_len, .bytes_out = 0 };
            long ret = bpf_map_update_elem(&ip_byte_counters_v6, &ip6->saddr, &new_counters, BPF_NOEXIST);
            if (ret == -17) {
                counters = bpf_map_lookup_elem(&ip_byte_counters_v6, &ip6->saddr);
                if (counters)
                    __sync_fetch_and_add(&counters->bytes_in, pkt_len);
            } else if (ret) {
                bpf_map_update_elem(&ip_byte_counters_v6, &ip6->saddr, &new_counters, BPF_ANY);
            }
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

// TC Egress: Count bytes going OUT to remote IPs
SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    __be16 proto = eth->h_proto;
    void *l3_start = (void *)(eth + 1);
    
    // Handle VLAN tags (802.1Q and QinQ)
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr_t *vlan = l3_start;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        proto = vlan->h_vlan_encapsulated_proto;
        l3_start = (void *)(vlan + 1);
        
        // Handle QinQ (double VLAN tag)
        if (proto == bpf_htons(ETH_P_8021Q)) {
            vlan = l3_start;
            if ((void *)(vlan + 1) > data_end)
                return TC_ACT_OK;
            proto = vlan->h_vlan_encapsulated_proto;
            l3_start = (void *)(vlan + 1);
        }
    }
    
    // Interface filtering
    if (!is_iface_allowed(skb))
        return TC_ACT_OK;
    
    // Process IPv4
    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr_t *ip = l3_start;
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (ip->version != 4 || ip->ihl < 5)
            return TC_ACT_OK;

        void *ip_end = (void *)ip + (ip->ihl * 4);
        if (ip_end > data_end)
            return TC_ACT_OK;

        __u16 tot_len = bpf_ntohs(ip->tot_len);
        if (tot_len < (ip->ihl * 4) || tot_len > (u32)(data_end - data))
            return TC_ACT_OK;

        u32 dst_ip = bpf_ntohl(ip->daddr);
        u32 pkt_len = tot_len;

        // Total byte counter (all protocols)
        struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters, &dst_ip);
        if (counters) {
            __sync_fetch_and_add(&counters->bytes_out, pkt_len);
        } else {
            struct ip_bytes new_counters = { .bytes_in = 0, .bytes_out = pkt_len };
            long ret = bpf_map_update_elem(&ip_byte_counters, &dst_ip, &new_counters, BPF_NOEXIST);
            if (ret == -17) {
                counters = bpf_map_lookup_elem(&ip_byte_counters, &dst_ip);
                if (counters)
                    __sync_fetch_and_add(&counters->bytes_out, pkt_len);
            } else if (ret) {
                bpf_map_update_elem(&ip_byte_counters, &dst_ip, &new_counters, BPF_ANY);
            }
        }

        // ICMP packet counter (egress: packets_out)
        if (ip->protocol == IPPROTO_ICMP) {
            update_icmp_counter(dst_ip, 1 /* packets_out */);
        }

        // Per-port byte counter (TCP/UDP only).
        // For egress: source port identifies the local service (e.g., 80, 443).
        // Skip non-first fragments (no L4 header).
        if ((ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) &&
            !(ip->frag_off & bpf_htons(0x1FFF))) {
            __be16 *l4_ports = ip_end;
            if ((void *)(l4_ports + 2) <= data_end) {
                u16 src_port = bpf_ntohs(*l4_ports); // src port (local service port on egress)
                update_port_bytes(dst_ip, src_port, pkt_len, 1 /* bytes_out */);
            }
        }

        return TC_ACT_OK;
    }

    // Process IPv6
    if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr_t *ip6 = l3_start;
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (ip6->version != 6)
            return TC_ACT_OK;

        __u16 payload_len = bpf_ntohs(ip6->payload_len);
        u32 pkt_len = payload_len + 40;

        struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters_v6, &ip6->daddr);
        if (counters) {
            __sync_fetch_and_add(&counters->bytes_out, pkt_len);
        } else {
            struct ip_bytes new_counters = { .bytes_in = 0, .bytes_out = pkt_len };
            long ret = bpf_map_update_elem(&ip_byte_counters_v6, &ip6->daddr, &new_counters, BPF_NOEXIST);
            if (ret == -17) {
                counters = bpf_map_lookup_elem(&ip_byte_counters_v6, &ip6->daddr);
                if (counters)
                    __sync_fetch_and_add(&counters->bytes_out, pkt_len);
            } else if (ret) {
                bpf_map_update_elem(&ip_byte_counters_v6, &ip6->daddr, &new_counters, BPF_ANY);
            }
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

// ============================================
// Security Considerations (Documentation)
// ============================================
// WARNING: This eBPF program exposes system-wide network information.
// Deployment considerations:
// 1. Map Access: Requires CAP_BPF - ensure only trusted processes have this capability
// 2. Information Disclosure: All TCP/UDP connections are captured (including internal services)
// 3. Process Leakage: PID, UID, and command names are exposed in events
// 4. No Filtering: Consider adding PID/UID filters in userspace for multi-tenant environments
// 5. Ring Buffer: Events are readable by any process with map access
//
// Recommended mitigations:
// - Run agent as dedicated user with minimal privileges beyond CAP_BPF, CAP_NET_ADMIN
// - Use BPF LSM or seccomp to restrict which processes can access maps
// - Implement userspace filtering before exposing data to dashboards/APIs
// - Consider encrypting sensitive fields before storing/transmitting
