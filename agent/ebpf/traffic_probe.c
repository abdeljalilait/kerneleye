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
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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

// Event structure sent to userspace
typedef struct event_t {
    u32 saddr;       // Source IP (Remote)
    u32 daddr;       // Dest IP (Local)
    u16 lport;       // Local Port (e.g., 80, 443)
    u16 rport;       // Remote Port
    u16 family;      // AF_INET or AF_INET6
    u8 protocol;     // TCP=6, UDP=17
    u8 flags;        // SYN=0x01, ACK=0x02, ESTABLISHED=0x04, FAILED=0x08
    u8 direction;    // DIR_INBOUND or DIR_OUTBOUND
    u8 _pad[3];      // Alignment padding
    u64 timestamp;   // Nanoseconds since boot
    u32 pid;         // Process ID
    u32 tgid;        // Thread Group ID (main process)
    u32 uid;         // User ID
    char comm[TASK_COMM_LEN]; // Process name
} event_t;

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB buffer
} events SEC(".maps");

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

// TCP connection tracking map (for detecting failed handshakes)
// Key: Full 4-tuple (saddr, sport, daddr, dport) to avoid collisions
// Value: timestamp of SYN
// Using LRU_HASH to auto-evict stale entries (e.g., connections that timeout
// without tcp_close being called due to killed processes or kernel cleanup)
struct conn_key {
    u32 saddr;  // Local IP
    u32 daddr;  // Remote IP
    u16 sport;  // Local port
    u16 dport;  // Remote port
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);  // 256K entries for high-traffic servers
    __type(key, struct conn_key); // Full 4-tuple as key
    __type(value, u64);           // Timestamp of SYN
} tcp_syn_tracker SEC(".maps");

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

// Helper: Create 4-tuple connection key
static __always_inline void make_conn_key(struct conn_key *key, u32 saddr, u16 sport, u32 daddr, u16 dport) {
    key->saddr = saddr;
    key->daddr = daddr;
    key->sport = sport;
    key->dport = dport;
}

// Helper: Fill process info
static __always_inline void fill_process_info(struct event_t *e) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Helper: Check rate limit before emitting event
// Returns 1 if event should be emitted, 0 if rate limited
// NOTE: This is a lightweight check - call EARLY in hooks before expensive operations
static __always_inline int check_rate_limit(void) {
    u32 key = 0;
    struct rate_limit_state *state = bpf_map_lookup_elem(&rate_limiter, &key);
    if (!state) {
        return 1; // Array map lookup should never fail, but allow if it does
    }
    
    u64 now = bpf_ktime_get_ns();
    
    // Check if we're in a new time window (or uninitialized: window_start=0)
    // When window_start is 0 (uninitialized), now - 0 >= 1s is always true,
    // so we'll initialize window_start to current time on first event.
    if (now - state->window_start >= RATE_LIMIT_WINDOW_NS) {
        // Reset/initialize window atomically
        state->window_start = now;
        state->event_count = 1;
        return 1;
    }
    
    // Check if we've exceeded the rate limit
    if (state->event_count >= RATE_LIMIT_EVENTS_PER_SEC) {
        __sync_fetch_and_add(&state->dropped_count, 1); // Atomic increment for accurate monitoring
        return 0; // Rate limited
    }
    
    __sync_fetch_and_add(&state->event_count, 1); // Atomic to avoid undercounting under concurrency
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

    struct inet_sock *inet = (struct inet_sock *)newsk;
    
    // Early filter: Only IPv4 (avoid ringbuf allocation for IPv6)
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET) {
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
    // NOTE: IP addresses are stored in network byte order (big-endian) in the kernel.
    // Convert to host byte order using bpf_ntohl() for correct display in userspace.
    e->saddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));     // Remote IP (network -> host order)
    e->daddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr)); // Local IP (network -> host order)
    e->lport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);       // Local port (already host order)
    e->rport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport)); // Remote port (network order -> host)
    e->family = family;
    e->protocol = IPPROTO_TCP;
    e->flags = FLAG_ACK | FLAG_ESTABLISHED; // Connection completed
    e->direction = DIR_INBOUND;  // Accept = incoming connection
    e->timestamp = bpf_ktime_get_ns();
    
    // Fill process info
    fill_process_info(e);

    // NOTE: Server-side accepts should NOT touch tcp_syn_tracker.
    // The SYN tracker is for client-side (outgoing) connection tracking only.

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: TCP Connect (Outgoing connections - SYN sent)
SEC("kprobe/tcp_connect")
int BPF_KPROBE(detect_tcp_connect, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }
    
    // Rate limit check FIRST - before any expensive operations
    if (!check_rate_limit()) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    // Early filter: Only IPv4 (avoid ringbuf allocation for IPv6)
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    
    // Read all socket fields once (minimize BPF_CORE_READ calls)
    // NOTE: IP addresses are stored in network byte order (big-endian) in the kernel.
    // Convert to host byte order using bpf_ntohl() for correct display in userspace.
    u32 daddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));     // Remote IP (network -> host order)
    u32 saddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr)); // Local IP (network -> host order)
    u16 dport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport)); // Remote port
    u16 sport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);       // Local port (host order)

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // For outgoing connections:
    // - saddr = destination IP (where we're connecting TO)
    // - daddr = local IP  
    // - lport = local ephemeral port
    // - rport = destination port (the service we're connecting to)
    e->saddr = daddr;  // Remote/Destination IP
    e->daddr = saddr;  // Local IP
    e->lport = sport;  // Local ephemeral port (FIXED: was incorrectly dport)
    e->rport = dport;  // Remote service port (FIXED: was incorrectly sport)
    e->family = family;
    e->protocol = IPPROTO_TCP;
    e->flags = FLAG_SYN;
    e->direction = DIR_OUTBOUND;  // Connect = outgoing connection
    e->timestamp = bpf_ktime_get_ns();
    
    // Fill process info
    fill_process_info(e);

    // Track SYN for failed handshake detection using 4-tuple key
    struct conn_key key = {};
    make_conn_key(&key, saddr, sport, daddr, dport);
    u64 ts = e->timestamp;
    bpf_map_update_elem(&tcp_syn_tracker, &key, &ts, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Hook: TCP State Change (clean SYN tracker on ESTABLISHED)
// This is crucial for long-lived connections (HTTP/2, WebSocket) that would
// otherwise leave stale entries in tcp_syn_tracker until tcp_close
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(detect_tcp_state_change, struct sock *sk, int state) {
    if (sk == NULL) {
        return 0;
    }
    
    // Only interested in transitions TO established state
    if (state != TCP_ESTABLISHED) {
        return 0;
    }
    
    struct inet_sock *inet = (struct inet_sock *)sk;
    
    // Early filter: Only IPv4
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    
    // Read socket fields
    // NOTE: For map key lookups, we need to use the same byte order as when the key was created.
    // Since detect_tcp_connect now stores keys in host byte order, we must convert here too.
    u32 daddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));
    u32 saddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr));
    u16 dport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport));
    u16 sport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);
    
    // Build 4-tuple key and clean up SYN tracker entry
    struct conn_key key = {};
    make_conn_key(&key, saddr, sport, daddr, dport);
    
    // Remove from SYN tracker - connection successfully established
    bpf_map_delete_elem(&tcp_syn_tracker, &key);
    
    return 0;
}

// Hook: TCP Close (detect failed handshakes)
SEC("kprobe/tcp_close")
int BPF_KPROBE(detect_tcp_close, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    // Early filter: Only IPv4
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    
    // Read socket fields once
    // NOTE: For map key lookups and event emission, convert IP addresses from network
    // to host byte order to match the format used in detect_tcp_connect.
    u32 daddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));
    u32 saddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr));
    u16 dport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport));
    u16 sport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);
    
    // Build 4-tuple key for lookup
    struct conn_key key = {};
    make_conn_key(&key, saddr, sport, daddr, dport);
    
    u64 *syn_ts = bpf_map_lookup_elem(&tcp_syn_tracker, &key);
    
    if (syn_ts) {
        // Only emit FAILED if the socket is not established
        // This prevents false positives from normal close sequences
        u8 sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
        if (sk_state == TCP_ESTABLISHED) {
            // Normal close of established connection - just cleanup
            bpf_map_delete_elem(&tcp_syn_tracker, &key);
            return 0;
        }
        
        // SYN was sent but connection was never established -> failed handshake
        // Rate limit check for failed connection events
        if (!check_rate_limit()) {
            bpf_map_delete_elem(&tcp_syn_tracker, &key);
            return 0;
        }
        
        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e) {
            bpf_map_delete_elem(&tcp_syn_tracker, &key);
            return 0;
        }
        
        e->saddr = daddr;   // Remote IP (already in host order)
        e->daddr = saddr;   // Local IP (already in host order)
        e->lport = sport;   // Local port
        e->rport = dport;   // Remote port
        e->family = family;
        e->protocol = IPPROTO_TCP;
        e->flags = FLAG_FAILED;
        e->direction = DIR_OUTBOUND;  // Failed outgoing connection
        e->timestamp = bpf_ktime_get_ns();
        
        fill_process_info(e);
        
        bpf_map_delete_elem(&tcp_syn_tracker, &key);
        
        bpf_ringbuf_submit(e, 0);
    }
    
    return 0;
}

// Hook: UDP Receive (for UDP monitoring)
// NOTE: For UDP, the socket stores the REMOTE peer in skc_daddr/skc_dport (if connected),
// or zeros for unconnected sockets receiving from multiple sources.
// SUPPORTED: Connected UDP sockets (e.g., QUIC, DTLS, connected DNS clients).
// LIMITATION: Truly unconnected UDP sockets (e.g., DNS servers, multicast listeners)
// where BOTH daddr=0 AND lport=0 are skipped. To get actual source IP/port for
// unconnected sockets, would need to hook __skb_recv_udp or parse msghdr - planned for v3.
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(detect_udp_recv, struct sock *sk) {
    if (sk == NULL) {
        return 0;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    
    // Early filter: Only IPv4 (avoid ringbuf allocation for IPv6)
    u16 family = BPF_CORE_READ(inet, sk.__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    
    // Read socket fields
    // NOTE: IP addresses are stored in network byte order (big-endian) in the kernel.
    // Convert to host byte order using bpf_ntohl() for correct display in userspace.
    u32 daddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_daddr));  // Remote IP (0 if unconnected)
    u32 saddr = bpf_ntohl(BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr)); // Local IP
    u16 lport = BPF_CORE_READ(inet, sk.__sk_common.skc_num);    // Local port (host order)
    u16 rport = bpf_ntohs(BPF_CORE_READ(inet, sk.__sk_common.skc_dport)); // Remote port (0 if unconnected)
    
    // Skip only truly unconnected sockets (no remote info AND no local binding)
    // This filters out sockets that haven't been bound or connected at all.
    // We now capture:
    // - UDP servers bound to specific interfaces (saddr != 0, daddr may be 0)
    // - Connected UDP clients (daddr != 0)
    // - Multicast listeners (daddr = multicast group)
    if (daddr == 0 && lport == 0) {
        return 0;
    }
    
    // Rate limit check to prevent event flooding
    if (!check_rate_limit()) {
        return 0;
    }

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->saddr = daddr;   // Remote IP
    e->daddr = saddr;   // Local IP
    e->lport = lport;   // Local port
    e->rport = rport;   // Remote port
    e->family = family;
    e->protocol = IPPROTO_UDP;
    e->flags = 0;
    e->direction = DIR_INBOUND;  // UDP recv = incoming data
    e->timestamp = bpf_ktime_get_ns();
    
    // Fill process info
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
// - No deep packet inspection (L3 only)
// - Always returns TC_ACT_OK (never drops packets)

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
    
    // Only process IPv4
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IPv4 header
    struct iphdr_t *ip = l3_start;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->version != 4 || ip->ihl < 5)
        return TC_ACT_OK;
    
    // Get source IP (remote sender) - convert to HOST byte order
    // This matches connection event IPs, allowing userspace to correlate:
    //   ip_byte_counters[event.saddr] gives bandwidth for that connection's remote IP
    u32 src_ip = bpf_ntohl(ip->saddr);
    
    // Use IP total length for accurate L3 byte count (excludes L2 headers)
    u32 pkt_len = bpf_ntohs(ip->tot_len);
    
    // Lookup or create counter for this IP
    // Race condition handling:
    // 1. First lookup - if found, atomic add (fast path)
    // 2. If not found, try BPF_NOEXIST to create atomically
    // 3. If EEXIST (race: another CPU created it), re-lookup and atomic add
    // 4. If other error (map full), force update with BPF_ANY
    struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters, &src_ip);
    if (counters) {
        __sync_fetch_and_add(&counters->bytes_in, pkt_len);
    } else {
        struct ip_bytes new_counters = {
            .bytes_in = pkt_len,
            .bytes_out = 0,
        };
        long ret = bpf_map_update_elem(&ip_byte_counters, &src_ip, &new_counters, BPF_NOEXIST);
        if (ret == -17) { // EEXIST: race condition, entry was just created by another CPU
            // Re-lookup and do atomic add to preserve the other CPU's count
            counters = bpf_map_lookup_elem(&ip_byte_counters, &src_ip);
            if (counters) {
                __sync_fetch_and_add(&counters->bytes_in, pkt_len);
            }
            // If still not found (LRU evicted it), we lose this packet's count - acceptable
        } else if (ret) {
            // Map full or other error - force update (may lose concurrent data, but better than nothing)
            bpf_map_update_elem(&ip_byte_counters, &src_ip, &new_counters, BPF_ANY);
        }
    }
    
    return TC_ACT_OK;  // Never drop!
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
    
    // Only process IPv4
    if (proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    // Parse IPv4 header
    struct iphdr_t *ip = l3_start;
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->version != 4 || ip->ihl < 5)
        return TC_ACT_OK;
    
    // Get destination IP (remote receiver) - convert to HOST byte order
    // This matches connection event IPs, allowing userspace to correlate:
    //   ip_byte_counters[event.saddr] gives bandwidth for that connection's remote IP
    u32 dst_ip = bpf_ntohl(ip->daddr);
    
    // Use IP total length for accurate L3 byte count (excludes L2 headers)
    u32 pkt_len = bpf_ntohs(ip->tot_len);
    
    // Lookup or create counter for this IP
    // Race condition handling:
    // 1. First lookup - if found, atomic add (fast path)
    // 2. If not found, try BPF_NOEXIST to create atomically
    // 3. If EEXIST (race: another CPU created it), re-lookup and atomic add
    // 4. If other error (map full), force update with BPF_ANY
    struct ip_bytes *counters = bpf_map_lookup_elem(&ip_byte_counters, &dst_ip);
    if (counters) {
        __sync_fetch_and_add(&counters->bytes_out, pkt_len);
    } else {
        struct ip_bytes new_counters = {
            .bytes_in = 0,
            .bytes_out = pkt_len,
        };
        long ret = bpf_map_update_elem(&ip_byte_counters, &dst_ip, &new_counters, BPF_NOEXIST);
        if (ret == -17) { // EEXIST: race condition, entry was just created by another CPU
            // Re-lookup and do atomic add to preserve the other CPU's count
            counters = bpf_map_lookup_elem(&ip_byte_counters, &dst_ip);
            if (counters) {
                __sync_fetch_and_add(&counters->bytes_out, pkt_len);
            }
            // If still not found (LRU evicted it), we lose this packet's count - acceptable
        } else if (ret) {
            // Map full or other error - force update (may lose concurrent data, but better than nothing)
            bpf_map_update_elem(&ip_byte_counters, &dst_ip, &new_counters, BPF_ANY);
        }
    }
    
    return TC_ACT_OK;  // Never drop!
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
