// traffic_maps.h declares all BPF maps plus their shared key and value structs
// for connection events, rate limiting, SYN tracking, and bandwidth counters.
#ifndef KERNELEYE_TRAFFIC_MAPS_H
#define KERNELEYE_TRAFFIC_MAPS_H

#include "traffic_common.h"

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

#endif // KERNELEYE_TRAFFIC_MAPS_H
