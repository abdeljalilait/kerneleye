// traffic_common.h defines shared traffic-probe includes, constants, packet
// header structs, and the userspace-facing event_t layout.
#ifndef KERNELEYE_TRAFFIC_COMMON_H
#define KERNELEYE_TRAFFIC_COMMON_H


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>


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

#endif // KERNELEYE_TRAFFIC_COMMON_H
