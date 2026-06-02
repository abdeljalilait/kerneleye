// traffic_udp.h implements UDP receive monitoring for connected UDP sockets
// and emits normalized connection events to the shared ring buffer.
#ifndef KERNELEYE_TRAFFIC_UDP_H
#define KERNELEYE_TRAFFIC_UDP_H

#include "traffic_helpers.h"

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
    init_event(e);

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


#endif // KERNELEYE_TRAFFIC_UDP_H
