// traffic_tc.h implements non-dropping TC ingress and egress bandwidth
// accounting for per-IP, ICMP, IPv6, and per-service-port counters.
#ifndef KERNELEYE_TRAFFIC_TC_H
#define KERNELEYE_TRAFFIC_TC_H

#include "traffic_helpers.h"

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


#endif // KERNELEYE_TRAFFIC_TC_H
