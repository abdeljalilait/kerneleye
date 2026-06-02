// SPDX-License-Identifier: GPL-2.0
// traffic_probe.c is the single bpf2go entrypoint that assembles the traffic
// monitoring modules into one eBPF object.
// eBPF traffic probe for KernelEye network monitoring
// Requires kernel 5.4+ with CO-RE support

#include "traffic_common.h"
#include "traffic_maps.h"
#include "traffic_helpers.h"
#include "traffic_tcp.h"
#include "traffic_udp.h"
#include "traffic_tc.h"

char __license[] SEC("license") = "GPL";

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
// 6. Event Initialization: Ring buffer records are zeroed before submission
//    to avoid leaking stale bytes through struct padding or inactive unions
//
// Recommended mitigations:
// - Run agent as dedicated user with minimal privileges beyond CAP_BPF, CAP_NET_ADMIN
// - Use BPF LSM or seccomp to restrict which processes can access maps
// - Implement userspace filtering before exposing data to dashboards/APIs
// - Consider encrypting sensitive fields before storing/transmitting
