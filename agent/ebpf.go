package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

// EBPFResources holds all eBPF-related resources for cleanup
type EBPFResources struct {
	Objects       *bpfObjects
	KpAccept      link.Link
	KpConnect     link.Link
	KpClose       link.Link
	KpUdpRecv     link.Link
	KpConnRequest link.Link // Inbound SYN detector (tracepoint)
	KpReset       link.Link // TCP RST detector (tracepoint)
	IngressFilter *netlink.BpfFilter
	EgressFilter  *netlink.BpfFilter
}

type inboundSynProbeStatus struct {
	TracepointDisabled bool
	ReducedMapCapacity bool
}

func markOptionalInboundSynProgramFromError(err error, status *inboundSynProbeStatus) bool {
	msg := err.Error()
	changed := false

	if !status.TracepointDisabled &&
		(strings.Contains(msg, "DetectTcpStateTransition") || strings.Contains(msg, "detect_tcp_state_transition")) {
		status.TracepointDisabled = true
		changed = true
	}

	return changed
}

func isBPFMapMemoryError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "map create") &&
		(strings.Contains(msg, "cannot allocate memory") || strings.Contains(msg, "not enough memory"))
}

func applyReducedMapCapacity(spec *ebpf.CollectionSpec) {
	reducedMaxEntries := map[string]uint32{
		"events":              1 << 22, // 4MB ring buffer
		"tcp_syn_tracker":     65536,
		"tcp_syn_tracker_v6":  16384,
		"ip_byte_counters":    65536,
		"ip_byte_counters_v6": 16384,
		"icmp_counters":       65536,
		"ip_port_bytes":       65536,
	}

	for name, maxEntries := range reducedMaxEntries {
		if mapSpec, ok := spec.Maps[name]; ok && mapSpec != nil && mapSpec.MaxEntries > maxEntries {
			mapSpec.MaxEntries = maxEntries
		}
	}
}

func loadBPFObjectsWithInboundSynFallback(objects *bpfObjects) (inboundSynProbeStatus, error) {
	status := inboundSynProbeStatus{}
	var firstErr error

	for attempt := 0; attempt < 4; attempt++ {
		spec, specErr := loadBpf()
		if specErr != nil {
			return status, fmt.Errorf("failed to load eBPF spec: %w", specErr)
		}

		if status.TracepointDisabled {
			if prog, ok := spec.Programs["detect_inbound_syn"]; ok && prog != nil {
				prog.Instructions = asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				}
			}
		}

		if status.ReducedMapCapacity {
			applyReducedMapCapacity(spec)
		}

		if err := spec.LoadAndAssign(objects, nil); err == nil {
			Logger.Info("✅ eBPF objects loaded successfully")
			if status.TracepointDisabled {
				Logger.Warn("⚠️  detect_inbound_syn was disabled due to kernel verifier rejection")
			}
			if status.ReducedMapCapacity {
				Logger.Warn("⚠️  eBPF maps loaded with reduced capacity due to kernel memory limits")
			}
			return status, nil
		} else {
			Logger.Warnf("⚠️  eBPF load attempt %d failed: %v", attempt+1, err)
			if firstErr == nil {
				firstErr = err
			}
			if isBPFMapMemoryError(err) && !status.ReducedMapCapacity {
				status.ReducedMapCapacity = true
				Logger.Warn("⚠️  Retrying eBPF load with reduced map capacity after map memory allocation failure")
				continue
			}
			if !markOptionalInboundSynProgramFromError(err, &status) {
				return status, fmt.Errorf("eBPF load failed (%w); fallback retry failed: %v", firstErr, err)
			}
		}
	}

	return status, fmt.Errorf("eBPF load failed after optional-probe fallbacks: %w", firstErr)
}

// Close cleans up all eBPF resources
func (r *EBPFResources) Close() {
	if r.IngressFilter != nil {
		netlink.FilterDel(r.IngressFilter)
	}
	if r.EgressFilter != nil {
		netlink.FilterDel(r.EgressFilter)
	}
	if r.KpUdpRecv != nil {
		r.KpUdpRecv.Close()
	}
	if r.KpClose != nil {
		r.KpClose.Close()
	}
	if r.KpConnect != nil {
		r.KpConnect.Close()
	}
	if r.KpAccept != nil {
		r.KpAccept.Close()
	}
	if r.KpConnRequest != nil {
		r.KpConnRequest.Close()
	}
	if r.KpReset != nil {
		r.KpReset.Close()
	}
	if r.Objects != nil {
		r.Objects.Close()
	}
}

// LoadAndAttacheBPF loads eBPF objects and attaches probes
func LoadAndAttacheBPF() (*EBPFResources, error) {
	res := &EBPFResources{Objects: &bpfObjects{}}
	synProbeStatus, err := loadBPFObjectsWithInboundSynFallback(res.Objects)
	if err != nil {
		return nil, err
	}

	// Initialize rate_limiter map (required for event rate limiting)
	// The BPF code expects this map to be initialized with zero values
	if err := initRateLimiterMap(res.Objects.RateLimiter); err != nil {
		Logger.Warnf("⚠️  Failed to initialize rate limiter map: %v", err)
		// Non-fatal, continue without rate limiting
	}

	var linkErr error

	// TCP Accept (incoming connections)
	res.KpAccept, linkErr = link.Kretprobe("inet_csk_accept", res.Objects.DetectTcpAccept, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}
	Logger.Info("✅ TCP accept probe attached: inet_csk_accept")

	// Inbound SYN detection via tracepoint
	if !synProbeStatus.TracepointDisabled {
		Logger.Info("🔄 Attempting tracepoint attachment: sock:inet_sock_set_state")
		res.KpConnRequest, linkErr = link.Tracepoint("sock", "inet_sock_set_state", res.Objects.DetectTcpStateTransition, nil)
		if linkErr != nil {
			Logger.Warnf("⚠️  tracepoint sock:inet_sock_set_state not available (non-critical): %v", linkErr)
		} else {
			Logger.Info("✅ Inbound SYN probe attached: tracepoint sock:inet_sock_set_state")
		}
	}

	if res.KpConnRequest == nil && synProbeStatus.TracepointDisabled {
		Logger.Warn("⚠️  inbound SYN probe disabled by verifier; SYN counters may remain zero")
	}

	// TCP Connect (outgoing connections - SYN sent)
	res.KpConnect, linkErr = link.Kprobe("tcp_connect", res.Objects.DetectTcpConnect, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}
	Logger.Info("✅ TCP connect probe attached: tcp_connect")

	// TCP Close (detect failed handshakes)
	res.KpClose, linkErr = link.Kprobe("tcp_close", res.Objects.DetectTcpClose, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}
	Logger.Info("✅ TCP close probe attached: tcp_close")

	// TCP Reset (detect RST packets via tracepoint)
	res.KpReset, linkErr = link.Tracepoint("tcp", "tcp_receive_reset", res.Objects.DetectTcpReset, nil)
	if linkErr != nil {
		Logger.Warnf("⚠️  tcp_receive_reset tracepoint not available (non-critical): %v", linkErr)
	} else {
		Logger.Info("✅ TCP reset probe attached: tracepoint tcp:tcp_receive_reset")
	}

	// UDP Receive
	res.KpUdpRecv, linkErr = link.Kprobe("udp_recvmsg", res.Objects.DetectUdpRecv, nil)
	if linkErr != nil {
		Logger.Warnf("⚠️  udp_recvmsg probe not available (non-critical): %v", linkErr)
		// Non-fatal: UDP monitoring optional
	} else {
		Logger.Info("✅ UDP recv probe attached: udp_recvmsg")
	}

	Logger.Infof("✅ All traffic probe attachments complete")

	return res, nil
}

// SetupBandwidthTracking sets up TC programs for bandwidth tracking
func SetupBandwidthTracking(res *EBPFResources) {
	ifaceName, err := getDefaultInterface()
	if err != nil {
		Logger.Warnf("⚠️  Could not detect network interface: %v", err)
		return
	}
	Logger.Infof("🔗 Attaching TC programs to interface: %s", ifaceName)
	if err := AttachTCPrograms(res, ifaceName); err != nil {
		Logger.Warnf("⚠️  Failed to attach TC programs: %v", err)
		return
	}
	byteCounterMap = res.Objects.IpByteCounters
	icmpCounterMap = res.Objects.IcmpCounters
	ipPortBytesMap = res.Objects.IpPortBytes
}

// rateLimitState matches the C struct in traffic_probe.c
type rateLimitState struct {
	WindowStart  uint64
	EventCount   uint32
	DroppedCount uint32
}

// initRateLimiterMap initializes the rate limiter map with a single zero-valued entry
// This is required because the BPF code reads from this map and expects it to exist
// Note: rate_limiter is a PERCPU_ARRAY map, so we need to provide values for all CPUs
func initRateLimiterMap(m *ebpf.Map) error {
	if m == nil {
		return nil
	}
	key := uint32(0)
	numCPU := runtime.NumCPU()
	// Create a slice with one entry per CPU
	states := make([]rateLimitState, numCPU)
	for i := range states {
		states[i] = rateLimitState{
			WindowStart:  0,
			EventCount:   0,
			DroppedCount: 0,
		}
	}
	return m.Put(key, states)
}
