package main

import (
	"fmt"
	"strings"

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
	KpSetState    link.Link
	KpUdpRecv     link.Link
	KpConnRequest link.Link // Inbound SYN detector (kprobe or tracepoint)
	IngressFilter *netlink.BpfFilter
	EgressFilter  *netlink.BpfFilter
}

type inboundSynProbeStatus struct {
	ConnRequestDisabled bool
	TracepointDisabled  bool
}

func markOptionalInboundSynProgramFromError(err error, status *inboundSynProbeStatus) bool {
	msg := err.Error()
	changed := false

	if !status.ConnRequestDisabled &&
		(strings.Contains(msg, "DetectTcpConnRequest") || strings.Contains(msg, "detect_tcp_conn_request")) {
		status.ConnRequestDisabled = true
		changed = true
	}
	if !status.TracepointDisabled &&
		(strings.Contains(msg, "DetectInboundSyn") || strings.Contains(msg, "detect_inbound_syn")) {
		status.TracepointDisabled = true
		changed = true
	}

	return changed
}

func loadBPFObjectsWithInboundSynFallback(objects *bpfObjects) (inboundSynProbeStatus, error) {
	status := inboundSynProbeStatus{}
	var firstErr error

	for attempt := 0; attempt < 3; attempt++ {
		spec, specErr := loadBpf()
		if specErr != nil {
			return status, fmt.Errorf("failed to load eBPF spec: %w", specErr)
		}

		if status.ConnRequestDisabled {
			if prog, ok := spec.Programs["detect_tcp_conn_request"]; ok && prog != nil {
				prog.Instructions = asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				}
			}
		}
		if status.TracepointDisabled {
			if prog, ok := spec.Programs["detect_inbound_syn"]; ok && prog != nil {
				prog.Instructions = asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				}
			}
		}

		if err := spec.LoadAndAssign(objects, nil); err == nil {
			if status.ConnRequestDisabled {
				Logger.Warn("⚠️  detect_tcp_conn_request was disabled due to kernel verifier rejection")
			}
			if status.TracepointDisabled {
				Logger.Warn("⚠️  detect_inbound_syn was disabled due to kernel verifier rejection")
			}
			return status, nil
		} else {
			if firstErr == nil {
				firstErr = err
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
	if r.KpSetState != nil {
		r.KpSetState.Close()
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
	var linkErr error

	// TCP Accept (incoming connections)
	res.KpAccept, linkErr = link.Kretprobe("inet_csk_accept", res.Objects.DetectTcpAccept, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}

	// Prefer tcp_v4_conn_request kprobe for inbound SYNs.
	if !synProbeStatus.ConnRequestDisabled {
		res.KpConnRequest, linkErr = link.Kprobe("tcp_v4_conn_request", res.Objects.DetectTcpConnRequest, nil)
		if linkErr != nil {
			Logger.Warnf("⚠️  kprobe tcp_v4_conn_request not available (non-critical): %v", linkErr)
		} else {
			Logger.Info("✅ Inbound SYN probe attached: kprobe tcp_v4_conn_request")
		}
	}

	// Fallback: tracepoint-based inbound SYN detection.
	if res.KpConnRequest == nil && !synProbeStatus.TracepointDisabled {
		res.KpConnRequest, linkErr = link.Tracepoint("sock", "inet_sock_set_state", res.Objects.DetectInboundSyn, nil)
		if linkErr != nil {
			Logger.Warnf("⚠️  tracepoint sock:inet_sock_set_state not available (non-critical): %v", linkErr)
		} else {
			Logger.Info("✅ Inbound SYN probe attached: tracepoint sock:inet_sock_set_state")
		}
	}

	if res.KpConnRequest == nil {
		if synProbeStatus.ConnRequestDisabled && synProbeStatus.TracepointDisabled {
			Logger.Warn("⚠️  inbound SYN probes disabled by verifier; SYN counters will remain zero")
		} else {
			Logger.Warn("⚠️  no inbound SYN probe attached; SYN counters may remain zero")
		}
	}

	// TCP Connect (outgoing connections - SYN sent)
	res.KpConnect, linkErr = link.Kprobe("tcp_connect", res.Objects.DetectTcpConnect, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}

	// TCP State Change (clean SYN tracker on ESTABLISHED)
	res.KpSetState, linkErr = link.Kprobe("tcp_set_state", res.Objects.DetectTcpStateChange, nil)
	if linkErr != nil {
		Logger.Warnf("⚠️  tcp_set_state probe not available (non-critical): %v", linkErr)
		// Non-fatal: tcp_close will still clean up, just less efficiently
	}

	// TCP Close (detect failed handshakes)
	res.KpClose, linkErr = link.Kprobe("tcp_close", res.Objects.DetectTcpClose, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}

	// UDP Receive
	res.KpUdpRecv, linkErr = link.Kprobe("udp_recvmsg", res.Objects.DetectUdpRecv, nil)
	if linkErr != nil {
		Logger.Warnf("⚠️  udp_recvmsg probe not available (non-critical): %v", linkErr)
		// Non-fatal: UDP monitoring optional
	}

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
}
