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
	KpConnRequest link.Link // TCP connection request (incoming SYN)
	IngressFilter *netlink.BpfFilter
	EgressFilter  *netlink.BpfFilter
}

func loadBPFObjectsWithConnRequestFallback(objects *bpfObjects) (bool, error) {
	if err := loadBpfObjects(objects, nil); err == nil {
		return false, nil
	} else if !isConnRequestLoadError(err) {
		return false, err
	} else {
		spec, specErr := loadBpf()
		if specErr != nil {
			return false, fmt.Errorf("eBPF load failed (%w); fallback spec load failed: %v", err, specErr)
		}

		prog, ok := spec.Programs["detect_tcp_conn_request"]
		if !ok || prog == nil {
			return false, err
		}

		// Replace only this optional probe with a verifier-safe no-op, then retry.
		prog.Instructions = asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		}

		if retryErr := spec.LoadAndAssign(objects, nil); retryErr != nil {
			return false, fmt.Errorf("eBPF load failed (%w); fallback retry failed: %v", err, retryErr)
		}

		Logger.Warnf("⚠️  detect_tcp_conn_request was rejected by kernel verifier; continuing with probe disabled: %v", err)
		return true, nil
	}
}

func isConnRequestLoadError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "DetectInboundSyn") || strings.Contains(msg, "detect_inbound_syn")
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
	if err := loadBpfObjects(res.Objects, nil); err != nil {
		if isConnRequestLoadError(err) {
			Logger.Warn("⚠️  Tracepoint load error - check kernel support for sock:inet_sock_set_state")
		}
		return nil, err
	}
	var linkErr error

	// TCP Accept (incoming connections)
	res.KpAccept, linkErr = link.Kretprobe("inet_csk_accept", res.Objects.DetectTcpAccept, nil)
	if linkErr != nil {
		res.Close()
		return nil, linkErr
	}

	// TCP state change tracepoint - catches inbound SYN (SYN_RECV state)
	// More stable than kprobe - properly typed fields across kernel versions
	res.KpConnRequest, linkErr = link.Tracepoint("sock", "inet_sock_set_state", res.Objects.DetectInboundSyn, nil)
	if linkErr != nil {
		Logger.Warnf("⚠️  tracepoint sock:inet_sock_set_state not available (non-critical): %v", linkErr)
		// Non-fatal: accept-based detection still works
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
