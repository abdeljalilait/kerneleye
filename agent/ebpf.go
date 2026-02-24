package main

import (
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
	IngressFilter *netlink.BpfFilter
	EgressFilter  *netlink.BpfFilter
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
	if r.Objects != nil {
		r.Objects.Close()
	}
}

// LoadAndAttacheBPF loads eBPF objects and attaches probes
func LoadAndAttacheBPF() (*EBPFResources, error) {
	res := &EBPFResources{Objects: &bpfObjects{}}
	if err := loadBpfObjects(res.Objects, nil); err != nil {
		return nil, err
	}
	var err error

	// TCP Accept (incoming connections)
	res.KpAccept, err = link.Kretprobe("inet_csk_accept", res.Objects.DetectTcpAccept, nil)
	if err != nil {
		res.Close()
		return nil, err
	}

	// TCP Connect (outgoing connections - SYN sent)
	res.KpConnect, err = link.Kprobe("tcp_connect", res.Objects.DetectTcpConnect, nil)
	if err != nil {
		res.Close()
		return nil, err
	}

	// TCP State Change (clean SYN tracker on ESTABLISHED)
	res.KpSetState, err = link.Kprobe("tcp_set_state", res.Objects.DetectTcpStateChange, nil)
	if err != nil {
		Logger.Warnf("⚠️  tcp_set_state probe not available (non-critical): %v", err)
		// Non-fatal: tcp_close will still clean up, just less efficiently
	}

	// TCP Close (detect failed handshakes)
	res.KpClose, err = link.Kprobe("tcp_close", res.Objects.DetectTcpClose, nil)
	if err != nil {
		res.Close()
		return nil, err
	}

	// UDP Receive
	res.KpUdpRecv, err = link.Kprobe("udp_recvmsg", res.Objects.DetectUdpRecv, nil)
	if err != nil {
		Logger.Warnf("⚠️  udp_recvmsg probe not available (non-critical): %v", err)
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
