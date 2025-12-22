package main

import (
	"log"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// AttachTCPrograms attaches TC ingress/egress programs to an interface
func AttachTCPrograms(res *EBPFResources, ifaceName string) error {
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	addClsactQdisc(iface)
	res.IngressFilter = createTCFilter(iface, netlink.HANDLE_MIN_INGRESS,
		res.Objects.TcIngress.FD(), "kerneleye_ingress")
	if err := netlink.FilterAdd(res.IngressFilter); err != nil {
		log.Printf("⚠️  Failed to attach TC ingress: %v", err)
		res.IngressFilter = nil
	} else {
		log.Println("✅ TC ingress attached")
	}
	res.EgressFilter = createTCFilter(iface, netlink.HANDLE_MIN_EGRESS,
		res.Objects.TcEgress.FD(), "kerneleye_egress")
	if err := netlink.FilterAdd(res.EgressFilter); err != nil {
		log.Printf("⚠️  Failed to attach TC egress: %v", err)
		res.EgressFilter = nil
	} else {
		log.Println("✅ TC egress attached")
	}
	return nil
}

func addClsactQdisc(iface netlink.Link) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc)
}

func createTCFilter(iface netlink.Link, parent uint32, fd int, name string) *netlink.BpfFilter {
	return &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index, Handle: 1,
			Parent: parent, Protocol: unix.ETH_P_ALL,
		},
		Fd: fd, Name: name, DirectAction: true,
	}
}
