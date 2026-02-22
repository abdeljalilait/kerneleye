package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"github.com/vishvananda/netlink"
)

// isPrivateIP checks if an IP address is in a private or reserved range
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // Treat nil as private (don't process)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		// IPv6: check for unique local (fc00::/7), link-local (fe80::/10)
		if len(ip) == 16 {
			// Unique Local Address (fc00::/7)
			if ip[0] == 0xfc || ip[0] == 0xfd {
				return true
			}
		}
		return false
	}
	// RFC 1918 private ranges
	if ip4[0] == 10 {
		return true
	}
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	// RFC 6598 CGN (100.64.0.0/10) - Shared Address Space
	if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	// Link-local (169.254.0.0/16) - already covered by IsLinkLocalUnicast but explicit check
	if ip4[0] == 169 && ip4[1] == 254 {
		return true
	}
	// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
	if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2 {
		return true
	}
	if ip4[0] == 198 && ip4[1] == 51 && ip4[2] == 100 {
		return true
	}
	if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
		return true
	}
	return false
}

// intToIP converts a uint32 IP address from host byte order to net.IP
// The eBPF code uses bpf_ntohl() to convert IPs from network byte order to host byte order.
// On little-endian systems (x86), this means the uint32 value is in little-endian format.
// net.IP expects bytes in network byte order (big-endian), so we use BigEndian.PutUint32
// which writes the bytes in the correct order for display.
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

// getProtocolFromNumber maps IP protocol numbers to protobuf enum values.
func getProtocolFromNumber(proto uint8) pb.Protocol {
	switch proto {
	case 6:
		return pb.Protocol_PROTOCOL_TCP
	case 17:
		return pb.Protocol_PROTOCOL_UDP
	case 1:
		return pb.Protocol_PROTOCOL_ICMP
	default:
		return pb.Protocol_PROTOCOL_UNKNOWN
	}
}

// getPublicIP detects the machine's public IP address
func getPublicIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// getDefaultInterface finds the primary network interface
func getDefaultInterface() (string, error) {
	if iface := os.Getenv("KERNELEYE_INTERFACE"); iface != "" {
		return iface, nil
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to list routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst == nil && route.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				continue
			}
			return link.Attrs().Name, nil
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return "", fmt.Errorf("failed to list links: %w", err)
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name != "lo" && attrs.Flags&net.FlagUp != 0 {
			return attrs.Name, nil
		}
	}
	return "", fmt.Errorf("no suitable network interface found")
}

// ipToNetworkOrder converts IP string to host byte order uint32
// This is the inverse of intToIP - converts a string IP to the same format
// that eBPF events use (after bpf_ntohl conversion).
func ipToNetworkOrder(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}
