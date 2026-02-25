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

// bytesToIP converts the 16-byte address array from the eBPF event to net.IP
// Family: AF_INET (2) for IPv4, AF_INET6 (10) for IPv6
func bytesToIP(addr []byte, family uint16) net.IP {
	if len(addr) < 4 {
		return nil
	}

	// AF_INET = 2, AF_INET6 = 10
	if family == 2 { // IPv4
		// BPF stores IP as host byte order (after bpf_ntohl)
		// On little-endian, this is stored LSB first in memory
		// We read it back as little-endian to get the host-order value,
		// then convert to network byte order for net.IP
		hostOrder := uint32(addr[0]) | uint32(addr[1])<<8 | uint32(addr[2])<<16 | uint32(addr[3])<<24
		ip := make(net.IP, 4)
		ip[0] = byte(hostOrder >> 24)
		ip[1] = byte(hostOrder >> 16)
		ip[2] = byte(hostOrder >> 8)
		ip[3] = byte(hostOrder)
		return ip
	} else { // IPv6
		// addr contains network-byte-order IPv6
		ip := make(net.IP, 16)
		copy(ip, addr[:16])
		return ip
	}
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

// ipv4ToBytes converts an IPv4 address string to a 16-byte array (first 4 bytes used)
// This is for creating test events that match the Event struct format
// The BPF code stores IPs in host byte order (after bpf_ntohl), which means on little-endian
// systems the bytes appear reversed in memory compared to network byte order
func ipv4ToBytes(ipStr string) [16]byte {
	var result [16]byte
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return result
	}
	// net.IP is in network byte order: [46, 224, 59, 11] = 0x2EE03B0B
	// Convert to host byte order (same as bpf_ntohl does): 0x0B3BE02E
	// On little-endian, this value in memory is: [0x0E, 0xE0, 0x3B, 0x0B] (LSB first)
	// Store exactly these bytes so binary.Read with LittleEndian gives us back 0x0B3BE02E
	result[0] = ip[3] // LSB of network order = MSB of host order
	result[1] = ip[2]
	result[2] = ip[1]
	result[3] = ip[0]
	return result
}
