// Package assets contains embedded eBPF object files.
package assets

import (
	_ "embed"
)

// XDPFirewallBpfelO contains the embedded XDP firewall eBPF object file.
//go:embed xdp_firewall_bpfel.o
var XDPFirewallBpfelO []byte
