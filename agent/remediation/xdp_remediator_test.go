package remediation

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      net.IP
		wantErr bool
	}{
		{"valid IPv4", net.ParseIP("203.0.113.1"), false},
		{"valid IPv6", net.ParseIP("2001:db8::1"), false},
		{"nil IP", nil, true},
		{"empty IP", net.IP{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsExternalIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// IPv4 external
		{"203.0.113.1", true},
		{"8.8.8.8", true},
		// IPv4 private/reserved
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.1.1", false},
		// IPv6 external
		{"2001:db8::1", true},
		// IPv6 loopback
		{"::1", false},
		// IPv6 link-local
		{"fe80::1", false},
		// IPv6 ULA
		{"fd00::1", false},
		{"fc00::1", false},
		// IPv6 multicast
		{"ff02::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := isExternalIP(ip); got != tt.want {
				t.Errorf("isExternalIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestXDPMode_String(t *testing.T) {
	tests := []struct {
		mode XDPMode
		want string
	}{
		{XDPModeDRV, "DRV (native)"},
		{XDPModeSKB, "SKB (generic)"},
		{XDPModeOffload, "Offload (hardware)"},
		{XDPMode(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("XDPMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHybridRemediator_NewHybridRemediator(t *testing.T) {
	h := NewHybridRemediator(HybridConfig{EnableXDP: false})
	if h.xdp != nil {
		t.Error("Expected XDP to be nil when disabled")
	}
	if h.iptables == nil {
		t.Error("Expected iptables to be non-nil")
	}

	h2 := NewHybridRemediator(HybridConfig{EnableXDP: true, InterfaceName: "eth0"})
	if h2.xdp == nil {
		t.Error("Expected XDP to be non-nil when enabled")
	}
}

func TestHybridRemediator_IsXDPEnabled(t *testing.T) {
	h := NewHybridRemediator(HybridConfig{EnableXDP: false})
	if h.IsXDPEnabled() {
		t.Error("Expected IsXDPEnabled to be false")
	}
	h.xdpEnabled = true
	if !h.IsXDPEnabled() {
		t.Error("Expected IsXDPEnabled to be true")
	}
}

func TestHybridRemediator_XDPMode(t *testing.T) {
	h := NewHybridRemediator(HybridConfig{EnableXDP: false})
	if mode := h.XDPMode(); mode != "disabled" {
		t.Errorf("Expected 'disabled', got %s", mode)
	}
}

func TestBlockEntry_ExpiryCalculation(t *testing.T) {
	now := monotonicNs()
	expiresNs := uint64(now + (5 * time.Minute).Nanoseconds())
	entry := blockEntry{ExpiresNs: expiresNs}

	if uint64(monotonicNs()) > entry.ExpiresNs {
		t.Error("Entry should not be expired immediately")
	}

	if (blockEntry{ExpiresNs: 0}).ExpiresNs != 0 {
		t.Error("Permanent entry should have ExpiresNs = 0")
	}
}

func TestParseCIDRv4(t *testing.T) {
	tests := []struct {
		cidr       string
		wantPrefix uint32
	}{
		{"192.168.0.0/24", 24},
		{"10.0.0.0/8", 8},
		{"172.16.0.0/12", 12},
		{"0.0.0.0/0", 0},
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			key, err := parseCIDRv4(tt.cidr)
			if err != nil {
				t.Fatalf("Failed to parse CIDR: %v", err)
			}
			if key.PrefixLen != tt.wantPrefix {
				t.Errorf("Expected prefix %d, got %d", tt.wantPrefix, key.PrefixLen)
			}
		})
	}
}

func TestRateLimitConfig_Structure(t *testing.T) {
	cfg := rateLimitConfig{1000, 10000000, uint64(60 * time.Second.Nanoseconds())}
	if cfg.MaxPPS != 1000 {
		t.Errorf("Expected MaxPPS 1000, got %d", cfg.MaxPPS)
	}
	if cfg.MaxBPS != 10000000 {
		t.Errorf("Expected MaxBPS 10000000, got %d", cfg.MaxBPS)
	}
	expectedBlockTimeNs := uint64(60 * time.Second.Nanoseconds())
	if cfg.BlockTimeNs != expectedBlockTimeNs {
		t.Errorf("Expected BlockTimeNs %d, got %d", expectedBlockTimeNs, cfg.BlockTimeNs)
	}
}

func TestXDPMapPinPath(t *testing.T) {
	if DefaultXDPMapPinPath != "/sys/fs/bpf/kerneleye" {
		t.Errorf("Unexpected pin path: %s", DefaultXDPMapPinPath)
	}
}

func TestNewXDPRemediatorWithConfig(t *testing.T) {
	cfg := XDPConfig{InterfaceName: "eth0", PinMaps: false, PinPath: "/custom/path"}
	rem := NewXDPRemediatorWithConfig(cfg)

	if rem.interfaceName != "eth0" {
		t.Errorf("Expected interface eth0, got %s", rem.interfaceName)
	}
	if rem.pinMaps != false {
		t.Error("Expected pinMaps to be false")
	}
	if rem.pinPath != "/custom/path" {
		t.Errorf("Expected pinPath /custom/path, got %s", rem.pinPath)
	}
}

func TestNewXDPRemediatorWithConfig_DefaultPinPath(t *testing.T) {
	rem := NewXDPRemediatorWithConfig(XDPConfig{InterfaceName: "eth0", PinMaps: true})
	if rem.pinPath != DefaultXDPMapPinPath {
		t.Errorf("Expected default pin path, got %s", rem.pinPath)
	}
}

func TestMonotonicNs(t *testing.T) {
	t1 := monotonicNs()
	time.Sleep(10 * time.Millisecond)
	t2 := monotonicNs()
	if t2 <= t1 {
		t.Errorf("Monotonic time should increase: t1=%d, t2=%d", t1, t2)
	}
}

func TestIsNotExist(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("key does not exist"), true},
		{fmt.Errorf("lookup: key does not exist"), true},
		{fmt.Errorf("other error"), false},
	}

	for _, tt := range tests {
		if got := isNotExist(tt.err); got != tt.want {
			t.Errorf("isNotExist(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
