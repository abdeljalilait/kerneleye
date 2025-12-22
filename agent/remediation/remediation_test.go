package remediation

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

type mockRunner struct {
	cmds []string
}

func (m *mockRunner) Run(name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	m.cmds = append(m.cmds, cmd)
	return nil
}

func TestIPSetRemediator_Block(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	// Test Valid Block
	ip := net.ParseIP("203.0.113.1") // External IP
	err := remediator.Block(ip, 5*time.Minute)
	if err != nil {
		t.Fatalf("Block failed: %v", err)
	}

	if len(mock.cmds) != 1 {
		t.Fatalf("Expected 1 command, got %d", len(mock.cmds))
	}
	expected := "ipset add kernel_eye_block 203.0.113.1 timeout 300 -exist"
	if mock.cmds[0] != expected {
		t.Errorf("Expected command %q, got %q", expected, mock.cmds[0])
	}
}

func TestIPSetRemediator_Block_IPv6(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	ip := net.ParseIP("2001:db8::1")
	err := remediator.Block(ip, 5*time.Minute)
	if err != nil {
		t.Fatalf("Block failed: %v", err)
	}

	expected := "ipset add kernel_eye_block_v6 2001:db8::1 timeout 300 -exist"
	if mock.cmds[0] != expected {
		t.Errorf("Expected command %q, got %q", expected, mock.cmds[0])
	}
}

func TestIPSetRemediator_PrivateIP(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	// Test Private IP (192.168.1.1)
	ip := net.ParseIP("192.168.1.1")
	err := remediator.Block(ip, 5*time.Minute)
	if err != nil {
		t.Fatalf("Block failed: %v", err)
	}

	// Should skipped
	if len(mock.cmds) != 0 {
		t.Errorf("Expected 0 commands for private IP, got: %v", mock.cmds)
	}

	// Test Loopback
	ip = net.ParseIP("127.0.0.1")
	remediator.Block(ip, 5*time.Minute)
	if len(mock.cmds) != 0 {
		t.Errorf("Expected 0 commands for loopback IP, got: %v", mock.cmds)
	}
}

func TestSetup_Teardown(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	if err := remediator.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Check for key commands
	foundBlockV6 := false
	for _, cmd := range mock.cmds {
		if strings.Contains(cmd, "create kernel_eye_block_v6") {
			foundBlockV6 = true
			break
		}
	}
	if !foundBlockV6 {
		t.Error("Setup did not create IPv6 block set")
	}

	mock.cmds = nil // Reset
	if err := remediator.Teardown(); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}

	foundDestroy := false
	for _, cmd := range mock.cmds {
		if strings.Contains(cmd, "destroy kernel_eye_block") {
			foundDestroy = true
			break
		}
	}
	if !foundDestroy {
		t.Error("Teardown did not destroy block set")
	}
}

func TestSetup_DockerUserChain(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	// Mock commands for Setup
	// 1. Create ipsets (4 calls)
	// 2. Create chain (1 call)
	// 3. Ensure INPUT jump (2 calls: check fails, insert)
	// 4. Check DOCKER-USER exists (1 call) -> SUCCESS
	// 5. Ensure DOCKER-USER jump (2 calls: check fails, insert)
	// 6. Flush chain (1 call)
	// 7. Add block/limit rules (3 calls)

	// Since mockRunner just successfully returns nil for everything, it simulates:
	// - `iptables -L DOCKER-USER -n` returning nil (success), meaning chain exists.
	// - `iptables -C ...` returning nil (success), meaning rule exists.
	// WAIT. If -C returns nil, we DON'T insert.
	// The default mockRunner returns nil for everything.
	// So `ensureJumpRule` will behave as: "Rule already exists", so NO insert.

	// Let's make a smarter mock to test the logic
	// We want to verify that IF DOCKER-USER exists, we try to insert the jump rule (assuming it doesn't exist yet).
	// To do this properly, we need a controllable mock.

	calls := []string{}
	remediator.Runner = func(name string, args ...string) error {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)

		// Simulate DOCKER-USER exists
		if name == "iptables" && args[0] == "-L" && args[1] == "DOCKER-USER" {
			return nil
		}

		// Simulate jump rule NOT existing (so we can assert it tries to create it)
		if name == "iptables" && args[0] == "-C" {
			return fmt.Errorf("rule does not exist")
		}

		return nil
	}

	if err := remediator.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Verify we tried to insert jump rule into DOCKER-USER
	foundDockerJump := false
	for _, cmd := range calls {
		if cmd == "iptables -I DOCKER-USER -j KERNEL_EYE" {
			foundDockerJump = true
			break
		}
	}
	if !foundDockerJump {
		t.Error("Setup did not insert jump rule into DOCKER-USER when it exists")
	}

	// Now Test Teardown
	calls = nil // reset
	if err := remediator.Teardown(); err != nil {
		t.Fatalf("Teardown failed: %v", err)
	}
	// Verify we tried to remove jump rule from DOCKER-USER
	foundDockerRemove := false
	for _, cmd := range calls {
		if cmd == "iptables -D DOCKER-USER -j KERNEL_EYE" {
			foundDockerRemove = true
			break
		}
	}
	if !foundDockerRemove {
		t.Error("Teardown did not remove jump rule from DOCKER-USER when it exists")
	}
}

func TestSyncBlocklist(t *testing.T) {
	mock := &mockRunner{}
	remediator := NewIPSetRemediator()
	remediator.Runner = mock.Run

	ips := []net.IP{
		net.ParseIP("203.0.113.1"),
		net.ParseIP("203.0.113.2"),
		net.ParseIP("127.0.0.1"), // Should be skipped
	}

	if err := remediator.SyncBlocklist(ips); err != nil {
		t.Fatalf("SyncBlocklist failed: %v", err)
	}

	// Verify Sequence:
	// 1. Create temp set
	// 2. Add IPs (valid ones only)
	// 3. Swap
	// 4. Destroy temp (deferred)

	cmds := mock.cmds
	if len(cmds) < 4 {
		t.Fatalf("Expected at least 4 commands, got %d", len(cmds))
	}

	// 1. Create temp
	if !strings.Contains(cmds[0], "create kernel_eye_block_temp") {
		t.Errorf("Expected create temp, got: %s", cmds[0])
	}

	// 2. Add IPs
	foundIP1 := false
	foundIP2 := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "add kernel_eye_block_temp 203.0.113.1") {
			foundIP1 = true
		}
		if strings.Contains(cmd, "add kernel_eye_block_temp 203.0.113.2") {
			foundIP2 = true
		}
		if strings.Contains(cmd, "add kernel_eye_block_temp 127.0.0.1") {
			t.Error("Should not have added localhost to blocklist")
		}
	}
	if !foundIP1 || !foundIP2 {
		t.Error("Did not find expected IP add commands")
	}

	// 3. Swap
	foundSwap := false
	for _, cmd := range cmds {
		if strings.Contains(cmd, "swap kernel_eye_block_temp kernel_eye_block") {
			foundSwap = true
		}
	}
	if !foundSwap {
		t.Error("Did not find swap command")
	}

	// 4. Destroy (deferred, so it should be last or near end)
	// mockRunner just appends, defer executes at end of function.
	// The `SyncBlocklist` function returned, so defer SHOULD have executed.
	lastCmd := cmds[len(cmds)-1]
	if !strings.Contains(lastCmd, "destroy kernel_eye_block_temp") {
		t.Errorf("Expected destroy temp as last command, got: %v", lastCmd)
	}
}

func TestIsExternalIP_Extended(t *testing.T) {
	remediator := NewIPSetRemediator()

	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.1", true},
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"169.254.169.254", false}, // Link Local (Metadata)
		{"224.0.0.1", false},       // Multicast
		{"::1", false},
		{"fe80::1", false}, // IPv6 Link Local (covered by IsPrivate in some go versions, or Unicast check)
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := remediator.isExternalIP(ip); got != tt.want {
			t.Errorf("isExternalIP(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
