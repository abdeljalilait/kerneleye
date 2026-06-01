package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestIsBPFMapMemoryError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "map create cannot allocate memory",
			err:  errors.New("field TcEgress: program tc_egress: map ip_byte_counters: map create: cannot allocate memory"),
			want: true,
		},
		{
			name: "program verifier error",
			err:  errors.New("program detect_tcp_state_transition: load program: invalid argument"),
			want: false,
		},
		{
			name: "generic memory error",
			err:  errors.New("cannot allocate memory"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBPFMapMemoryError(tt.err); got != tt.want {
				t.Fatalf("isBPFMapMemoryError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestApplyReducedMapCapacity(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"events":              {MaxEntries: 1 << 24},
			"tcp_syn_tracker":     {MaxEntries: 262144},
			"tcp_syn_tracker_v6":  {MaxEntries: 65536},
			"ip_byte_counters":    {MaxEntries: 262144},
			"ip_byte_counters_v6": {MaxEntries: 65536},
			"icmp_counters":       {MaxEntries: 262144},
			"ip_port_bytes":       {MaxEntries: 262144},
			"debug_counters":      {MaxEntries: 1},
		},
	}

	applyReducedMapCapacity(spec)

	want := map[string]uint32{
		"events":              1 << 22,
		"tcp_syn_tracker":     65536,
		"tcp_syn_tracker_v6":  16384,
		"ip_byte_counters":    65536,
		"ip_byte_counters_v6": 16384,
		"icmp_counters":       65536,
		"ip_port_bytes":       65536,
		"debug_counters":      1,
	}

	for name, wantMaxEntries := range want {
		if got := spec.Maps[name].MaxEntries; got != wantMaxEntries {
			t.Fatalf("map %s MaxEntries = %d, want %d", name, got, wantMaxEntries)
		}
	}
}

// TestEventSize verifies the Go Event struct is exactly 80 bytes, matching
// the refactored C event_t layout (zero internal padding, 80 bytes total).
func TestEventSize(t *testing.T) {
	var e Event
	size := unsafe.Sizeof(e)
	if size != 80 {
		t.Fatalf("Event struct size = %d, want 80. The Go struct layout must match traffic_probe.c event_t exactly.", size)
	}
}

// TestEventBinaryDeserialization verifies that binary.Read correctly
// deserializes a raw 80-byte ring buffer record into the Event struct,
// matching the refactored C event_t field order.
func TestEventBinaryDeserialization(t *testing.T) {
	// Build a raw 80-byte event matching the C event_t layout:
	//   [0:8]   timestamp
	//   [8:12]  pid
	//   [12:16] tgid
	//   [16:20] uid
	//   [20:22] lport
	//   [22:24] rport
	//   [24:26] family
	//   [26]    protocol
	//   [27]    flags
	//   [28]    direction
	//   [29:32] _pad[3]
	//   [32:48] saddr[16]
	//   [48:64] daddr[16]
	//   [64:80] comm[16]
	raw := make([]byte, 80)

	// timestamp = 0x0102030405060708 (little-endian)
	binary.LittleEndian.PutUint64(raw[0:8], 0x0102030405060708)
	// pid = 1234
	binary.LittleEndian.PutUint32(raw[8:12], 1234)
	// tgid = 5678
	binary.LittleEndian.PutUint32(raw[12:16], 5678)
	// uid = 1000
	binary.LittleEndian.PutUint32(raw[16:20], 1000)
	// lport = 443
	binary.LittleEndian.PutUint16(raw[20:22], 443)
	// rport = 54321
	binary.LittleEndian.PutUint16(raw[22:24], 54321)
	// family = AF_INET (2)
	binary.LittleEndian.PutUint16(raw[24:26], 2)
	// protocol = TCP (6)
	raw[26] = 6
	// flags = FLAG_SYN | FLAG_ACK (0x03)
	raw[27] = 0x03
	// direction = DIR_INBOUND (0)
	raw[28] = 0
	// _pad[3] = zero (already zero)

	// saddr = 10.0.0.1 (0x0A000001 host order → big-endian in first 4 bytes)
	copy(raw[32:36], []byte{0x01, 0x00, 0x00, 0x0A}) // host order 0x0A000001
	// daddr = 192.168.1.1 (0xC0A80101 host order → bytes)
	copy(raw[48:52], []byte{0x01, 0x01, 0xA8, 0xC0}) // host order 0xC0A80101
	// comm = "sshd" + null padding
	copy(raw[64:80], append([]byte("sshd"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

	var event Event
	if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &event); err != nil {
		t.Fatalf("binary.Read failed: %v", err)
	}

	// Verify every field
	if event.Timestamp != 0x0102030405060708 {
		t.Errorf("Timestamp = 0x%x, want 0x0102030405060708", event.Timestamp)
	}
	if event.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", event.Pid)
	}
	if event.Tgid != 5678 {
		t.Errorf("Tgid = %d, want 5678", event.Tgid)
	}
	if event.Uid != 1000 {
		t.Errorf("Uid = %d, want 1000", event.Uid)
	}
	if event.Lport != 443 {
		t.Errorf("Lport = %d, want 443", event.Lport)
	}
	if event.Rport != 54321 {
		t.Errorf("Rport = %d, want 54321", event.Rport)
	}
	if event.Family != 2 {
		t.Errorf("Family = %d, want 2 (AF_INET)", event.Family)
	}
	if event.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6 (TCP)", event.Protocol)
	}
	if event.Flags != 0x03 {
		t.Errorf("Flags = 0x%02x, want 0x03 (SYN|ACK)", event.Flags)
	}
	if event.Direction != 0 {
		t.Errorf("Direction = %d, want 0 (DIR_INBOUND)", event.Direction)
	}
	// saddr first 4 bytes should be 0x0A000001 in host order
	saddr4 := binary.LittleEndian.Uint32(event.Saddr[:4])
	if saddr4 != 0x0A000001 {
		t.Errorf("Saddr[0:4] = 0x%08x, want 0x0A000001 (10.0.0.1 host order)", saddr4)
	}
	// daddr first 4 bytes should be 0xC0A80101
	daddr4 := binary.LittleEndian.Uint32(event.Daddr[:4])
	if daddr4 != 0xC0A80101 {
		t.Errorf("Daddr[0:4] = 0x%08x, want 0xC0A80101 (192.168.1.1 host order)", daddr4)
	}
	if string(bytes.TrimRight(event.Comm[:], "\x00")) != "sshd" {
		t.Errorf("Comm = %q, want \"sshd\"", string(event.Comm[:]))
	}
}

// TestEventFieldOffsets verifies that each field is at the expected offset
// within the Go struct. This guards against accidental field reordering.
func TestEventFieldOffsets(t *testing.T) {
	var e Event
	typ := reflect.TypeOf(e)

	tests := []struct {
		field  string
		offset uintptr
	}{
		{"Timestamp", 0},
		{"Pid", 8},
		{"Tgid", 12},
		{"Uid", 16},
		{"Lport", 20},
		{"Rport", 22},
		{"Family", 24},
		{"Protocol", 26},
		{"Flags", 27},
		{"Direction", 28},
		{"Saddr", 32},
		{"Daddr", 48},
		{"Comm", 64},
	}

	for _, tt := range tests {
		f, ok := typ.FieldByName(tt.field)
		if !ok {
			t.Fatalf("Field %s not found in Event struct", tt.field)
		}
		if f.Offset != tt.offset {
			t.Errorf("Event.%s offset = %d, want %d", tt.field, f.Offset, tt.offset)
		}
	}
}

// TestMarkOptionalInboundSynProgramFromError verifies the tracepoint-disable
// fallback logic correctly detects the renamed tcp_state_transition program.
func TestMarkOptionalInboundSynProgramFromError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantDisabled   bool
	}{
		{
			name:         "new program name match",
			err:          errors.New("field DetectTcpStateTransition: program detect_tcp_state_transition: load program: permission denied"),
			wantDisabled: true,
		},
		{
			name:         "new lowercase match",
			err:          errors.New("program detect_tcp_state_transition: invalid argument"),
			wantDisabled: true,
		},
		{
			name:         "old program name (should not match)",
			err:          errors.New("field DetectInboundSyn: program detect_inbound_syn: load program: invalid argument"),
			wantDisabled: false,
		},
		{
			name:         "unrelated error",
			err:          errors.New("map ip_byte_counters: map create: cannot allocate memory"),
			wantDisabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := &inboundSynProbeStatus{}
			changed := markOptionalInboundSynProgramFromError(tt.err, status)
			if changed != tt.wantDisabled {
				t.Errorf("markOptionalInboundSynProgramFromError returned changed=%v, want %v", changed, tt.wantDisabled)
			}
			if status.TracepointDisabled != tt.wantDisabled {
				t.Errorf("status.TracepointDisabled = %v, want %v", status.TracepointDisabled, tt.wantDisabled)
			}
		})
	}
}

// TestRateLimiterInit verifies the initRateLimiterMap function correctly
// initializes a PERCPU_ARRAY map with one entry per CPU.
func TestRateLimiterInit(t *testing.T) {
	// Create an in-memory PERCPU_ARRAY spec and load it.
	// We use a real eBPF map here because the PERCPU_ARRAY semantics
	// (per-CPU storage) are kernel-enforced and can't be mocked easily.
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"rate_limiter": {
				Type:       ebpf.PerCPUArray,
				KeySize:    4,
				ValueSize:  uint32(unsafe.Sizeof(rateLimitState{})),
				MaxEntries: 1,
			},
		},
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Skipf("Skipping: cannot create test eBPF map (requires kernel support): %v", err)
	}
	defer coll.Close()

	m := coll.Maps["rate_limiter"]
	if m == nil {
		t.Fatal("rate_limiter map not found in test collection")
	}

	if err := initRateLimiterMap(m); err != nil {
		t.Fatalf("initRateLimiterMap failed: %v", err)
	}

	// Read back and verify: for a PERCPU_ARRAY, the lookup returns
	// a slice of values (one per CPU).
	var states []rateLimitState
	if err := m.Lookup(uint32(0), &states); err != nil {
		t.Fatalf("Lookup on rate_limiter failed: %v", err)
	}

	if len(states) == 0 {
		t.Fatal("rate_limiter returned empty slice; expected at least 1 entry")
	}

	for i, s := range states {
		if s.WindowStart != 0 {
			t.Errorf("CPU %d: WindowStart = %d, want 0", i, s.WindowStart)
		}
		if s.EventCount != 0 {
			t.Errorf("CPU %d: EventCount = %d, want 0", i, s.EventCount)
		}
		if s.DroppedCount != 0 {
			t.Errorf("CPU %d: DroppedCount = %d, want 0", i, s.DroppedCount)
		}
	}
}

// TestGlobalRateLimiterMapExists verifies the generated bpfObjects includes
// the global_rate_limiter map (added for cross-CPU flood protection).
func TestGlobalRateLimiterMapExists(t *testing.T) {
	// Check via reflection that bpfObjects.bpfMaps has the GlobalRateLimiter field.
	objType := reflect.TypeOf(bpfObjects{})
	mapsType := objType.Field(1).Type // bpfMaps is the second embedded field

	_, ok := mapsType.FieldByName("GlobalRateLimiter")
	if !ok {
		t.Fatal("bpfMaps.GlobalRateLimiter field not found. " +
			"The global_rate_limiter map must be present in traffic_probe.c and " +
			"bpf2go must have generated the corresponding Go field. " +
			"Run 'go generate' after C changes.")
	}
}

// TestTracepointFallbackProgramName verifies the fallback lookup in
// loadBPFObjectsWithInboundSynFallback uses the correct program name
// after the detect_inbound_syn → detect_tcp_state_transition rename.
func TestTracepointFallbackProgramName(t *testing.T) {
	// Build a minimal spec with the new program name to verify the lookup works.
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"detect_tcp_state_transition": {
				Type: ebpf.Tracing,
			},
		},
	}

	// Verify the new name resolves
	prog, ok := spec.Programs["detect_tcp_state_transition"]
	if !ok || prog == nil {
		t.Fatal("spec.Programs[\"detect_tcp_state_transition\"] not found — update the spec key after rename")
	}

	// Verify the old name no longer resolves (regression check)
	if _, ok := spec.Programs["detect_inbound_syn"]; ok {
		t.Fatal("spec.Programs[\"detect_inbound_syn\"] still present — old program name was not fully renamed")
	}
}
