package main

import (
	"errors"
	"testing"

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
			err:  errors.New("program detect_inbound_syn: load program: invalid argument"),
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
