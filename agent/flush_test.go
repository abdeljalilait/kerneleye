package main

import (
	"testing"

	pb "github.com/kerneleye/proto/kerneleye/v1"
)

func TestIsFullyAccepted(t *testing.T) {
	tests := []struct {
		name      string
		resp      *pb.TrafficResponse
		submitted int
		wantOK    bool
	}{
		{name: "nil response", resp: nil, submitted: 3, wantOK: false},
		{name: "explicit failure", resp: &pb.TrafficResponse{Success: false, Message: "failed", EventsProcessed: 3}, submitted: 3, wantOK: false},
		{name: "partial success", resp: &pb.TrafficResponse{Success: true, EventsProcessed: 2}, submitted: 3, wantOK: false},
		{name: "full success", resp: &pb.TrafficResponse{Success: true, EventsProcessed: 3}, submitted: 3, wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, _ := isFullyAccepted(tt.resp, tt.submitted)
			if gotOK != tt.wantOK {
				t.Fatalf("isFullyAccepted() ok=%v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}
