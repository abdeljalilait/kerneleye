package main

import "testing"

func TestBuildGRPCDialTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "plain host port", target: "localhost:9091", want: "localhost:9091"},
		{name: "https default port", target: "https://grpc.example.com", want: "grpc.example.com:443"},
		{name: "grpcs explicit port", target: "grpcs://grpc.example.com:8443", want: "grpc.example.com:8443"},
		{name: "http default port", target: "http://localhost", want: "localhost:80"},
		{name: "http explicit port", target: "http://localhost:9091", want: "localhost:9091"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGRPCDialTarget(tt.target); got != tt.want {
				t.Fatalf("buildGRPCDialTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestGRPCTransportForTarget(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantTLS bool
	}{
		{name: "http scheme is plaintext", target: "http://localhost:9091", wantTLS: false},
		{name: "https scheme is tls", target: "https://grpc.example.com:443", wantTLS: true},
		{name: "port 443 defaults to tls", target: "api.example.com:443", wantTLS: true},
		{name: "port 9091 defaults to plaintext", target: "localhost:9091", wantTLS: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTLS := grpcTransportForTarget(tt.target)
			if gotTLS != tt.wantTLS {
				t.Fatalf("grpcTransportForTarget(%q) = %v, want %v", tt.target, gotTLS, tt.wantTLS)
			}
		})
	}
}
