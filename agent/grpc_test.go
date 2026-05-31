package main

import (
	"testing"
)

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

func TestBuildTLSTransportInsecure(t *testing.T) {
	creds, err := buildTLSTransport(&TLSTransportConfig{Insecure: true})
	if err != nil {
		t.Fatalf("buildTLSTransport insecure should not error: %v", err)
	}
	if creds == nil {
		t.Fatal("credentials should not be nil")
	}
	info := creds.Info()
	if info.SecurityProtocol != "insecure" {
		t.Fatalf("expected insecure protocol, got %s", info.SecurityProtocol)
	}
}

func TestBuildTLSTransportSecure(t *testing.T) {
	// TLS (no mTLS) uses system CA pool — no error expected.
	creds, err := buildTLSTransport(&TLSTransportConfig{})
	if err != nil {
		t.Fatalf("buildTLSTransport secure should not error: %v", err)
	}
	if creds == nil {
		t.Fatal("credentials should not be nil")
	}
	info := creds.Info()
	if info.SecurityProtocol != "tls" {
		t.Fatalf("expected tls protocol, got %s", info.SecurityProtocol)
	}
}

func TestBuildTLSTransportMissingCAFile(t *testing.T) {
	_, err := buildTLSTransport(&TLSTransportConfig{CAFile: "/nonexistent/ca.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestBuildTLSTransportMissingCert(t *testing.T) {
	_, err := buildTLSTransport(&TLSTransportConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"})
	if err == nil {
		t.Fatal("expected error for missing client cert/key")
	}
}
