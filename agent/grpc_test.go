package main

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNormalizeGRPCTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "plain host default port", target: "grpc.example.com", want: "grpc.example.com:443"},
		{name: "plain host explicit port", target: "grpc.example.com:443", want: "grpc.example.com:443"},
		{name: "localhost explicit port", target: "localhost:9091", want: "localhost:9091"},
		{name: "https default port", target: "https://grpc.example.com", want: "https://grpc.example.com:443"},
		{name: "https explicit port", target: "https://grpc.example.com:8443", want: "https://grpc.example.com:8443"},
		{name: "http default port", target: "http://localhost", want: "http://localhost:80"},
		{name: "ipv6 explicit port", target: "[::1]:9091", want: "[::1]:9091"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeGRPCTarget(tt.target); got != tt.want {
				t.Fatalf("normalizeGRPCTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}

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

func TestIsRetriableRegisterError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "unknown grpc status", err: status.Error(codes.Unknown, "unexpected HTTP status code received from server: 500 (Internal Server Error); malformed header: missing HTTP content-type"), want: true},
		{name: "missing content type text", err: errors.New("malformed header: missing HTTP content-type"), want: true},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, "invalid key"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetriableRegisterError(tt.err); got != tt.want {
				t.Fatalf("isRetriableRegisterError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestGRPCTransportModeMessage(t *testing.T) {
	tests := []struct {
		name string
		cfg  *TLSTransportConfig
		want string
	}{
		{
			name: "plaintext",
			cfg:  &TLSTransportConfig{Insecure: true},
			want: "⚠️  gRPC transport: plaintext (--insecure), target=grpc.kerneleye.net:9091",
		},
		{
			name: "tls system ca",
			cfg:  &TLSTransportConfig{},
			want: "🔐 gRPC transport: TLS 1.3 enabled, target=grpc.kerneleye.net:9091, CA=system",
		},
		{
			name: "tls custom ca",
			cfg:  &TLSTransportConfig{CAFile: "/etc/kerneleye/ca.crt"},
			want: "🔐 gRPC transport: TLS 1.3 enabled, target=grpc.kerneleye.net:9091, CA=/etc/kerneleye/ca.crt",
		},
		{
			name: "mtls",
			cfg:  &TLSTransportConfig{CertFile: "/etc/kerneleye/agent.crt", KeyFile: "/etc/kerneleye/agent.key"},
			want: "🔐 gRPC transport: mTLS enabled, target=grpc.kerneleye.net:9091, client_cert=/etc/kerneleye/agent.crt",
		},
		{
			name: "nil config",
			cfg:  nil,
			want: "🔐 gRPC transport: TLS 1.3 enabled, target=grpc.kerneleye.net:9091, CA=system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcTransportModeMessage(tt.cfg, "grpc.kerneleye.net:9091")
			if got != tt.want {
				t.Fatalf("grpcTransportModeMessage() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "agent.key") {
				t.Fatal("transport mode log must not include private key path")
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
