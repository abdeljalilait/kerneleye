package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const grpcDialTargetPrefix = "passthrough:///"

// TLSTransportConfig holds TLS configuration for agent-to-backend communication.
type TLSTransportConfig struct {
	// Insecure disables TLS entirely. Only for development/testing.
	// The agent will log a prominent warning each time this is used.
	Insecure bool

	// CAFile is the path to a CA certificate PEM file for verifying the backend.
	// When empty, the system CA pool is used.
	CAFile string

	// CertFile is the path to the agent's client certificate PEM file (for mTLS).
	CertFile string

	// KeyFile is the path to the agent's client private key PEM file (for mTLS).
	KeyFile string

	// ServerName overrides the TLS server name used for hostname verification.
	ServerName string
}

// buildGRPCTarget converts server host to gRPC target address.
func buildGRPCTarget(serverHost, grpcURL string) string {
	if grpcURL != "" {
		grpcTarget := strings.TrimSpace(grpcURL)
		if !strings.Contains(grpcTarget, ":") {
			grpcTarget = grpcTarget + ":9091"
		} else {
			grpcTarget = strings.Replace(grpcTarget, ":443", ":9091", 1)
		}
		return grpcTarget
	}
	grpcTarget := strings.TrimSpace(serverHost)
	if !strings.Contains(grpcTarget, ":") {
		grpcTarget = grpcTarget + ":9091"
	} else {
		grpcTarget = strings.Replace(grpcTarget, ":443", ":9091", 1)
	}
	return grpcTarget
}

// buildGRPCDialTarget returns the target format expected by grpc.NewClient.
func buildGRPCDialTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	if !strings.Contains(target, "://") {
		return target
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return target
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(parsed.Scheme) {
		case "https", "grpcs":
			host += ":443"
		case "http", "grpc", "h2c":
			host += ":80"
		}
	}
	return host
}

// buildTLSTransport creates a TLS transport credentials object for the agent.
// When tlsCfg.Insecure is true, returns plaintext credentials (insecure).
// When CertFile+KeyFile are provided, sets up mTLS client certificate.
// When CAFile is provided, uses a custom CA pool instead of the system pool.
func buildTLSTransport(tlsCfg *TLSTransportConfig) (credentials.TransportCredentials, error) {
	if tlsCfg != nil && tlsCfg.Insecure {
		if Logger != nil {
			Logger.Warn("⚠️  TLS DISABLED: agent is running in insecure mode. " +
				"All gRPC traffic with the backend will be in plaintext. " +
				"Never use this in production.")
		}
		return insecure.NewCredentials(), nil
	}

	var caCertPool *x509.CertPool
	if tlsCfg != nil && tlsCfg.CAFile != "" {
		caCertPool = x509.NewCertPool()
		pem, err := os.ReadFile(tlsCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from %s: %w", tlsCfg.CAFile, err)
		}
		if !caCertPool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", tlsCfg.CAFile)
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
	}

	if tlsCfg != nil && tlsCfg.ServerName != "" {
		tlsConfig.ServerName = tlsCfg.ServerName
	}

	// mTLS: load client certificate if provided
	if tlsCfg != nil && tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate (cert=%s, key=%s): %w",
				tlsCfg.CertFile, tlsCfg.KeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsConfig), nil
}

// buildGRPCOpts builds gRPC dial options with TLS by default.
// Plaintext is only allowed when tlsCfg.Insecure is explicitly true.
func buildGRPCOpts(tlsCfg *TLSTransportConfig) []grpc.DialOption {
	creds, err := buildTLSTransport(tlsCfg)
	if err != nil {
		Logger.Fatalf("Failed to build TLS transport: %v", err)
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}
}

func isRetriableRegisterError(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded, codes.Internal, codes.Unknown:
			return true
		default:
			return false
		}
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unexpected http status code received from server") ||
		strings.Contains(msg, "missing http-content-type") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "transport is closing") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "server closed the stream") ||
		strings.Contains(msg, "eof") {
		return true
	}
	return false
}

// registerAndWaitForApproval registers the agent and polls for approval.
func registerAndWaitForApproval(apiKey, serverHost, grpcURL string, tlsCfg *TLSTransportConfig) error {
	hostname, _ := os.Hostname()
	ipAddress := getPublicIP()

	grpcTarget := buildGRPCTarget(serverHost, grpcURL)
	grpcDialTarget := buildGRPCDialTarget(grpcTarget)
	Logger.Infof("Connecting to gRPC server at %s...", grpcTarget)

	var regResp *pb.RegisterResponse
	var lastErr error
	const maxAttempts = 5

	opts := buildGRPCOpts(tlsCfg)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(1<<(attempt-2)) * time.Second
			Logger.Infof("Retrying registration in %v (attempt %d/%d)...", backoff, attempt, maxAttempts)
			time.Sleep(backoff)
		}

		conn, err := grpc.NewClient(grpcDialTargetPrefix+grpcDialTarget, opts...)
		if err != nil {
			lastErr = fmt.Errorf("failed to create gRPC client: %w", err)
			continue
		}

		client := pb.NewIngestServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		regResp, err = client.Register(ctx, &pb.RegisterRequest{
			UserId:    apiKey,
			Hostname:  hostname,
			IpAddress: ipAddress,
		})
		cancel()
		_ = conn.Close()

		if err == nil {
			lastErr = nil
			break
		}

		lastErr = err
		if !isRetriableRegisterError(err) {
			return fmt.Errorf("gRPC registration failed: %v", err)
		}

		Logger.Warnf("Registration attempt %d/%d failed with transient transport error: %v", attempt, maxAttempts, err)
	}

	if lastErr != nil {
		return fmt.Errorf("gRPC registration failed after %d attempts: %v", maxAttempts, lastErr)
	}

	if regResp.Status == "active" {
		Logger.Info("Agent already approved!")
		return nil
	}

	Logger.Info("Agent registered (pending). Waiting for approval...")

	pollConn, err := grpc.NewClient(grpcDialTargetPrefix+grpcDialTarget, opts...)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client for status polling: %w", err)
	}
	defer pollConn.Close()
	pollClient := pb.NewIngestServiceClient(pollConn)

	clientToken := regResp.ClientToken
	for {
		time.Sleep(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		statusResp, err := pollClient.GetStatus(ctx, &pb.GetStatusRequest{
			ClientToken: clientToken,
		})
		cancel()

		if err != nil {
			Logger.Warnf("Poll failed: %v", err)
			continue
		}

		switch statusResp.Status {
		case "active":
			return nil
		case "rejected":
			return fmt.Errorf("registration rejected by user")
		}
	}
}
