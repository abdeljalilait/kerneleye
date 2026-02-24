package main

import (
	"context"
	"crypto/tls"
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

// buildGRPCTarget converts server host to gRPC target address
// If grpcURL is provided, it takes precedence over serverHost.
// The returned value may include an explicit scheme.
func buildGRPCTarget(serverHost, grpcURL string) string {
	// If explicit gRPC URL is provided, use it directly
	if grpcURL != "" {
		return strings.TrimSpace(grpcURL)
	}
	// Otherwise derive from server host
	grpcTarget := strings.TrimSpace(serverHost)
	if !strings.Contains(grpcTarget, ":") {
		grpcTarget = grpcTarget + ":9091"
	} else {
		grpcTarget = strings.Replace(grpcTarget, ":443", ":9091", 1)
	}
	return grpcTarget
}

// buildGRPCDialTarget returns the target format expected by grpc.NewClient.
// It strips URL schemes and normalizes default ports where possible.
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

func grpcTransportForTarget(target string) bool {
	target = strings.TrimSpace(target)

	if strings.Contains(target, "://") {
		if parsed, err := url.Parse(target); err == nil {
			switch strings.ToLower(parsed.Scheme) {
			case "https", "grpcs":
				return true
			case "http", "grpc", "h2c":
				return false
			}
			target = parsed.Host
		}
	}

	hostPort := target
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 {
		if hostPort[idx+1:] == "443" {
			// Conventional TLS endpoint when no explicit scheme is provided.
			return true
		}
	}

	// Default to plaintext for local and self-hosted direct gRPC listeners.
	return false
}

func buildGRPCOpts(target string) []grpc.DialOption {
	useTLS := grpcTransportForTarget(target)
	if !useTLS {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}

	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{}))}
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
		strings.Contains(msg, "missing http content-type") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "transport is closing") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "server closed the stream") ||
		strings.Contains(msg, "eof") {
		return true
	}

	return false
}

// registerAndWaitForApproval registers the agent and polls for approval
func registerAndWaitForApproval(apiKey, serverHost, grpcURL string) error {
	hostname, _ := os.Hostname()
	ipAddress := getPublicIP()

	grpcTarget := buildGRPCTarget(serverHost, grpcURL)
	grpcDialTarget := buildGRPCDialTarget(grpcTarget)
	Logger.Infof("Connecting to gRPC server at %s...", grpcTarget)

	var regResp *pb.RegisterResponse
	var lastErr error
	const maxAttempts = 5

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(1<<(attempt-2)) * time.Second
			Logger.Infof("Retrying registration in %v (attempt %d/%d)...", backoff, attempt, maxAttempts)
			time.Sleep(backoff)
		}

		conn, err := grpc.NewClient(grpcDialTargetPrefix+grpcDialTarget, buildGRPCOpts(grpcTarget)...)
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

	pollConn, err := grpc.NewClient(grpcDialTargetPrefix+grpcDialTarget, buildGRPCOpts(grpcTarget)...)
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
