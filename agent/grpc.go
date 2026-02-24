package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
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
// If grpcURL is provided, it takes precedence over serverHost
func buildGRPCTarget(serverHost, grpcURL string) string {
	// If explicit gRPC URL is provided, use it directly
	if grpcURL != "" {
		return normalizeGRPCTarget(grpcURL)
	}
	// Otherwise derive from server host
	grpcTarget := normalizeGRPCTarget(serverHost)
	if !strings.Contains(grpcTarget, ":") {
		grpcTarget = grpcTarget + ":9091"
	} else {
		grpcTarget = strings.Replace(grpcTarget, ":8080", ":9091", 1)
	}
	return grpcTarget
}

func normalizeGRPCTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "dns:///")
	target = strings.TrimPrefix(target, "passthrough:///")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")

	// Support passing full URLs like https://api.example.com:443/api/v1
	if parsed, err := url.Parse("https://" + target); err == nil && parsed.Host != "" {
		return parsed.Host
	}

	return target
}

func buildGRPCOpts(target string) []grpc.DialOption {
	// For known proxy domains with TLS, use secure credentials
	// Traefik handles TLS termination, so we need to use TLS to communicate with it
	tlsDomains := []string{"grpc.kerneleye.net", "grpc."}
	for _, domain := range tlsDomains {
		if strings.HasPrefix(target, domain) {
			// Use TLS credentials for Traefik with HTTP/2 + TLS
			return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))}
		}
	}
	// For targets explicitly using port 443, use TLS
	if strings.HasSuffix(target, ":443") {
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(nil))}
	}
	// Default: use insecure credentials for local development
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
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
	log.Printf("Connecting to gRPC server at %s...", grpcTarget)

	var regResp *pb.RegisterResponse
	var lastErr error
	const maxAttempts = 5

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(1<<(attempt-2)) * time.Second
			log.Printf("Retrying registration in %v (attempt %d/%d)...", backoff, attempt, maxAttempts)
			time.Sleep(backoff)
		}

		conn, err := grpc.NewClient(grpcDialTargetPrefix+grpcTarget, buildGRPCOpts(grpcTarget)...)
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

		log.Printf("Registration attempt %d/%d failed with transient transport error: %v", attempt, maxAttempts, err)
	}

	if lastErr != nil {
		return fmt.Errorf("gRPC registration failed after %d attempts: %v", maxAttempts, lastErr)
	}

	if regResp.Status == "active" {
		log.Println("Agent already approved!")
		return nil
	}

	log.Printf("Agent registered (pending). Waiting for approval...")

	pollConn, err := grpc.NewClient(grpcDialTargetPrefix+grpcTarget, buildGRPCOpts(grpcTarget)...)
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
			log.Printf("Poll failed: %v", err)
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
