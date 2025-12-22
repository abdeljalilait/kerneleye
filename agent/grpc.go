package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	pb "github.com/kerneleye/proto/kerneleye/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// buildGRPCTarget converts server host to gRPC target address
func buildGRPCTarget(serverHost string) string {
	grpcTarget := serverHost
	if !strings.Contains(grpcTarget, ":") {
		grpcTarget = grpcTarget + ":9091"
	} else {
		grpcTarget = strings.Replace(grpcTarget, ":8080", ":9091", 1)
	}
	return grpcTarget
}

func buildGRPCOpts(target string) []grpc.DialOption {
	if strings.HasSuffix(target, ":443") {
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(nil))}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}

// registerAndWaitForApproval registers the agent and polls for approval
func registerAndWaitForApproval(apiKey, serverHost string) error {
	hostname, _ := os.Hostname()
	ipAddress := getPublicIP()

	grpcTarget := buildGRPCTarget(serverHost)

	var opts []grpc.DialOption
	if strings.HasSuffix(grpcTarget, ":443") {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(nil)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	log.Printf("Connecting to gRPC server at %s...", grpcTarget)

	conn, err := grpc.NewClient("passthrough:///"+grpcTarget, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewIngestServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	regResp, err := client.Register(ctx, &pb.RegisterRequest{
		UserId:    apiKey,
		Hostname:  hostname,
		IpAddress: ipAddress,
	})
	if err != nil {
		return fmt.Errorf("gRPC registration failed: %v", err)
	}

	if regResp.Status == "active" {
		log.Println("Agent already approved!")
		return nil
	}

	log.Printf("Agent registered (pending). Waiting for approval...")

	clientToken := regResp.ClientToken
	for {
		time.Sleep(5 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		statusResp, err := client.GetStatus(ctx, &pb.GetStatusRequest{
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
