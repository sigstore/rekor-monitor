package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/sigstore/rekor-monitor/internal/monitorGRPC"
	"google.golang.org/grpc"
)

func main() {
	port := os.Getenv("GRPC_PORT")

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatal(err)
	}

	grpcServer := grpc.NewServer()
	monitorGRPC.RegisterMonitorServiceServer(grpcServer, monitorGRPC.NewServer())
	log.Printf("Monitor gRPC service starting at localhost:%s\n", port)
	if err = grpcServer.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
