package grpc_nodes

import (
	"context"
	"github.com/SpeedReach/ebpf_consensus/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"time"
)

func StartClient() {
	// Set up a connection to the server.

	conn, err := grpc.NewClient("localhost:50050", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewHelloServiceClient(conn)

	for {
		ctx := context.Background()
		r, err := c.Hi(ctx, &pb.HelloRequest{A: 1})
		if err != nil {
			log.Fatalf("Could not greet: %v", err)
		}
		log.Printf("Greeting: %d", r.B)

		time.Sleep(time.Second)
	}

}
