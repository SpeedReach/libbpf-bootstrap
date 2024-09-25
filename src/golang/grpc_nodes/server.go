package grpc_nodes

import (
	"context"
	"fmt"
	"github.com/SpeedReach/ebpf_consensus/pb"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"google.golang.org/grpc"
	"log"
	"net"
)

type Service struct {
	pb.UnimplementedHelloServiceServer
}

func (Service) Hi(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{
		B: 45,
	}, nil
}

func StartServer() {
	// Listen on a TCP port
	go listenTcp()
	server := Service{}
	lis, err := net.Listen("tcp", ":50051")

	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Create a new gRPC server
	grpcServer := grpc.NewServer()

	// Register the Greeter service
	pb.RegisterHelloServiceServer(grpcServer, &server)

	log.Println("Server is listening on port 50051...")
	// Start serving
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

}

func listenTcp() {
	// Open the device for capturing
	handle, err := pcap.OpenLive("lo", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set a filter for TCP packets destined to your gRPC port (e.g., 50051)
	if err := handle.SetBPFFilter("tcp port 50051"); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			for idx, option := range tcp.Options {
				fmt.Printf("%d %s %s\n", idx, option.String(), option.OptionType.String())
			}
			print("\n")
		}
	}

}
