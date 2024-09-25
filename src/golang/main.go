package main

import (
	"github.com/SpeedReach/ebpf_consensus/udp_nodes"
	"time"
)

func main() {
	go udp_nodes.StartServer(0, 50051)
	go udp_nodes.StartServer(1, 50052)
	time.Sleep(time.Second)
	udp_nodes.StartClient()
}
