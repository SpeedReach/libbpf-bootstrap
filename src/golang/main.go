package main

import (
	"github.com/SpeedReach/ebpf_consensus/udp_nodes"
	"time"
)

func main() {
	go udp_nodes.StartServer(0, 7073)
	go udp_nodes.StartServer(1, 8073)
	time.Sleep(time.Second)
	udp_nodes.StartClient()
}
