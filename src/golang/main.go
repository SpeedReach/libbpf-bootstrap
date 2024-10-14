package main

import (
	"github.com/SpeedReach/ebpf_consensus/tcp_nodes"
	"github.com/SpeedReach/ebpf_consensus/udp_nodes"
	"time"
)

func main() {
	udp_start()
}

func udp_start() {
	go udp_nodes.StartServer(0, 7073)
	go udp_nodes.StartServer(1, 8073)
	time.Sleep(time.Second)
	udp_nodes.StartClient()
}

func tcp_start() {
	go tcp_nodes.StartServer(0, 7073)
	go tcp_nodes.StartServer(1, 8073)
	time.Sleep(time.Second)
	tcp_nodes.StartClient()
}
