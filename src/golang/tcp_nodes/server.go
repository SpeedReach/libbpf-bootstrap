package tcp_nodes

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func StartServer(serverId int, port int) {
	addr, err := resolveTCPAddr("localhost", port)
	if err != nil {
		panic(err)
	}

	listener, err := createTCPListener(addr)
	if err != nil {
		panic(err)
	}
	listenAndServe(serverId, listener)
}

func listenAndServe(serverId int, listener net.Listener) {
	defer listener.Close()

	log.Printf("TCP server listening on %s\n", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v\n", err)
			continue
		}
		go handleConnection(serverId, conn)
	}
}

func handleConnection(serverId int, conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024) // Adjust buffer size as needed
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from TCP connection: %v\n", err)
			}
			return
		}

		if n < 4 {
			log.Printf("Received message too short\n")
			continue
		}

		var sequence uint32 = binary.LittleEndian.Uint32(buffer[n-4 : n])
		message := string(buffer[:n-4])
		log.Printf("Server %d %d Received %d bytes from %s: %s\n", serverId, sequence, n, conn.RemoteAddr(), message)
	}
}

func createTCPListener(tcpAddr *net.TCPAddr) (net.Listener, error) {
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("error listening on TCP address %v: %v", tcpAddr, err)
	}
	return listener, nil
}

func resolveTCPAddr(ip string, port int) (*net.TCPAddr, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("error resolving TCP address %s: %v", addr, err)
	}
	return tcpAddr, nil
}
