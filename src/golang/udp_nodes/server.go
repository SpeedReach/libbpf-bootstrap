package udp_nodes

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

func StartServer(serverId int, port int) {
	addr, err := resolveUDPAddr("localhost", port)
	if err != nil {
		panic(err)
	}

	conn, err := createUDPListener(addr)
	if err != nil {
		panic(err)
	}
	listenAndServe(serverId, conn)
}

func listenAndServe(serverId int, conn *net.UDPConn) {
	defer conn.Close()
	buffer := make([]byte, 1024) // Adjust buffer size as needed

	log.Printf("UDP server listening on %s:%d\n", conn.LocalAddr().(*net.UDPAddr).IP, conn.LocalAddr().(*net.UDPAddr).Port)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v\n", err)
			continue // Continue listening even if there's an error
		}
		var sequence uint32 = binary.LittleEndian.Uint32(buffer[n-4 : n])
		message := string(buffer[:n-4])
		log.Printf("Server %d %d Received %d bytes from %s: %s\n", serverId, sequence, n, addr, message)
	}
}

func createUDPListener(udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("error listening on UDP address %v: %v", udpAddr, err)
	}
	return conn, nil
}

func resolveUDPAddr(ip string, port int) (*net.UDPAddr, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("error resolving UDP address %s: %v", addr, err)
	}
	return udpAddr, nil
}
