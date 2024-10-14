package tcp_nodes

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

func StartClient() {
	// Define the server address (change "localhost" and port if needed)
	serverAddr := "localhost:7072"

	// Create a TCP connection
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Printf("Error connecting to server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Connected to TCP server at %s\n", serverAddr)

	for {
		// Create the message
		message := fmt.Sprintf("Hi %d from client!!\n", rand.Int())

		// Send the message to the server
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error sending data: %v\n", err)
			return
		}

		time.Sleep(time.Second)
	}
}
