package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
)

type Message struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload []byte `json:"payload"`
}

var (
	clients = make(map[string]net.Conn)
	mu      sync.Mutex
)
var dhPending = make(map[string]bool) // usernames awaiting DH public key

func main() {
	ln, err := net.Listen("tcp", ":3000")
	if err != nil {
		panic(err)
	}
	fmt.Println("Server listening on :3000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}
		go handleClient(conn)
	}
}

func DHExchange() {
	mu.Lock()
	defer mu.Unlock()

	if len(clients) == 2 {
		var usernames []string
		for name := range clients {
			usernames = append(usernames, name)
		}
		// Notify both clients to start DH exchange
		for i := 0; i < 2; i++ {
			peerMsg := Message{
				Type:    "start_dh",
				From:    "server",
				To:      usernames[i],
				Payload: []byte(usernames[1-i]), // send other client's name
			}
			data, _ := json.Marshal(peerMsg)
			clients[usernames[i]].Write(append(data, '\n'))
		}
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	// Expect initial handshake
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading handshake:", err)
		return
	}

	var handshake Message
	if err := json.Unmarshal(buf[:n], &handshake); err != nil {
		fmt.Println("Invalid handshake message:", err)
		return
	}

	username := handshake.From

	// Register client
	mu.Lock()
	if _, exists := clients[username]; exists {
		mu.Unlock()
		fmt.Fprintf(conn, `{"type":"error","payload":"username already in use"}`+"\n")
		return
	}
	clients[username] = conn
	mu.Unlock()

	fmt.Println("Handshake received. Connected:", username)
	DHExchange()

	// Listen for further messages from this client
	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("Error reading from", username, ":", err)
			}
			break
		}
		go relayMessage(conn, buf[:n])
	}

	// Remove client on disconnect
	mu.Lock()
	delete(clients, username)
	mu.Unlock()
	fmt.Println("Disconnected:", username)
}

func relayMessage(from net.Conn, data []byte) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Println("Invalid message JSON:", err)
		return
	}

	if msg.Type == "handshake" {
		// Handshake should only occur once during connection
		fmt.Println("Ignored secondary handshake from:", msg.From)
		return
	}
	if msg.Type == "dh_pub" {
		// Relay DH pub key to the other client
		mu.Lock()
		delete(dhPending, msg.From)

		// Find the other connected client
		var otherConn net.Conn
		for name, conn := range clients {
			if name != msg.From {
				otherConn = conn
				break
			}
		}
		mu.Unlock()

		if otherConn != nil {
			// Relay public key to the other client
			relayMsg := Message{
				Type:    "dh_pub",
				From:    msg.From,
				To:      msg.To,
				Payload: msg.Payload,
			}
			data, _ := json.Marshal(relayMsg)
			otherConn.Write(append(data, '\n'))
		}
		return
	}

	mu.Lock()
	targetConn, ok := clients[msg.To]
	mu.Unlock()

	if ok {
		_, err := targetConn.Write(data)
		if err != nil {
			fmt.Println("Failed to send message to", msg.To, ":", err)
		}
	} else {
		fmt.Println("Client", msg.To, "not connected")
		fmt.Println("Currently connected clients:", clients)

		errMsg := Message{
			Type:    "error",
			From:    "server",
			To:      msg.From,
			Payload: []byte(fmt.Sprintf("Client %s not connected", msg.To)),
		}
		dataOut, _ := json.Marshal(errMsg)
		from.Write(append(dataOut, '\n'))
	}
}
