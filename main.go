// client.go
package main

import (
	"bufio"
	"e2e-chat/common"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
)

type Message struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload []byte `json:"payload"`
}

var prime = func() *big.Int {
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
	return p
}()
var priv *big.Int
var shared [32]byte

func process(data []byte, conn net.Conn, from string) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		fmt.Println("Invalid message JSON:", err)
		return
	}

	switch msg.Type {
	case "start_dh":
		to := string(msg.Payload) // peer username
		fmt.Println("**Starting DH key exchange: ", to)

		// DH parameters (same as earlier)
		gen := big.NewInt(2)
		sec, pub, _ := common.DHGenKeyPair(prime, gen)
		priv = sec

		// Send public key
		pubMsg := Message{
			Type:    "dh_pub",
			From:    from,
			To:      to,
			Payload: pub.Bytes(),
		}
		data, _ := json.Marshal(pubMsg)
		conn.Write(append(data, '\n'))

	case "dh_pub":
		// receive peer public key
		peerPub := new(big.Int).SetBytes(msg.Payload)

		key, _, _ := common.DHDeriveSymmetricKey(peerPub, priv, prime)
		shared = key
		fmt.Printf("**Shared secret: %x**\n", key)

	case "message":
		dec, _ := common.DecryptAES(shared, msg.Payload)
		fmt.Printf(">>From %s: %s\n", msg.From, string(dec))
	}

	//fmt.Println("> ")
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Your username: ")
	from, _ := reader.ReadString('\n')
	from = strings.TrimSpace(from)

	fmt.Print("Talk to (username): ")
	to, _ := reader.ReadString('\n')
	to = strings.TrimSpace(to)

	conn, err := net.Dial("tcp", "localhost:3000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// DH setup, hardcoded p and g for now
	//secret, _ := rand.Int(rand.Reader, new(big.Int).Sub(prime, big.NewInt(2)))

	// Send public key to the other client
	/*
		keyExchangeMsg := Message{
			Type:    "key-exchange",
			From:    from,
			To:      to,
			Payload: pubBytes,
		}
		msgBytes, _ := json.Marshal(keyExchangeMsg)
		conn.Write(msgBytes)
	*/

	// Start listening
	go func() {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			data := scanner.Bytes()
			process(data, conn, from)
		}
	}()

	fmt.Printf("Sender: %s \nTo: %s\n", from, to)
	fmt.Println("Handshake to server")

	// Handshake server
	synMsg := Message{
		Type:    "handshake",
		From:    from,
		To:      "server",
		Payload: []byte{},
	}

	msgBytes, _ := json.Marshal(synMsg)
	conn.Write(msgBytes)

	// Intake user input
	console := bufio.NewScanner(os.Stdin)
	for {
		//fmt.Print("> ")
		if !console.Scan() {
			break
		}

		text := console.Text()
		enc, _ := common.EncryptAES(shared, []byte(text))
		msg := Message{
			Type:    "message",
			From:    from,
			To:      to,
			Payload: enc,
		}

		data, err := json.Marshal(msg)
		if err != nil {
			fmt.Println("JSON Marshal Error: ", err)
			continue
		}

		conn.Write(append(data, '\n'))
	}
}
