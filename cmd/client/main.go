package main

import (
	"fmt"
	"math/big"

	"cryptography-server/internal/application/client"
)

const (
	serverHost = "0.0.0.0"
	serverPort = "5000"
)

func main() {
	var publicKey, privateKey int
	fmt.Println("Enter private key for Diffie-Hellman exchange:")
	fmt.Scanf("%d\n", &privateKey)
	fmt.Println("Enter public key for Diffie-Hellman exchange:")
	fmt.Scanf("%d\n", &publicKey)

	app := client.New(client.Config{
		Host:       serverHost,
		Port:       serverPort,
		PublicKey:  big.NewInt(int64(publicKey)),
		PrivateKey: big.NewInt(int64(privateKey)),
	})

	uuid := app.CreateConnection()
	app.GenerateFullKey(uuid)
}
