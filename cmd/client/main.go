package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"

	"cryptography-server/internal/application/client"
	customRsa "cryptography-server/pkg/crypto/rsa"
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

	var p, q int
	for {
		fmt.Println("Enter parameter p for RSA:")
		fmt.Scanf("%d\n", &p)
		fmt.Println("Enter parameter q for RSA:")
		fmt.Scanf("%d\n", &q)
		if big.NewInt(int64(p)).ProbablyPrime(0) && big.NewInt(int64(q)).ProbablyPrime(0) {
			break
		}
		fmt.Println("Numbers not prime. Enter another")
	}

	rsaPublicKey, rsaPrivateKey := customRsa.GenerateKeys(big.NewInt(int64(p)), big.NewInt(int64(q)))

	scanner := bufio.NewScanner(os.Stdin)

	var answer string
	var message string
	for {
		fmt.Println("Do you want to send a message? Enter y or n.")
		fmt.Scanln(&answer)
		if answer == "n" {
			os.Exit(0)
		} else if answer != "y" {
			fmt.Println("Didn't recognized your answer.")
			continue
		}

		fmt.Println("Enter your message: ")
		if scanner.Scan() {
			message = scanner.Text()
		}

		status := app.SendMessage(message, uuid, rsaPublicKey, rsaPrivateKey)
		if status {
			fmt.Println("Sending message succeed")
		} else {
			fmt.Println("Something wrong")
		}
	}
}
