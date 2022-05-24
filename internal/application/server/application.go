package server

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"cryptography-server/internal/entities"
	"cryptography-server/pkg/crypto/diffie_helman"
	customRsa "cryptography-server/pkg/crypto/rsa"
	"github.com/D3vR4pt0rs/logger"
	uuid2 "github.com/google/uuid"
)

type Controller interface {
	CreateNewConnection(powerKey *big.Int) (string, *big.Int)
	GetPartialKey(uuid string, partialKey *big.Int) *big.Int
	ValidateMessage(container entities.Container) bool
}

type application struct {
	clients map[string]entities.ClientInformation
}

func New() *application {
	return &application{
		clients: make(map[string]entities.ClientInformation),
	}
}

func (app application) CreateNewConnection(powerKey *big.Int) (string, *big.Int) {
	uuid, _ := uuid2.NewUUID()
	publicKey, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		logger.Error.Printf(err.Error())
	}
	privateKey, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		logger.Error.Printf(err.Error())
	}
	clientInformation := entities.ClientInformation{
		Id:     "",
		Client: diffie_helman.New(publicKey, privateKey),
	}

	clientInformation.Client.GeneratePartialKey(powerKey, true)
	app.clients[uuid.String()] = clientInformation

	logger.Info.Println("Generated partial key", app.clients[uuid.String()].Client.GetPartialKey())
	return uuid.String(), clientInformation.Client.GetPublicKey()
}

func (app application) GetPartialKey(uuid string, partialKey *big.Int) *big.Int {
	app.clients[uuid].Client.GenerateFullKey(partialKey, true)
	logger.Info.Println("Generated full key", app.clients[uuid].Client.GetFullKey())
	return app.clients[uuid].Client.GetPartialKey()
}

func (app application) ValidateMessage(container entities.Container) bool {
	decryptedHash := app.getHashFromSign(container.Sign, container.PublicKey)

	messageHash := md5.Sum([]byte(container.Message))
	computedHash := hex.EncodeToString(messageHash[:])
	logger.Info.Println(fmt.Sprintf("Received sign: %s.\n Computed sign: %s.", decryptedHash, computedHash))
	return decryptedHash == computedHash
}

func (app application) getHashFromSign(sign []int, publicKey *customRsa.PublicKey) string {
	hashCodes := customRsa.EncryptRSA(publicKey, sign)
	hash := ""
	for _, value := range hashCodes {
		hash += string(value)
	}
	return hash
}
