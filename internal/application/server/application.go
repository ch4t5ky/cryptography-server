package server

import (
	"crypto/rand"
	"math/big"

	"cryptography-server/internal/entities"
	"cryptography-server/pkg/crypto/diffie_helman"
	"github.com/D3vR4pt0rs/logger"
	uuid2 "github.com/google/uuid"
)

type Controller interface {
	CreateNewConnection(powerKey *big.Int) (string, *big.Int, error)
	GetPartialKey(uuid string, partialKey *big.Int) (*big.Int, error)
	// SendMessage(container entities.Container) (bool, error)
}

type application struct {
	clients map[string]entities.ClientInformation
}

func New() *application {
	return &application{
		clients: make(map[string]entities.ClientInformation),
	}
}

func (app application) CreateNewConnection(powerKey *big.Int) (string, *big.Int, error) {
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
	return uuid.String(), clientInformation.Client.GetPublicKey(), nil
}

func (app application) GetPartialKey(uuid string, partialKey *big.Int) (*big.Int, error) {
	app.clients[uuid].Client.GenerateFullKey(partialKey, true)
	logger.Info.Println("Generated full key", app.clients[uuid].Client.GetFullKey())
	return app.clients[uuid].Client.GetPartialKey(), nil
}
