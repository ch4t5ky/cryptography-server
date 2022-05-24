package client

import (
	"math/big"

	"cryptography-server/internal/entities"
)

type UserSettingsResponse struct {
	Id        string   `json:"id"`
	PublicKey *big.Int `json:"public_key"`
}

type PartialKeyResponse struct {
	PartialKey *big.Int `json:"partial_key"`
}

type MessagePayload struct {
	Uuid      string             `json:"uuid"`
	Container entities.Container `json:"container"`
}

type MessageResponse struct {
	Status bool `json:"status"`
}
