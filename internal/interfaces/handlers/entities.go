package handlers

import (
	"math/big"

	"cryptography-server/internal/entities"
)

type SetupPayload struct {
	PublicKey int `json:"public_key"`
}

type PartialKeyPayload struct {
	Uuid       string `json:"uuid"`
	PartialKey int    `json:"partial_key"`
}

type MessagePayload struct {
	Uuid      string             `json:"uuid"`
	Container entities.Container `json:"container"`
}

type UserSettingsResponse struct {
	Id        string   `json:"id"`
	PublicKey *big.Int `json:"public_key"`
}

type PartialKeyResponse struct {
	PartialKey *big.Int `json:"partial_key"`
}

type MessageResponse struct {
	Status bool `json:"status"`
}
