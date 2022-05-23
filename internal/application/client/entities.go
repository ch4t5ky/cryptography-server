package client

import "math/big"

type UserSettingsResponse struct {
	Id        string   `json:"id"`
	PublicKey *big.Int `json:"public_key"`
}

type PartialKeyResponse struct {
	PartialKey *big.Int `json:"partial_key"`
}
