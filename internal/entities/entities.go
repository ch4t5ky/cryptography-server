package entities

import (
	"math/big"

	"cryptography-server/pkg/crypto/diffie_helman"
)

type Container struct {
	Message   string    `json:"message"`
	Sign      string    `json:"sign"`
	PublicKey PublicKey `json:"public_key"`
}

type PublicKey struct {
	E *big.Int `json:"e"`
	N *big.Int `json:"n"`
}

type ClientInformation struct {
	Id     string
	Client *diffie_helman.Algorithm
}
