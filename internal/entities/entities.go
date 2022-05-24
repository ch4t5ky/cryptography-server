package entities

import (
	"cryptography-server/pkg/crypto/diffie_helman"
	customRsa "cryptography-server/pkg/crypto/rsa"
)

type Container struct {
	Message   []int                `json:"message"`
	Sign      []int                `json:"sign"`
	PublicKey *customRsa.PublicKey `json:"public_key"`
}

type ClientInformation struct {
	Id     string
	Client *diffie_helman.Algorithm
}
