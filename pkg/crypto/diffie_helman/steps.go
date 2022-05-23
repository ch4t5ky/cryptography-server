package diffie_helman

import (
	"math/big"
)

type Parameters struct {
	PublicKey        *big.Int
	PrivateKey       *big.Int
	ForeignPublicKey *big.Int
	PartialKey       *big.Int
	FullKey          *big.Int
}

type Algorithm struct {
	params Parameters
}

func New(publicKey *big.Int, privateKey *big.Int) *Algorithm {
	return &Algorithm{
		params: Parameters{
			PublicKey:        publicKey,
			PrivateKey:       privateKey,
			ForeignPublicKey: new(big.Int),
			PartialKey:       new(big.Int),
			FullKey:          new(big.Int),
		},
	}
}

func (algo Algorithm) GeneratePartialKey(publicKey *big.Int, isPower bool) {
	partialKey := new(big.Int)
	algo.params.ForeignPublicKey.Set(publicKey)
	if isPower {
		partialKey.Exp(algo.params.ForeignPublicKey, algo.params.PrivateKey, algo.params.PublicKey)
	} else {
		partialKey.Exp(algo.params.PublicKey, algo.params.PrivateKey, algo.params.ForeignPublicKey)
	}

	algo.params.PartialKey.Set(partialKey)
}

func (algo Algorithm) GenerateFullKey(partialKey *big.Int, isModule bool) {
	fullKey := new(big.Int)
	if isModule {
		fullKey.Exp(partialKey, algo.params.PrivateKey, algo.params.PublicKey)
	} else {
		fullKey.Exp(partialKey, algo.params.PrivateKey, algo.params.ForeignPublicKey)
	}
	algo.params.FullKey.Set(fullKey)
}

func (algo Algorithm) GetPublicKey() *big.Int {
	return algo.params.PublicKey
}

func (algo Algorithm) GetPartialKey() *big.Int {
	return algo.params.PartialKey
}

func (algo Algorithm) GetFullKey() *big.Int {
	return algo.params.FullKey
}
