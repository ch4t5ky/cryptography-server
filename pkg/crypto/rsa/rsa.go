package rsa

import (
	"math/big"
)

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	N *big.Int
	D *big.Int
}

func GenerateKeys(p *big.Int, q *big.Int) (*PublicKey, *PrivateKey) {
	n := new(big.Int).Set(p)
	n.Mul(n, q)

	// theta(n) = (p-1)(q-1)
	p.Sub(p, big.NewInt(1))
	q.Sub(q, big.NewInt(1))
	theta := new(big.Int).Set(p)
	theta.Mul(theta, q)

	// e as recommended by PKCS#1 (RFC 2313)
	e := big.NewInt(65537)

	d := new(big.Int).ModInverse(e, theta)

	pub := &PublicKey{N: n, E: e}
	priv := &PrivateKey{N: n, D: d}
	return pub, priv
}

func decrypt(private *PrivateKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, private.D, private.N)
	return m
}

func encrypt(public *PublicKey, c *big.Int) *big.Int {
	m := new(big.Int)
	m.Exp(c, public.E, public.N)
	return m
}

func EncryptRSA(pub *PublicKey, message []int) []int {
	var encryptedMessage []int
	for _, letter := range message {
		encryptedLetter := encrypt(pub, big.NewInt(int64(letter)))
		encryptedMessage = append(encryptedMessage, int(encryptedLetter.Int64()))
	}
	return encryptedMessage
}

func DecryptRSA(priv *PrivateKey, message []int) []int {
	var decryptedMessage []int
	for _, letter := range message {
		decryptedLetter := decrypt(priv, big.NewInt(int64(letter)))
		decryptedMessage = append(decryptedMessage, int(decryptedLetter.Int64()))
	}
	return decryptedMessage
}
