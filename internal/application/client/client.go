package client

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"cryptography-server/internal/entities"
	"cryptography-server/pkg/crypto/diffie_helman"
	customRsa "cryptography-server/pkg/crypto/rsa"
	"github.com/D3vR4pt0rs/logger"
)

type Config struct {
	Host       string
	Port       string
	PublicKey  *big.Int
	PrivateKey *big.Int
}

type Client struct {
	dhClient   *diffie_helman.Algorithm
	httpClient *http.Client
	url        string
}

func New(cnfg Config) *Client {
	return &Client{
		dhClient:   diffie_helman.New(cnfg.PublicKey, cnfg.PrivateKey),
		httpClient: &http.Client{},
		url:        fmt.Sprintf("http://%s:%s/api", cnfg.Host, cnfg.Port),
	}
}

func (c Client) CreateConnection() string {
	url := fmt.Sprintf("%s/setup", c.url)

	data := []byte(fmt.Sprintf(`{"public_key":%d}`, c.dhClient.GetPublicKey()))

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		logger.Error.Fatal("Error reading request. ", err)
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(request)
	if err != nil {
		logger.Error.Fatalf("Error reading response. ", err)
	}
	defer resp.Body.Close()

	var userSettings UserSettingsResponse
	err = json.NewDecoder(resp.Body).Decode(&userSettings)
	if err != nil {
		logger.Error.Printf("Failed to parse body: %s", err.Error())
	}

	c.dhClient.GeneratePartialKey(userSettings.PublicKey, false)
	logger.Info.Println("Generated partial key", c.dhClient.GetPartialKey())
	return userSettings.Id
}

func (c Client) GenerateFullKey(uuid string) {
	url := fmt.Sprintf("%s/partial", c.url)
	data := []byte(fmt.Sprintf(`{"uuid": "%s", "partial_key":%d}`, uuid, c.dhClient.GetPartialKey()))

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		logger.Error.Fatal("Error reading request. ", err)
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(request)
	if err != nil {
		logger.Error.Fatalf("Error reading response. ", err)
	}
	defer resp.Body.Close()

	var partialKeyResponse PartialKeyResponse
	err = json.NewDecoder(resp.Body).Decode(&partialKeyResponse)
	if err != nil {
		logger.Error.Printf("Failed to parse body: %s", err.Error())
	}

	c.dhClient.GenerateFullKey(partialKeyResponse.PartialKey, false)

	logger.Info.Println("Generated full key", c.dhClient.GetFullKey())
}

func (c Client) SendMessage(message string, uuid string, publicKey *customRsa.PublicKey, privateKey *customRsa.PrivateKey) bool {
	hash := md5.Sum([]byte(message))

	hexHash := hex.EncodeToString(hash[:])
	fmt.Println(hexHash)

	sign := c.getSignFromHash(hexHash, privateKey)
	fmt.Println(sign)

	container := entities.Container{Message: message, Sign: sign, PublicKey: publicKey}
	jsonData, err := json.Marshal(MessagePayload{Uuid: uuid, Container: container})
	url := fmt.Sprintf("%s/message", c.url)

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		logger.Error.Fatal("Error reading request. ", err)
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(request)
	if err != nil {
		logger.Error.Fatalf("Error reading response. ", err)
	}
	defer resp.Body.Close()
	return true
}

func (c Client) getSignFromHash(hash string, privateKey *customRsa.PrivateKey) []int {
	var hashCodes []int
	for _, letter := range hash {
		hashCodes = append(hashCodes, int(letter))
	}
	sign := customRsa.DecryptRSA(privateKey, hashCodes)
	return sign
}

func (c Client) getHashFromSign(sign []int, publicKey *customRsa.PublicKey) string {
	hashCodes := customRsa.EncryptRSA(publicKey, sign)
	hash := ""
	for _, value := range hashCodes {
		hash += string(value)
	}
	return hash
}
