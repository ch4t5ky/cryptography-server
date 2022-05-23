package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"cryptography-server/pkg/crypto/diffie_helman"
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
