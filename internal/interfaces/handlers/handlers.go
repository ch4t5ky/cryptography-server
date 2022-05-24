package handlers

import (
	"encoding/json"
	"math/big"
	"net/http"

	"cryptography-server/internal/application/server"

	"github.com/D3vR4pt0rs/logger"
	"github.com/gorilla/mux"
)

func setup(app server.Controller) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info.Println("Get request for creating session")
		errorMessage := "Error create connection"

		setupPayload := SetupPayload{}
		err := json.NewDecoder(r.Body).Decode(&setupPayload)
		if err != nil {
			logger.Error.Printf("Failed to decode payload. Got %v", err)
			http.Error(w, errorMessage, http.StatusBadRequest)
			return
		}

		id, publicKey := app.CreateNewConnection(big.NewInt(int64(setupPayload.PublicKey)))

		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(UserSettingsResponse{Id: id, PublicKey: publicKey})
	})
}

func exchangePartial(app server.Controller) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info.Println("Get request for exchange partial keys")
		errorMessage := "Error create connection"

		partialKeyPayload := PartialKeyPayload{}
		err := json.NewDecoder(r.Body).Decode(&partialKeyPayload)
		if err != nil {
			logger.Error.Printf("Failed to decode payload. Got %v", err)
			http.Error(w, errorMessage, http.StatusBadRequest)
			return
		}

		partialKey := app.GetPartialKey(partialKeyPayload.Uuid, big.NewInt(int64(partialKeyPayload.PartialKey)))

		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(PartialKeyResponse{PartialKey: partialKey})
	})
}

func validateMessage(app server.Controller) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info.Println("Get request for getting message")
		errorMessage := "Error receive message"

		messagePayload := MessagePayload{}
		err := json.NewDecoder(r.Body).Decode(&messagePayload)
		if err != nil {
			logger.Error.Printf("Failed to decode payload. Got %v", err)
			http.Error(w, errorMessage, http.StatusBadRequest)
			return
		}

		status := app.ValidateMessage(messagePayload.Container)

		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(MessageResponse{Status: status})
	})

}

func Make(r *mux.Router, app server.Controller) {
	apiUri := "/api"
	serviceRouter := r.PathPrefix(apiUri).Subrouter()
	serviceRouter.Handle("/setup", setup(app)).Methods("POST")
	serviceRouter.Handle("/partial", exchangePartial(app)).Methods("POST")
	serviceRouter.Handle("/message", validateMessage(app)).Methods("POST")
}
