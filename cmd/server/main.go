package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"cryptography-server/internal/application/server"
	"cryptography-server/internal/interfaces/handlers"
	"github.com/D3vR4pt0rs/logger"
	"github.com/gorilla/mux"
)

func main() {
	app := server.New()

	router := mux.NewRouter()
	handlers.Make(router, app)
	srv := &http.Server{
		Addr:    ":5000",
		Handler: router,
	}

	go func() {
		listener := make(chan os.Signal, 1)
		signal.Notify(listener, os.Interrupt, syscall.SIGTERM)
		logger.Info.Println("Received a shutdown signal:", <-listener)

		if err := srv.Shutdown(context.Background()); err != nil && err != http.ErrServerClosed {
			logger.Error.Println("Failed to gracefully shutdown ", err)
		}
	}()

	logger.Info.Println("[*]  Listening...")
	if err := srv.ListenAndServe(); err != nil {
		logger.Error.Println("Failed to listen and serve ", err)
	}

	logger.Critical.Fatal("Server shutdown")
}
