package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ranson21/ranor-auth/internal/config"
	"github.com/ranson21/ranor-auth/internal/server"
	dbConfig "github.com/ranson21/ranor-common/pkg/database/config"
	"github.com/ranson21/ranor-common/pkg/database/connection"
	"github.com/ranson21/ranor-common/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	// Create a new service config
	cfg := config.NewConfig()

	// Create the db connection
	db, err := connection.NewDB(dbConfig.NewDatabaseConfig(dbConfig.Environment(cfg.Env), "auth"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close() // Don't forget to close when done

	// Use the database
	if err := db.Ping(context.Background()); err != nil {
		log.Printf("Database connection error: %v", err)
	}

	// Setup the application logger
	log, err := logger.SetupLogger(logger.Environment(cfg.Env))
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	// Create a new server to handle HTTP and gRPC traffic
	srv := server.New(cfg, log, db)

	// Create the service protocols
	srv.SetupHTTP()
	srv.SetupGRPC()

	// Start the service
	if err := srv.Start(); err != nil {
		log.Error("Failed to start servers", zap.Error(err))
		os.Exit(1)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Failed to shutdown servers", zap.Error(err))
	}
}
