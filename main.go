package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ranson21/ranor-auth/internal/auth"
	"github.com/ranson21/ranor-auth/internal/config"
	"github.com/ranson21/ranor-auth/internal/secrets"
	"github.com/ranson21/ranor-auth/internal/server"
	dbConfig "github.com/ranson21/ranor-common/pkg/database/config"
	"github.com/ranson21/ranor-common/pkg/database/connection"
	"github.com/ranson21/ranor-common/pkg/logger"
	"go.uber.org/zap"
)

func main() {
	// Create a new service config
	cfg := config.NewConfig()

	// Setup the application logger
	log, err := logger.SetupLogger(logger.Environment(cfg.Env))
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	ctx := context.Background()
	if err := secrets.InitDefaultManager(ctx, 5*time.Minute); err != nil {
		log.Fatal("Failed to initialize secrets manager", zap.Error(err))
	}

	// Create the firebase app
	app, err := auth.New(os.Getenv("GCP_PROJECT"), os.Getenv("FIREBASE_SECRET_ID"))
	if err != nil {
		log.Fatal("Failed to initialize firebase app", zap.Error(err))
	}

	// Create the db connection
	db, err := connection.NewDB(dbConfig.NewDatabaseConfig(dbConfig.Environment(cfg.Env), "auth"))
	if err != nil {
		log.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer db.Close() // Don't forget to close when done

	// Use the database
	if err := db.Ping(context.Background()); err != nil {
		log.Fatal("Failed to connect to database", zap.Error(err))
	}

	// Create a new server to handle HTTP and gRPC traffic
	srv := server.New(cfg, log, db, app)

	// Create the service protocols
	srv.SetupHTTP(ctx)
	srv.SetupGRPC(ctx)

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
