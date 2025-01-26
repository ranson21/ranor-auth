package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/ranson21/ranor-common/pkg/logger"
	"github.com/ranson21/ranor-common/pkg/middleware"
)

func main() {
	engine := gin.New()
	log, err := logger.SetupLogger(logger.Environment(os.Getenv("ENV")))
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	// Attach middleware
	engine.Use(middleware.DefaultMiddlewares(log)...)

	// Start the service
	engine.Run()
}
