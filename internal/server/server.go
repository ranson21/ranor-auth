package server

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ranson21/ranor-auth/internal/config"
	serverGRPC "github.com/ranson21/ranor-auth/internal/grpc"
	serverHTTP "github.com/ranson21/ranor-auth/internal/http"
	"github.com/ranson21/ranor-auth/internal/service"
	pb "github.com/ranson21/ranor-auth/proto"
	"github.com/ranson21/ranor-common/pkg/database/connection"
	"github.com/ranson21/ranor-common/pkg/logger"
	"github.com/ranson21/ranor-common/pkg/middleware"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	config     *config.Config
	httpServer *http.Server
	ginEngine  *gin.Engine
	grpcServer *grpc.Server
	logger     logger.Logger
	db         connection.Database
}

func New(cfg *config.Config, logger logger.Logger, db connection.Database) *Server {
	return &Server{
		db:     db,
		config: cfg,
		logger: logger,
	}
}

func (s *Server) SetupHTTP() {
	s.ginEngine = gin.New()
	s.ginEngine.Use(middleware.DefaultMiddlewares(s.logger)...)

	authService := service.NewAuthService(s.db)
	authHandler := serverHTTP.NewAuthHandler(authService)
	authHandler.RegisterRoutes(s.ginEngine)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.HTTPPort),
		Handler: s.ginEngine,
	}
}

func (s *Server) SetupGRPC() {
	server := grpc.NewServer()

	authService := service.NewAuthService(s.db)
	authServer := serverGRPC.NewAuthServer(authService)
	pb.RegisterAuthServiceServer(server, authServer)

	reflection.Register(server)
	s.grpcServer = server
}

func (s *Server) Start() error {
	go func() {
		s.logger.Info("Starting HTTP server", zap.Int("port", s.config.HTTPPort))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Failed to start HTTP server", zap.Error(err))
		}
	}()

	go func() {
		addr := fmt.Sprintf(":%d", s.config.GRPCPort)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			s.logger.Error("Failed to create gRPC listener", zap.Error(err))
			return
		}
		s.logger.Info("Starting gRPC server", zap.Int("port", s.config.GRPCPort))
		if err := s.grpcServer.Serve(listener); err != nil {
			s.logger.Error("Failed to start gRPC server", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error("Failed to shutdown HTTP server", zap.Error(err))
	}
	s.grpcServer.GracefulStop()
	return nil
}
