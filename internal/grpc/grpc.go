package grpc

import (
	"context"

	"github.com/ranson21/ranor-auth/internal/service"
	pb "github.com/ranson21/ranor-auth/proto" // Your generated protobuf code
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	authService *service.AuthService
}

func NewAuthServer(authService *service.AuthService) *AuthServer {
	return &AuthServer{
		authService: authService,
	}
}

func (s *AuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	valid, err := s.authService.ValidateToken(ctx, req.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &pb.ValidateTokenResponse{
		Valid: valid,
	}, nil
}
