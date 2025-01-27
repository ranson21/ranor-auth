package grpc

import (
	"context"

	"github.com/ranson21/ranor-auth/internal/service"
	pb "github.com/ranson21/ranor-auth/proto"
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
	claims, err := s.authService.ValidateAccessToken(ctx, req.Token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	return &pb.ValidateTokenResponse{
		Valid: true,
		Claims: &pb.TokenClaims{
			UserId:    (*claims)["sub"].(string),
			Email:     (*claims)["email"].(string),
			Name:      (*claims)["name"].(string),
			Provider:  (*claims)["provider"].(string),
			SessionId: (*claims)["session"].(string),
		},
	}, nil
}

func (s *AuthServer) GetSession(ctx context.Context, req *pb.GetSessionRequest) (*pb.GetSessionResponse, error) {
	session, err := s.authService.GetSession(ctx, req.SessionId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "session not found")
	}

	return &pb.GetSessionResponse{
		Session: &pb.Session{
			Id:        session.ID,
			UserId:    session.UserID,
			Email:     session.Email,
			Name:      session.Name,
			Provider:  string(session.Provider),
			CreatedAt: session.CreatedAt.Unix(),
			ExpiresAt: session.ExpiresAt.Unix(),
		},
	}, nil
}
