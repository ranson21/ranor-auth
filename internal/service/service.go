package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/ranson21/ranor-auth/internal/secrets"
	"github.com/ranson21/ranor-common/pkg/database/connection"
)

type AuthService struct {
	db                  connection.Database
	fb                  *firebase.App
	auth                *auth.Client
	hmac                *HMACConfig
	sessionCookieName   string
	sessionCookieExpire time.Duration
	accessTokenExpire   time.Duration
}

func NewAuthService(db connection.Database, fb *firebase.App) *AuthService {
	ctx := context.Background()
	authClient, err := fb.Auth(ctx)
	if err != nil {
		log.Fatalf("error initializing Firebase auth client: %v", err)
	}

	hmacConfig, err := NewHMACConfig()
	if err != nil {
		log.Fatalf("error initializing HMAC config: %v", err)
	}

	return &AuthService{
		db:                  db,
		fb:                  fb,
		auth:                authClient,
		hmac:                hmacConfig,
		sessionCookieName:   "session",
		sessionCookieExpire: 3600 * time.Second,
		accessTokenExpire:   3600 * time.Second,
	}
}

// Core business logic that can be shared between gRPC and HTTP
func (s *AuthService) ValidateToken(ctx context.Context, token string) (bool, error) {
	// TODO: Implement token validation
	return false, nil
}

func (s *AuthService) CreateUser(ctx context.Context, email, password string) error {
	// TODO: Implement user creation
	return nil
}

func (s *AuthService) CreateAccessToken(claims jwt.MapClaims) (string, error) {
	if len(s.hmac.secrets) == 0 {
		return "", fmt.Errorf("no secrets available for signing")
	}

	// Always use the most recent secret for signing
	secret := s.hmac.secrets[0]

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = secret.KeyID

	return token.SignedString([]byte(secret.Secret))
}

func (s *AuthService) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	var lastErr error

	// Try each secret, starting with the most recent
	for _, secret := range s.hmac.secrets {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret.Secret), nil
		})

		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				return claims, nil
			}
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to validate token with any secret: %v", lastErr)
}

/**
 * Begin KMS Definition
 */

type JWTSecret struct {
	Secret   string            `json:"secret"`
	Version  int               `json:"version"`
	Created  string            `json:"created"`
	KeyID    string            `json:"key_id"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type HMACConfig struct {
	secrets []JWTSecret
	keyID   string
}

func NewHMACConfig() (*HMACConfig, error) {
	ctx := context.Background()
	secretName := os.Getenv("JWT_SECRET_ID")
	if secretName == "" {
		return nil, fmt.Errorf("JWT_SECRET_ID environment variable is required")
	}

	sm, err := secrets.GetDefaultManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets manager: %v", err)
	}

	rawSecret, err := sm.GetSecret(ctx, os.Getenv("GCP_PROJECT"), secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT secret: %v", err)
	}

	// Try to parse as a JWTSecret first
	var secret JWTSecret
	if err := json.Unmarshal(rawSecret, &secret); err != nil {
		// Handle legacy format - treat raw secret as the secret string
		return &HMACConfig{
			secrets: []JWTSecret{{
				Secret:  string(rawSecret),
				Version: 1,
				Created: time.Now().UTC().Format(time.RFC3339),
				KeyID:   time.Now().UTC().Format("20060102"),
			}},
		}, nil
	}

	return &HMACConfig{
		secrets: []JWTSecret{secret},
		keyID:   secret.KeyID,
	}, nil
}
