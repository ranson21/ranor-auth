// pkg/auth/token/validator.go
package token

import (
	"context"
	"fmt"
	"os"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/ranson21/ranor-auth/internal/auth/claims"
	"google.golang.org/api/option"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*claims.Claims, error)
	VerifyPermissions(claims *claims.Claims, required []claims.Permission) bool
}

type firebaseValidator struct {
	client *auth.Client
}

func NewTokenValidator(ctx context.Context) (TokenValidator, error) {
	app, err := initFirebase(os.Getenv("GCP_PROJECT"), os.Getenv("FIREBASE_SECRET_ID"))
	if err != nil {
		return nil, fmt.Errorf("error initializing firebase app: %w", err)
	}

	client, err := app.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting auth client: %w", err)
	}

	return &firebaseValidator{client: client}, nil
}

func (v *firebaseValidator) ValidateToken(ctx context.Context, idToken string) (*claims.Claims, error) {
	token, err := v.client.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("error verifying ID token: %w", err)
	}

	claims := &claims.Claims{
		UserID:    token.UID,
		Email:     token.Claims["email"].(string),
		Roles:     parseRoles(token.Claims["roles"]),
		AppID:     token.Claims["app_id"].(string),
		IssuedAt:  token.IssuedAt,
		ExpiresAt: token.Expires,
	}

	// Validate claims immediately
	if err := claims.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid claims: %w", err)
	}

	return claims, nil
}

func (v *firebaseValidator) VerifyPermissions(c *claims.Claims, required []claims.Permission) bool {
	return c.HasAllPermissions(required...)
}

func parseRoles(roles interface{}) []string {
	if roles == nil {
		return []string{}
	}

	rolesSlice, ok := roles.([]interface{})
	if !ok {
		return []string{}
	}

	result := make([]string, len(rolesSlice))
	for i, role := range rolesSlice {
		if str, ok := role.(string); ok {
			result[i] = str
		}
	}
	return result
}

func initFirebase(projectID, secretID string) (*firebase.App, error) {
	ctx := context.Background()

	// Create Secret Manager client
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %v", err)
	}
	defer smClient.Close()

	// Get credentials from Secret Manager
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := smClient.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret: %v", err)
	}

	// Initialize Firebase with credentials
	opt := option.WithCredentialsJSON(result.Payload.Data)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firebase: %v", err)
	}

	return app, nil
}
