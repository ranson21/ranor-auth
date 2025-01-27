package auth

import (
	"context"
	"fmt"

	firebase "firebase.google.com/go/v4"
	"github.com/ranson21/ranor-auth/internal/secrets"
	"google.golang.org/api/option"
)

func New(projectID, secretID string) (*firebase.App, error) {
	ctx := context.Background()
	sm, err := secrets.GetDefaultManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets manager: %v", err)
	}

	creds, err := sm.GetSecret(ctx, projectID, secretID)
	if err != nil {
		return nil, fmt.Errorf("failed to get firebase credentials: %v", err)
	}

	opt := option.WithCredentialsJSON(creds)
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize firebase: %v", err)
	}

	return app, nil
}
