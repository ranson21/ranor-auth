package auth

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	firebase "firebase.google.com/go/v4"
	"google.golang.org/api/option"
)

func New(projectID, secretID string) (*firebase.App, error) {
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
