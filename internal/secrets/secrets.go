package secrets

import (
	"context"
	"fmt"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type Manager struct {
	client *secretmanager.Client
	cache  map[string]cachedSecret
	mu     sync.RWMutex
	ttl    time.Duration
}

type cachedSecret struct {
	value      []byte
	expiration time.Time
}

var (
	defaultManager *Manager
	initOnce       sync.Once
	initErr        error
)

// Must be called before using GetDefaultManager
func InitDefaultManager(ctx context.Context, ttl time.Duration) error {
	initOnce.Do(func() {
		defaultManager, initErr = NewManager(ctx, ttl)
	})
	return initErr
}

func GetDefaultManager() (*Manager, error) {
	if defaultManager == nil {
		return nil, fmt.Errorf("default manager not initialized. call InitDefaultManager first")
	}
	return defaultManager, nil
}

func NewManager(ctx context.Context, ttl time.Duration) (*Manager, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %v", err)
	}

	return &Manager{
		client: client,
		cache:  make(map[string]cachedSecret),
		ttl:    ttl,
	}, nil
}

func (m *Manager) GetSecret(ctx context.Context, projectID, secretID string) ([]byte, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)
	return m.Get(ctx, name)
}

func (m *Manager) Get(ctx context.Context, name string) ([]byte, error) {
	m.mu.RLock()
	if cached, ok := m.cache[name]; ok && time.Now().Before(cached.expiration) {
		defer m.mu.RUnlock()
		return cached.value, nil
	}
	m.mu.RUnlock()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := m.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret %s: %v", name, err)
	}

	m.mu.Lock()
	m.cache[name] = cachedSecret{
		value:      result.Payload.Data,
		expiration: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()

	return result.Payload.Data, nil
}

func (m *Manager) Close() error {
	return m.client.Close()
}
