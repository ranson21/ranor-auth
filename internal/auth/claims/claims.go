package claims

import (
	"errors"
	"time"
)

// Claims represents the custom claims for a user token
type Claims struct {
	UserID    string   `json:"uid"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	AppID     string   `json:"app_id"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

type Permission string

const (
	PermissionReadProfile  Permission = "profile:read"
	PermissionWriteProfile Permission = "profile:write"
	PermissionAdmin        Permission = "admin"
)

var (
	ErrInvalidClaims = errors.New("invalid claims")
	ErrExpiredToken  = errors.New("token has expired")
)

// HasPermission checks if the claims contain a specific permission
func (c *Claims) HasPermission(p Permission) bool {
	for _, role := range c.Roles {
		if role == string(p) {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if the claims contain any of the given permissions
func (c *Claims) HasAnyPermission(permissions ...Permission) bool {
	for _, p := range permissions {
		if c.HasPermission(p) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if the claims contain all of the given permissions
func (c *Claims) HasAllPermissions(permissions ...Permission) bool {
	for _, p := range permissions {
		if !c.HasPermission(p) {
			return false
		}
	}
	return true
}

// IsAdmin is a convenience method to check if the user has admin permission
func (c *Claims) IsAdmin() bool {
	return c.HasPermission(PermissionAdmin)
}

// IsValid checks if the claims are valid and not expired
func (c *Claims) IsValid() error {
	if c.UserID == "" || c.Email == "" || c.AppID == "" {
		return ErrInvalidClaims
	}

	if time.Now().Unix() > c.ExpiresAt {
		return ErrExpiredToken
	}

	return nil
}

// TimeUntilExpiry returns the duration until the token expires
func (c *Claims) TimeUntilExpiry() time.Duration {
	return time.Until(time.Unix(c.ExpiresAt, 0))
}

// IsExpired checks if the token has expired
func (c *Claims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// CreateTime returns the time when the token was created
func (c *Claims) CreateTime() time.Time {
	return time.Unix(c.IssuedAt, 0)
}

// ExpiryTime returns the time when the token will expire
func (c *Claims) ExpiryTime() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}
