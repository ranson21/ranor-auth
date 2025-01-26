package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ranson21/ranor-auth/internal/auth/claims"
	"github.com/ranson21/ranor-auth/internal/auth/token"
	"github.com/ranson21/ranor-common/pkg/logger"
	"go.uber.org/zap"
)

type contextKey string

const (
	ContextKeyClaims = contextKey("claims")
)

type Middleware interface {
	Authenticate() gin.HandlerFunc
	RequirePermissions(permissions ...claims.Permission) gin.HandlerFunc
	RequireAnyPermission(permissions ...claims.Permission) gin.HandlerFunc
}

type AuthMiddleware struct {
	validator token.TokenValidator
	logger    logger.Logger
}

func NewAuthMiddleware(v token.TokenValidator, l logger.Logger) Middleware {
	return &AuthMiddleware{
		validator: v,
		logger:    l,
	}
}

func (m *AuthMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractToken(c.Request)
		if token == "" {
			m.logger.Warn("No token provided in request")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims, err := m.validator.ValidateToken(c, token)
		if err != nil {
			m.logger.Error("Token validation failed", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims.IsExpired() {
			m.logger.Warn("Expired token",
				zap.String("user_id", claims.UserID),
				zap.Time("expired_at", claims.ExpiryTime()),
			)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			c.Abort()
			return
		}

		m.logger.Info("Successful authentication",
			zap.String("user_id", claims.UserID),
			zap.String("app_id", claims.AppID),
			zap.Duration("expires_in", claims.TimeUntilExpiry()),
		)

		c.Set("claims", claims)
		c.Next()
	}
}

// RequirePermissions Middleware
func (m *AuthMiddleware) RequirePermissions(required ...claims.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		authClaims, exists := c.Get("claims")
		if !exists {
			m.logger.Error("No claims found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		userClaims, ok := authClaims.(*claims.Claims)
		if !ok || !userClaims.HasAllPermissions(required...) {
			m.logger.Warn("Insufficient permissions",
				zap.String("user_id", userClaims.UserID),
				zap.Any("required_perms", required),
				zap.Strings("user_roles", userClaims.Roles),
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission Middleware
func (m *AuthMiddleware) RequireAnyPermission(permissions ...claims.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		authClaims, exists := c.Get("claims")
		if !exists {
			m.logger.Error("No claims found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		userClaims, ok := authClaims.(*claims.Claims)
		if !ok || !userClaims.HasAnyPermission(permissions...) {
			m.logger.Warn("Insufficient permissions",
				zap.String("user_id", userClaims.UserID),
				zap.Any("required_perms", permissions),
				zap.Strings("user_roles", userClaims.Roles),
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	parts := strings.Split(bearerToken, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return ""
}
