package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ranson21/ranor-auth/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

func (h *AuthHandler) RegisterRoutes(r *gin.Engine) {
	auth := r.Group("/auth")
	{
		auth.POST("/validate", h.ValidateToken)
		// auth.POST("/users", h.CreateUser)
	}
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	valid, err := h.authService.ValidateAccessToken(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": valid})
}

// func (h *AuthHandler) CreateUser(c *gin.Context) {
// 	var req struct {
// 		Email    string `json:"email" binding:"required,email"`
// 		Password string `json:"password" binding:"required"`
// 	}

// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	err := h.authService.CreateUser(c.Request.Context(), req.Email, req.Password)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
// 		return
// 	}

// 	c.Status(http.StatusCreated)
// }
