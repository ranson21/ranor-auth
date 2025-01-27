package http

import (
	"fmt"
	"net/http"
	"net/url"

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
		auth.GET("/login/:provider", h.InitiateOAuth)
		auth.GET("/callback/:provider", h.OAuthCallback)
		auth.POST("/validate", h.ValidateToken)
		auth.GET("/session", h.GetSession)
		auth.POST("/logout", h.Logout)
		auth.POST("/applications", h.RegisterApplication)
	}
}

func (h *AuthHandler) InitiateOAuth(c *gin.Context) {
	provider := service.Provider(c.Param("provider"))
	appID := c.Query("app_id")
	state := url.QueryEscape(appID)

	authURL, err := h.authService.GetAuthorizationURL(provider, state)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid provider: %v", err)})
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

func (h *AuthHandler) RegisterApplication(c *gin.Context) {
	var app service.Application
	if err := c.ShouldBindJSON(&app); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.RegisterApplication(c.Request.Context(), app); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to register application: %v", err)})
		return
	}

	c.Status(http.StatusCreated)
}

func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	provider := service.Provider(c.Param("provider"))
	code := c.Query("code")
	state := c.Query("state")
	appID, err := url.QueryUnescape(state)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return
	}

	result, err := h.authService.HandleOAuthCallback(c.Request.Context(), provider, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("authentication failed: %v", err)})
		return
	}

	if err := h.authService.ValidateApplicationAccess(c.Request.Context(), appID, result.UserID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "application access denied"})
		return
	}

	session, err := h.authService.GetSession(c.Request.Context(), result.SessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get session"})
		return
	}

	h.authService.SetAuthCookies(c.Writer, session, result.Token, appID)

	redirectURI := h.authService.GetApplicationRedirectURI(appID)
	if result.RequiresAdditionalInfo {
		redirectURI = fmt.Sprintf("%s?complete_profile=true", redirectURI)
	}

	c.Redirect(http.StatusTemporaryRedirect, redirectURI)
}

func (h *AuthHandler) ValidateToken(c *gin.Context) {
	var req struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := h.authService.ValidateAccessToken(c.Request.Context(), req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	c.JSON(http.StatusOK, claims)
}

func (h *AuthHandler) GetSession(c *gin.Context) {
	sessionID, err := c.Cookie(h.authService.GetSessionCookieName())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no session found"})
		return
	}

	session, err := h.authService.GetSession(c.Request.Context(), sessionID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
		return
	}

	c.JSON(http.StatusOK, session)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, err := c.Cookie(h.authService.GetSessionCookieName())
	if err != nil {
		c.Status(http.StatusOK)
		return
	}

	if err := h.authService.InvalidateSession(c.Request.Context(), sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
		return
	}

	h.authService.ClearAuthCookies(c.Writer)
	c.Status(http.StatusOK)
}
