package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/lib/pq"
	"github.com/ranson21/ranor-auth/internal/secrets"
	"github.com/ranson21/ranor-common/pkg/database/connection"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type Provider string

const (
	Google    Provider = "google"
	GitHub    Provider = "github"
	Microsoft Provider = "microsoft"
)

type Config struct {
	SessionCookieName   string
	TokenCookieName     string
	CookieDomain        string
	SessionCookieExpire time.Duration
	AccessTokenExpire   time.Duration
}

type AuthService struct {
	db           connection.Database
	fb           *firebase.App
	auth         *auth.Client
	hmac         *HMACConfig
	providers    map[Provider]*oauth2.Config
	applications map[string]Application
	config       Config
	sm           *secrets.Manager
}

type Application struct {
	ID           string
	Name         string
	RedirectURIs []string
	Scopes       []string
	AllowedUsers []string
}

type Session struct {
	ID        string
	UserID    string
	Email     string
	Name      string
	Provider  Provider
	CreatedAt time.Time
	ExpiresAt time.Time
	Metadata  map[string]interface{}
}

type UserInfo struct {
	Email    string
	Name     string
	Picture  string
	Provider Provider
}

type AuthResult struct {
	UserID                 string
	Token                  string
	IsNewUser              bool
	RequiresAdditionalInfo bool
	SessionID              string
}

type signInResponse struct {
	IDToken      string `json:"idToken"`
	Email        string `json:"email"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    string `json:"expiresIn"`
	LocalID      string `json:"localId"`
}

// NewAuthService creates a new AuthService instance
func NewAuthService(ctx context.Context, db connection.Database, fb *firebase.App) (*AuthService, error) {
	authClient, err := fb.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("error initializing Firebase auth: %w", err)
	}

	hmacConfig, err := NewHMACConfig()
	if err != nil {
		return nil, fmt.Errorf("error initializing HMAC: %w", err)
	}

	sm, err := secrets.GetDefaultManager()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets manager: %v", err)
	}

	service := &AuthService{
		db:   db,
		fb:   fb,
		auth: authClient,
		hmac: hmacConfig,
		config: Config{
			SessionCookieName:   "sid",
			TokenCookieName:     "access_token",
			SessionCookieExpire: 3600 * time.Second,
			AccessTokenExpire:   3600 * time.Second,
			CookieDomain:        os.Getenv("SSO_COOKIE_DOMAIN"),
		},
		providers:    make(map[Provider]*oauth2.Config),
		applications: make(map[string]Application),
		sm:           sm,
	}

	if err := service.loadProviders(ctx); err != nil {
		return nil, fmt.Errorf("error loading providers: %w", err)
	}

	if err := service.LoadApplications(ctx); err != nil {
		return nil, fmt.Errorf("error loading applications: %w", err)
	}

	return service, nil
}

func (s *AuthService) loadProviders(ctx context.Context) error {
	// Set the search path to ensure we're in the correct schema
	_, err := s.db.ExecContext(ctx, `SET search_path TO auth`)
	if err != nil {
		return fmt.Errorf("error setting search path: %w", err)
	}

	query := `
		SELECT 
			id, name, client_id, secret_id, 
			scopes, enabled
		FROM auth.oauth_providers
		WHERE enabled = true
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error querying providers: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var providerID, name, clientID, clientSecret string
		var enabled bool
		scopes := make([]string, 0)

		// Try scanning again with the proper array handler
		err = rows.Scan(&providerID, &name, &clientID, &clientSecret, &scopes, &enabled)
		if err != nil {
			log.Printf("Debug - Array scan error: %v", err)
			return fmt.Errorf("error scanning provider: %w", err)
		}

		if !enabled {
			continue
		}

		// Get provider secret from secrets manager
		secret, err := s.sm.GetSecret(ctx, os.Getenv("GCP_PROJECT"), clientSecret)
		if err != nil {
			return fmt.Errorf("error getting provider secret: %w", err)
		}

		var endpoint oauth2.Endpoint
		switch Provider(providerID) {
		case Google:
			endpoint = google.Endpoint
		case GitHub:
			endpoint = github.Endpoint
		case Microsoft:
			endpoint = microsoft.AzureADEndpoint("common")
		default:
			log.Printf("Unknown provider type: %s", providerID)
			continue
		}

		// Log the successful provider configuration
		log.Printf("Configuring provider: %s with %d scopes", providerID, len(scopes))

		s.providers[Provider(providerID)] = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: string(secret),
			Scopes:       scopes,
			Endpoint:     endpoint,
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating providers: %w", err)
	}

	return nil
}

// LoadApplications updates to handle the new many-to-many relationship
func (s *AuthService) LoadApplications(ctx context.Context) error {
	// First, load basic application information
	query := `
		SELECT id, name, scopes, allowed_users
		FROM sso_applications
		WHERE active = true
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error loading applications: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var app Application
		if err := rows.Scan(
			&app.ID,
			&app.Name,
			&app.Scopes,
			&app.AllowedUsers,
		); err != nil {
			return fmt.Errorf("error scanning application: %w", err)
		}

		// Initialize empty RedirectURIs slice
		app.RedirectURIs = make([]string, 0)
		s.applications[app.ID] = app
	}

	// Then load application provider configurations
	providerQuery := `
		SELECT application_id, provider_id, redirect_uri
		FROM application_providers
		WHERE enabled = true
	`
	providerRows, err := s.db.QueryContext(ctx, providerQuery)
	if err != nil {
		return fmt.Errorf("error loading application providers: %w", err)
	}
	defer providerRows.Close()

	for providerRows.Next() {
		var appID, providerID, redirectURI string
		if err := providerRows.Scan(&appID, &providerID, &redirectURI); err != nil {
			return fmt.Errorf("error scanning application provider: %w", err)
		}

		// Update application's redirect URIs
		if app, ok := s.applications[appID]; ok {
			app.RedirectURIs = append(app.RedirectURIs, redirectURI)
			s.applications[appID] = app

			// Update provider config with the redirect URI for this application
			if provider, ok := s.providers[Provider(providerID)]; ok {
				// Create a new config with the specific redirect URI for this application
				providerCopy := *provider
				providerCopy.RedirectURL = redirectURI
				s.providers[Provider(providerID)] = &providerCopy
			}
		}
	}

	return nil
}

func (s *AuthService) CreateSession(ctx context.Context, userID, email, name string, provider Provider) (*Session, error) {
	session := &Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Email:     email,
		Name:      name,
		Provider:  provider,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.config.SessionCookieExpire),
		Metadata:  make(map[string]interface{}),
	}

	metadata, err := json.Marshal(session.Metadata)
	if err != nil {
		return nil, fmt.Errorf("error marshaling metadata: %w", err)
	}

	query := `
		INSERT INTO sso_sessions (id, user_id, email, name, provider, created_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err = s.db.ExecContext(ctx, query,
		session.ID,
		session.UserID,
		session.Email,
		session.Name,
		session.Provider,
		session.CreatedAt,
		session.ExpiresAt,
		metadata,
	)
	if err != nil {
		return nil, fmt.Errorf("error creating session: %w", err)
	}

	return session, nil
}

func (s *AuthService) HandleOAuthCallback(ctx context.Context, provider Provider, code string) (*AuthResult, error) {
	config, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	oauthToken, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	userInfo, err := s.getUserInfo(ctx, provider, oauthToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	existingUser, err := s.auth.GetUserByEmail(ctx, userInfo.Email)
	isNewUser := err != nil && auth.IsUserNotFound(err)

	var user *auth.UserRecord
	if isNewUser {
		user, err = s.createUser(ctx, userInfo)
	} else {
		user, err = s.updateUser(ctx, existingUser.UID, userInfo)
	}
	if err != nil {
		return nil, err
	}

	session, err := s.CreateSession(ctx, user.UID, userInfo.Email, userInfo.Name, provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":      user.UID,
		"email":    userInfo.Email,
		"name":     userInfo.Name,
		"provider": provider,
		"exp":      time.Now().Add(s.config.AccessTokenExpire).Unix(),
		"iat":      time.Now().Unix(),
		"session":  session.ID,
	}

	jwtToken, err := s.CreateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &AuthResult{
		UserID:                 user.UID,
		Token:                  jwtToken,
		IsNewUser:              isNewUser,
		RequiresAdditionalInfo: s.needsAdditionalInfo(ctx, user.UID),
		SessionID:              session.ID,
	}, nil
}

// New types for email/password auth
type EmailSignUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type EmailSignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Handle email/password sign up
func (s *AuthService) HandleEmailSignUp(ctx context.Context, req EmailSignUpRequest) (*AuthResult, error) {
	params := (&auth.UserToCreate{}).
		Email(req.Email).
		Password(req.Password).
		DisplayName(req.Name)

	// Create user in Firebase
	user, err := s.auth.CreateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	// Create user in your DB
	userInfo := &UserInfo{
		Email:    req.Email,
		Name:     req.Name,
		Provider: "password", // New provider type for email/password
	}
	if err := s.createUserInDB(ctx, user.UID, userInfo); err != nil {
		return nil, fmt.Errorf("error creating user in database: %w", err)
	}

	// Create session like in OAuth flow
	session, err := s.CreateSession(ctx, user.UID, req.Email, req.Name, "password")
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Create JWT token like in OAuth flow
	claims := jwt.MapClaims{
		"sub":      user.UID,
		"email":    req.Email,
		"name":     req.Name,
		"provider": "password",
		"exp":      time.Now().Add(s.config.AccessTokenExpire).Unix(),
		"iat":      time.Now().Unix(),
		"session":  session.ID,
	}

	jwtToken, err := s.CreateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &AuthResult{
		UserID:                 user.UID,
		Token:                  jwtToken,
		IsNewUser:              true,
		RequiresAdditionalInfo: s.needsAdditionalInfo(ctx, user.UID),
		SessionID:              session.ID,
	}, nil
}

func (s *AuthService) HandleEmailSignIn(ctx context.Context, req EmailSignInRequest) (*AuthResult, error) {
	// Get Firebase API key from environment or config
	apiKey := os.Getenv("FIREBASE_API_KEY")

	// Prepare the sign-in request
	payload := map[string]string{
		"email":             req.Email,
		"password":          req.Password,
		"returnSecureToken": "true",
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling payload: %w", err)
	}

	// Make request to Firebase Auth REST API
	url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=%s", apiKey)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("authentication failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("authentication failed: %v", errResp)
	}

	var signInResp signInResponse
	if err := json.NewDecoder(resp.Body).Decode(&signInResp); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	// Get user details from Firebase
	user, err := s.auth.GetUser(ctx, signInResp.LocalID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create session
	session, err := s.CreateSession(ctx, user.UID, user.Email, user.DisplayName, "password")
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Create JWT token
	claims := jwt.MapClaims{
		"sub":      user.UID,
		"email":    user.Email,
		"name":     user.DisplayName,
		"provider": "password",
		"exp":      time.Now().Add(s.config.AccessTokenExpire).Unix(),
		"iat":      time.Now().Unix(),
		"session":  session.ID,
	}

	jwtToken, err := s.CreateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &AuthResult{
		UserID:                 user.UID,
		Token:                  jwtToken,
		IsNewUser:              false,
		RequiresAdditionalInfo: s.needsAdditionalInfo(ctx, user.UID),
		SessionID:              session.ID,
	}, nil
}

func (s *AuthService) createUser(ctx context.Context, userInfo *UserInfo) (*auth.UserRecord, error) {
	params := (&auth.UserToCreate{}).
		Email(userInfo.Email).
		DisplayName(userInfo.Name).
		PhotoURL(userInfo.Picture).
		EmailVerified(true)

	user, err := s.auth.CreateUser(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	if err := s.createUserInDB(ctx, user.UID, userInfo); err != nil {
		return nil, fmt.Errorf("error creating user in database: %w", err)
	}

	return user, nil
}

func (s *AuthService) updateUser(ctx context.Context, userID string, userInfo *UserInfo) (*auth.UserRecord, error) {
	params := (&auth.UserToUpdate{}).
		DisplayName(userInfo.Name).
		PhotoURL(userInfo.Picture)

	return s.auth.UpdateUser(ctx, userID, params)
}

func (s *AuthService) createUserInDB(ctx context.Context, userID string, userInfo *UserInfo) error {
	query := `
		INSERT INTO users (id, email, display_name, provider, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`
	_, err := s.db.ExecContext(ctx, query, userID, userInfo.Email, userInfo.Name, userInfo.Provider)
	return err
}

func (s *AuthService) CreateAccessToken(claims jwt.MapClaims) (string, error) {
	activeSecret := s.hmac.secrets[0]
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = activeSecret.KeyID

	return token.SignedString([]byte(activeSecret.Secret))
}

func (s *AuthService) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.MapClaims, error) {
	var lastErr error

	for _, secret := range s.hmac.secrets {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret.Secret), nil
		})

		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				return &claims, nil
			}
		}
		lastErr = err
	}

	return nil, fmt.Errorf("token validation failed: %w", lastErr)
}

func (s *AuthService) getUserInfo(ctx context.Context, provider Provider, accessToken string) (*UserInfo, error) {
	var userInfo UserInfo
	userInfo.Provider = provider

	client := &http.Client{}
	var req *http.Request
	var err error

	switch provider {
	case Google:
		req, err = http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	case GitHub:
		req, err = http.NewRequest("GET", "https://api.github.com/user", nil)
	case Microsoft:
		req, err = http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}

	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provider returned status %d", resp.StatusCode)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	switch provider {
	case Google:
		userInfo.Email = data["email"].(string)
		userInfo.Name = data["name"].(string)
		userInfo.Picture = data["picture"].(string)
	case GitHub:
		userInfo.Name = data["name"].(string)
		userInfo.Picture = data["avatar_url"].(string)
		// Get primary email from GitHub
		emails, err := s.getGitHubEmails(ctx, accessToken)
		if err != nil {
			return nil, err
		}
		userInfo.Email = emails
	case Microsoft:
		userInfo.Email = data["userPrincipalName"].(string)
		userInfo.Name = data["displayName"].(string)
	}

	return &userInfo, nil
}

func (s *AuthService) getGitHubEmails(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", fmt.Errorf("no primary verified email found")
}

// Update function:
func (s *AuthService) needsAdditionalInfo(ctx context.Context, userID string) bool {
	query := `
			SELECT COALESCE(NOT profile_complete, true)
			FROM users 
			WHERE id = $1
	`
	var needsInfo bool
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&needsInfo)
	return err != nil || needsInfo
}

// Add new function for profile service to call:
func (s *AuthService) UpdateProfileStatus(ctx context.Context, userID string, isComplete bool) error {
	query := `
			UPDATE users 
			SET profile_complete = $2
			WHERE id = $1
	`
	_, err := s.db.ExecContext(ctx, query, userID, isComplete)
	return err
}

func (s *AuthService) SetAuthCookies(w http.ResponseWriter, session *Session, token string, appID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.config.SessionCookieName,
		Value:    session.ID,
		Domain:   s.config.CookieDomain,
		Path:     "/",
		Expires:  session.ExpiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("%s_%s", s.config.TokenCookieName, appID),
		Value:    token,
		Domain:   s.config.CookieDomain,
		Path:     "/",
		Expires:  time.Now().Add(s.config.AccessTokenExpire),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *AuthService) GetSession(ctx context.Context, sessionID string) (*Session, error) {
	query := `
		SELECT id, user_id, email, name, provider, created_at, expires_at, metadata
		FROM sso_sessions
		WHERE id = $1 AND expires_at > NOW()
	`

	var session Session
	var metadata []byte
	err := s.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.ID,
		&session.UserID,
		&session.Email,
		&session.Name,
		&session.Provider,
		&session.CreatedAt,
		&session.ExpiresAt,
		&metadata,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired")
		}
		return nil, fmt.Errorf("error getting session: %w", err)
	}

	if err := json.Unmarshal(metadata, &session.Metadata); err != nil {
		return nil, fmt.Errorf("error unmarshaling metadata: %w", err)
	}

	return &session, nil
}

func (s *AuthService) ValidateApplicationAccess(ctx context.Context, appID, userID string) error {
	app, ok := s.applications[appID]
	if !ok {
		return fmt.Errorf("unknown application")
	}

	if len(app.AllowedUsers) == 0 {
		return nil
	}

	for _, allowedUser := range app.AllowedUsers {
		if allowedUser == userID {
			return nil
		}
	}

	return fmt.Errorf("user not authorized for this application")
}

func (s *AuthService) GetAuthorizationURL(provider Provider, state string) (string, error) {
	config, ok := s.providers[provider]
	if !ok {
		return "", fmt.Errorf("unsupported provider: %s", provider)
	}
	return config.AuthCodeURL(state), nil
}

func (s *AuthService) GetSessionCookieName() string {
	return s.config.SessionCookieName
}

func (s *AuthService) GetApplicationRedirectURI(appID string) string {
	app, ok := s.applications[appID]
	if !ok || len(app.RedirectURIs) == 0 {
		return "/"
	}
	return app.RedirectURIs[0]
}

func (s *AuthService) InvalidateSession(ctx context.Context, sessionID string) error {
	query := `UPDATE sso_sessions SET expires_at = NOW() WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, sessionID)
	return err
}

func (s *AuthService) ClearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.config.SessionCookieName,
		Value:    "",
		Domain:   s.config.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// RegisterApplication updates to handle the new many-to-many relationship
func (s *AuthService) RegisterApplication(ctx context.Context, app Application) error {
	// Start a transaction
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("error starting transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert the application
	query := `
		INSERT INTO sso_applications (
			id, name, scopes, allowed_users, active, created_at
		) VALUES ($1, $2, $3, $4, true, NOW())
	`
	_, err = tx.Exec(ctx, query,
		app.ID,
		app.Name,
		pq.Array(app.Scopes),
		pq.Array(app.AllowedUsers),
	)
	if err != nil {
		return fmt.Errorf("error registering application: %w", err)
	}

	// Insert application provider configurations
	for _, redirectURI := range app.RedirectURIs {
		// Extract provider from redirect URI (assuming format like ".../callback/google")
		parts := strings.Split(redirectURI, "/")
		providerID := parts[len(parts)-1] // Get the last part

		query := `
			INSERT INTO application_providers (
				application_id, provider_id, redirect_uri, enabled
			) VALUES ($1, $2, $3, true)
		`
		_, err = tx.Exec(ctx, query, app.ID, providerID, redirectURI)
		if err != nil {
			return fmt.Errorf("error registering application provider: %w", err)
		}
	}

	// Commit the transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	// Update local cache
	s.applications[app.ID] = app
	return nil
}

/**
 * Begin HMAC Definition
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
