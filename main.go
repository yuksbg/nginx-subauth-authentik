package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"golang.org/x/oauth2"
)

// Config represents the main application configuration
type Config struct {
	Server  ServerConfig            `koanf:"server"`
	Domains map[string]DomainConfig `koanf:"domains"`
	JWT     JWTConfig               `koanf:"jwt"`
}

// ServerConfig represents server-level configuration
type ServerConfig struct {
	Port          string `koanf:"port"`
	Host          string `koanf:"host"`
	GinMode       string `koanf:"gin_mode"`
	DefaultDomain string `koanf:"default_domain"`
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	SecretKey     string        `koanf:"secret_key"`
	Issuer        string        `koanf:"issuer"`
	TokenDuration time.Duration `koanf:"token_duration"`
	RefreshBefore time.Duration `koanf:"refresh_before"`
}

// DomainConfig represents configuration for a specific domain
type DomainConfig struct {
	Name       string       `koanf:"name"`
	CookieName string       `koanf:"cookie_name"`
	BaseURL    string       `koanf:"base_url"`
	OAuth      OAuthConfig  `koanf:"oauth"`
	Cookie     CookieConfig `koanf:"cookie"`
}

// OAuthConfig represents OAuth2 configuration
type OAuthConfig struct {
	ClientID     string   `koanf:"client_id"`
	ClientSecret string   `koanf:"client_secret"`
	Scopes       []string `koanf:"scopes"`
	AuthURL      string   `koanf:"auth_url"`
	TokenURL     string   `koanf:"token_url"`
	UserInfoURL  string   `koanf:"userinfo_url"`
	StateString  string   `koanf:"state_string"`
}

// CookieConfig represents cookie configuration
type CookieConfig struct {
	Domain   string `koanf:"domain"`
	Path     string `koanf:"path"`
	MaxAge   int    `koanf:"max_age"`
	Secure   bool   `koanf:"secure"`
	HTTPOnly bool   `koanf:"http_only"`
	SameSite string `koanf:"same_site"`
}

// stateData holds the OAuth state and the original URL to redirect to
type stateData struct {
	State  string `json:"state"`
	Next   string `json:"next"`
	Domain string `json:"domain"`
}

// UserInfo represents user information from OAuth provider
type UserInfo struct {
	Sub      string `json:"sub"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
}

// CustomClaims represents our JWT claims
type CustomClaims struct {
	UserInfo UserInfo `json:"user_info"`
	Domain   string   `json:"domain"`
	jwt.RegisteredClaims
}

// DomainHandler holds domain-specific configuration and OAuth client
type DomainHandler struct {
	Config      *DomainConfig
	OAuthConfig *oauth2.Config
}

var (
	config         *Config
	domainHandlers map[string]*DomainHandler
	jwtPrivateKey  *rsa.PrivateKey
	jwtPublicKey   *rsa.PublicKey
	k              = koanf.New(".")

	// Command line flags
	configFile  = flag.String("config", "config.yaml", "Path to configuration file")
	showHelp    = flag.Bool("help", false, "Show help message")
	showVersion = flag.Bool("version", false, "Show version information")
)

const (
	version = "1.0.0"
	appName = "SSO Auth Service"
)

// loadConfig loads configuration from various sources
func loadConfig() error {
	// Default configuration
	defaultConfig := Config{
		Server: ServerConfig{
			Port:          "8080",
			Host:          "0.0.0.0",
			GinMode:       "debug",
			DefaultDomain: "localhost",
		},
		JWT: JWTConfig{
			SecretKey:     "", // Will be generated if empty
			Issuer:        "sso-auth-service",
			TokenDuration: time.Hour * 24, // 24 hours
			RefreshBefore: time.Hour * 2,  // Refresh if expires in 2 hours
		},
		Domains: map[string]DomainConfig{},
	}

	// Load default configuration
	if err := k.Load(structs.Provider(defaultConfig, "koanf"), nil); err != nil {
		return fmt.Errorf("error loading default config: %v", err)
	}

	// Load from config file if it exists
	configFile := "config.yaml"
	if envFile := os.Getenv("CONFIG_FILE"); envFile != "" {
		configFile = envFile
	}

	if _, err := os.Stat(configFile); err == nil {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return fmt.Errorf("error loading config file: %v", err)
		}
		log.Printf("Loaded configuration from %s", configFile)
	} else {
		log.Printf("Config file %s not found, using defaults and environment variables", configFile)
	}

	// Load environment variables with prefix
	if err := k.Load(env.Provider("AUTH_", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "AUTH_")), "_", ".", -1)
	}), nil); err != nil {
		return fmt.Errorf("error loading environment config: %v", err)
	}

	// Unmarshal into config struct
	if err := k.Unmarshal("", &config); err != nil {
		return fmt.Errorf("error unmarshaling config: %v", err)
	}

	return nil
}

// initializeJWTKeys initializes RSA keys for JWT signing
func initializeJWTKeys() error {
	// Generate RSA private key if secret key is not provided
	if config.JWT.SecretKey == "" {
		log.Println("No JWT secret key provided, generating RSA key pair...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA private key: %w", err)
		}
		jwtPrivateKey = privateKey
		jwtPublicKey = &privateKey.PublicKey

		log.Println("Generated RSA key pair for JWT signing")
	} else {
		// If you want to support HMAC signing with a secret key, you can implement that here
		// For now, we'll stick with RSA which is more secure
		return fmt.Errorf("HMAC JWT signing not implemented, please remove jwt.secret_key or use RSA")
	}

	return nil
}

// setupDomainHandlers creates OAuth configs for each domain
func setupDomainHandlers() {
	domainHandlers = make(map[string]*DomainHandler)

	for domain, domainConfig := range config.Domains {
		// Create a copy of the domain config
		cfg := domainConfig

		// Set up OAuth2 config
		oauthConfig := &oauth2.Config{
			ClientID:     cfg.OAuth.ClientID,
			ClientSecret: cfg.OAuth.ClientSecret,
			RedirectURL:  cfg.BaseURL + "/sso_oauth/callback",
			Scopes:       cfg.OAuth.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.OAuth.AuthURL,
				TokenURL: cfg.OAuth.TokenURL,
			},
		}

		domainHandlers[domain] = &DomainHandler{
			Config:      &cfg,
			OAuthConfig: oauthConfig,
		}

		log.Printf("Configured domain: %s", domain)
		log.Printf("  Cookie Name: %s", cfg.CookieName)
		log.Printf("  Base URL: %s", cfg.BaseURL)
		log.Printf("  Redirect URL: %s", oauthConfig.RedirectURL)
	}
}

// generateJWT creates a JWT token with user information
func generateJWT(userInfo *UserInfo, domain string) (string, error) {
	now := time.Now()

	claims := CustomClaims{
		UserInfo: *userInfo,
		Domain:   domain,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.JWT.Issuer,
			Subject:   userInfo.Sub,
			Audience:  []string{domain},
			ExpiresAt: jwt.NewNumericDate(now.Add(config.JWT.TokenDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(jwtPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// validateJWT validates our own JWT token
func validateJWT(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtPublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims type")
	}

	return claims, nil
}

// shouldRefreshToken checks if token should be refreshed based on expiration
func shouldRefreshToken(claims *CustomClaims) bool {
	if claims.ExpiresAt == nil {
		return true
	}

	timeToExpiry := time.Until(claims.ExpiresAt.Time)
	return timeToExpiry < config.JWT.RefreshBefore
}

// getDomainHandler returns the appropriate domain handler based on the request
func getDomainHandler(c *gin.Context) *DomainHandler {
	host := c.Request.Host

	// Remove port from host if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Try to find exact domain match
	if handler, exists := domainHandlers[host]; exists {
		return handler
	}

	// Fall back to default domain
	if handler, exists := domainHandlers[config.Server.DefaultDomain]; exists {
		return handler
	}

	// Return first available handler as last resort
	for _, handler := range domainHandlers {
		return handler
	}

	return nil
}

func main() {
	// Load configuration
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize JWT keys
	if err := initializeJWTKeys(); err != nil {
		log.Fatalf("Failed to initialize JWT keys: %v", err)
	}

	// Setup domain handlers
	setupDomainHandlers()

	// Set Gin mode
	gin.SetMode(config.Server.GinMode)

	r := gin.Default()

	// Middleware to log domain information
	r.Use(func(c *gin.Context) {
		handler := getDomainHandler(c)
		if handler != nil {
			log.Printf("Request for domain: %s, using config: %s", c.Request.Host, handler.Config.Name)
		}
		c.Next()
	})

	// Register routes with /sso_oauth/ prefix
	ssoGroup := r.Group("/sso_oauth")
	{
		ssoGroup.GET("/auth", authHandler)
		ssoGroup.HEAD("/auth", authHandler)
		ssoGroup.GET("/login", loginHandler)
		ssoGroup.GET("/callback", callbackHandler)
		ssoGroup.GET("/userinfo", userinfoHandler)
		ssoGroup.GET("/logout", logoutHandler)
		ssoGroup.GET("/refresh", refreshHandler) // New refresh endpoint
	}

	// Health check endpoint
	r.GET("/health", healthHandler)

	address := fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
	log.Printf("Starting auth server on %s", address)
	log.Printf("JWT token duration: %v", config.JWT.TokenDuration)
	log.Printf("JWT refresh threshold: %v", config.JWT.RefreshBefore)
	log.Printf("Configured domains: %v", getConfiguredDomains())
	log.Fatal(r.Run(address))
}

// getConfiguredDomains returns a list of configured domain names
func getConfiguredDomains() []string {
	var domains []string
	for domain := range config.Domains {
		domains = append(domains, domain)
	}
	return domains
}

// authHandler is the main handler for nginx auth_request (now with self-issued JWT validation)
func authHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		log.Printf("No handler found for domain: %s", c.Request.Host)
		c.Status(http.StatusInternalServerError)
		return
	}

	// Check for JWT token in cookies
	tokenString, err := c.Cookie(handler.Config.CookieName)
	if err != nil || tokenString == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Validate JWT token
	claims, err := validateJWT(tokenString)
	if err != nil {
		log.Printf("JWT validation failed for domain %s: %v", handler.Config.Name, err)
		c.Status(http.StatusUnauthorized)
		return
	}

	// Check if token should be refreshed (optional: auto-refresh)
	if shouldRefreshToken(claims) {
		log.Printf("Token for user %s is expiring soon, consider refresh", claims.UserInfo.Username)
		// You could implement auto-refresh here, or just log it
	}

	// Set user headers for the upstream application
	c.Header("X-Auth-User", claims.UserInfo.Username)
	c.Header("X-Auth-Email", claims.UserInfo.Email)
	c.Header("X-Auth-Name", claims.UserInfo.Name)
	c.Header("X-Auth-Subject", claims.UserInfo.Sub)
	c.Header("X-Auth-Domain", claims.Domain)

	// Get original URL from nginx headers
	originalURL := c.GetHeader("X-Original-URL")
	if originalURL != "" {
		c.Header("X-Auth-Original-URL", originalURL)
	}

	c.Status(http.StatusOK)
}

// loginHandler initiates OAuth flow
func loginHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	// Get the original URL
	next := c.Query("next")
	if next == "" {
		next = c.GetHeader("X-Original-URL")
	}
	if next == "" {
		next = c.GetHeader("Referer")
	}

	stateStruct := stateData{
		State:  handler.Config.OAuth.StateString,
		Next:   next,
		Domain: handler.Config.Name,
	}
	stateBytes, _ := json.Marshal(stateStruct)
	stateEncoded := base64.URLEncoding.EncodeToString(stateBytes)
	authCodeURL := handler.OAuthConfig.AuthCodeURL(stateEncoded)

	c.Redirect(http.StatusTemporaryRedirect, authCodeURL)
}

// callbackHandler handles OAuth callback and issues our own JWT
func callbackHandler(c *gin.Context) {
	stateEncoded := c.Query("state")
	stateBytes, err := base64.URLEncoding.DecodeString(stateEncoded)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid state encoding"})
		return
	}

	var stateStruct stateData
	if err := json.Unmarshal(stateBytes, &stateStruct); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid state data"})
		return
	}

	// Get handler for the domain from state
	var handler *DomainHandler
	if stateStruct.Domain != "" {
		handler = domainHandlers[stateStruct.Domain]
	}
	if handler == nil {
		handler = getDomainHandler(c)
	}
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	if stateStruct.State != handler.Config.OAuth.StateString {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid OAuth state"})
		return
	}

	code := c.Query("code")
	token, err := handler.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Get user information from OAuth provider
	userInfo, err := getUserInfoFromProvider(token.AccessToken, handler.Config.OAuth.UserInfoURL, handler.OAuthConfig)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
		return
	}

	// Generate our own JWT token with user information
	jwtToken, err := generateJWT(userInfo, handler.Config.Name)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication token"})
		return
	}

	// Set JWT cookie with domain-specific settings
	cookieConfig := handler.Config.Cookie
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(cookieConfig.SameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(
		handler.Config.CookieName,
		jwtToken, // Store our JWT instead of OAuth token
		cookieConfig.MaxAge,
		cookieConfig.Path,
		cookieConfig.Domain,
		cookieConfig.Secure,
		cookieConfig.HTTPOnly,
	)

	log.Printf("Successfully authenticated user %s for domain %s", userInfo.Username, handler.Config.Name)

	// Redirect to original URL if present
	if stateStruct.Next != "" {
		c.Redirect(http.StatusTemporaryRedirect, stateStruct.Next)
	} else {
		c.Redirect(http.StatusTemporaryRedirect, "/")
	}
}

// refreshHandler refreshes JWT token (optional endpoint for frontend use)
func refreshHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	// Get current JWT token
	tokenString, err := c.Cookie(handler.Config.CookieName)
	if err != nil || tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Validate current token (even if expired, we'll check the claims)
	claims, err := validateJWT(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Generate new JWT token with same user info
	newToken, err := generateJWT(&claims.UserInfo, claims.Domain)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		return
	}

	// Update cookie
	cookieConfig := handler.Config.Cookie
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(cookieConfig.SameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	c.SetSameSite(sameSite)
	c.SetCookie(
		handler.Config.CookieName,
		newToken,
		cookieConfig.MaxAge,
		cookieConfig.Path,
		cookieConfig.Domain,
		cookieConfig.Secure,
		cookieConfig.HTTPOnly,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

// userinfoHandler returns user information from JWT
func userinfoHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	tokenString, err := c.Cookie(handler.Config.CookieName)
	if err != nil || tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	claims, err := validateJWT(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":       claims.UserInfo,
		"domain":     claims.Domain,
		"expires_at": claims.ExpiresAt,
		"issued_at":  claims.IssuedAt,
	})
}

// logoutHandler clears the JWT cookie
func logoutHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	// Clear the JWT cookie
	cookieConfig := handler.Config.Cookie
	c.SetCookie(
		handler.Config.CookieName,
		"",
		-1,
		cookieConfig.Path,
		cookieConfig.Domain,
		cookieConfig.Secure,
		cookieConfig.HTTPOnly,
	)

	next := c.Query("next")
	if next == "" {
		next = "/"
	}

	c.Redirect(http.StatusTemporaryRedirect, next)
}

// healthHandler returns health status and configuration info
func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"domains": getConfiguredDomains(),
		"server": gin.H{
			"port":           config.Server.Port,
			"default_domain": config.Server.DefaultDomain,
		},
		"jwt": gin.H{
			"issuer":         config.JWT.Issuer,
			"token_duration": config.JWT.TokenDuration.String(),
			"refresh_before": config.JWT.RefreshBefore.String(),
		},
	})
}

// getUserInfoFromProvider gets user information from OAuth provider (only called during callback)
func getUserInfoFromProvider(accessToken, userInfoURL string, oauthConfig *oauth2.Config) (*UserInfo, error) {
	client := oauthConfig.Client(context.Background(), &oauth2.Token{AccessToken: accessToken})
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo: %w", err)
	}

	return &userInfo, nil
}
