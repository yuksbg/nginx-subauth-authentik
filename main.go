package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
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
}

// ServerConfig represents server-level configuration
type ServerConfig struct {
	Port          string `koanf:"port"`
	Host          string `koanf:"host"`
	GinMode       string `koanf:"gin_mode"`
	DefaultDomain string `koanf:"default_domain"`
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

// DomainHandler holds domain-specific configuration and OAuth client
type DomainHandler struct {
	Config      *DomainConfig
	OAuthConfig *oauth2.Config
}

var (
	config         *Config
	domainHandlers map[string]*DomainHandler
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

// setupDomainHandlers creates OAuth configs for each domain
func setupDomainHandlers() {
	domainHandlers = make(map[string]*DomainHandler)

	for domain, domainConfig := range config.Domains {
		// Create a copy of the domain config
		cfg := domainConfig

		// Set up OAuth2 config - using /sso_oauth/ prefix
		oauthConfig := &oauth2.Config{
			ClientID:     cfg.OAuth.ClientID,
			ClientSecret: cfg.OAuth.ClientSecret,
			RedirectURL:  cfg.BaseURL + "/sso_oauth/callback", // Added /sso_oauth/ prefix
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
	}

	// Health check endpoint (keep without prefix for monitoring)
	r.GET("/health", healthHandler)

	address := fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
	log.Printf("Starting auth server on %s", address)
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

// authHandler is the main handler for nginx auth_request
func authHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		log.Printf("No handler found for domain: %s", c.Request.Host)
		c.Status(http.StatusInternalServerError)
		return
	}

	// Check for OAuth token in cookies
	token, err := c.Cookie(handler.Config.CookieName)
	if err != nil || token == "" {
		c.Status(http.StatusUnauthorized)
		return
	}

	// Validate the token by checking user info
	userInfo, err := validateTokenAndGetUserInfo(token, handler.Config.OAuth.UserInfoURL, handler.OAuthConfig)
	if err != nil {
		log.Printf("Token validation failed for domain %s: %v", handler.Config.Name, err)
		c.Status(http.StatusUnauthorized)
		return
	}

	// Set user headers for the upstream application
	c.Header("X-Auth-User", userInfo.Username)
	c.Header("X-Auth-Email", userInfo.Email)
	c.Header("X-Auth-Name", userInfo.Name)
	c.Header("X-Auth-Subject", userInfo.Sub)
	c.Header("X-Auth-Domain", handler.Config.Name)

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

// callbackHandler handles OAuth callback
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

	// Set cookie with domain-specific settings
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
		token.AccessToken,
		cookieConfig.MaxAge,
		cookieConfig.Path,
		cookieConfig.Domain,
		cookieConfig.Secure,
		cookieConfig.HTTPOnly,
	)

	// Redirect to original URL if present
	if stateStruct.Next != "" {
		c.Redirect(http.StatusTemporaryRedirect, stateStruct.Next)
	} else {
		c.Redirect(http.StatusTemporaryRedirect, "/")
	}
}

// userinfoHandler returns user information
func userinfoHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	token, err := c.Cookie(handler.Config.CookieName)
	if err != nil || token == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	userInfo, err := validateTokenAndGetUserInfo(token, handler.Config.OAuth.UserInfoURL, handler.OAuthConfig)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":   userInfo,
		"domain": handler.Config.Name,
	})
}

// logoutHandler clears the authentication cookie
func logoutHandler(c *gin.Context) {
	handler := getDomainHandler(c)
	if handler == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Domain not configured"})
		return
	}

	// Clear the cookie with domain-specific settings
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
	})
}

// validateTokenAndGetUserInfo validates the OAuth token and returns user info
func validateTokenAndGetUserInfo(accessToken, userInfoURL string, oauthConfig *oauth2.Config) (*UserInfo, error) {
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
