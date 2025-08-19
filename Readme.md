# Auth Service Configuration Guide with Multi-Domain Support

## Overview

The auth service now supports multiple domains with individual OAuth configurations using [koanf](https://github.com/knadh/koanf) for configuration management. Each domain can have its own:

- OAuth provider settings
- Cookie configuration
- URL prefix
- Security settings

## Configuration Methods

The service loads configuration in this order (later sources override earlier ones):

1. **Default values** (hardcoded)
2. **YAML configuration file** (`config.yaml` by default)
3. **Environment variables** (prefixed with `AUTH_`)

## Configuration File Structure

Create a `config.yaml` file with the following structure:

```yaml
server:
  port: "8080"
  host: "0.0.0.0"
  gin_mode: "release"
  default_domain: "app.example.com"

domains:
  app.example.com:
    name: "app.example.com"
    url_prefix: "/auth"
    cookie_name: "session_token"
    base_url: "https://app.example.com"
    oauth:
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      # ... more OAuth settings
    cookie:
      domain: ".example.com"
      secure: true
      # ... more cookie settings
```

See the complete example configuration file for all available options.

## Environment Variables

You can override any configuration value using environment variables with the `AUTH_` prefix:

| Environment Variable | Description | Example |
|---------------------|-------------|---------|
| `CONFIG_FILE` | Path to config file | `CONFIG_FILE=./prod-config.yaml` |
| `AUTH_SERVER_PORT` | Server port | `AUTH_SERVER_PORT=9000` |
| `AUTH_SERVER_GIN_MODE` | Gin mode | `AUTH_SERVER_GIN_MODE=release` |
| `AUTH_DOMAINS_LOCALHOST_OAUTH_CLIENT_ID` | OAuth client ID for localhost | `AUTH_DOMAINS_LOCALHOST_OAUTH_CLIENT_ID=new-client` |

### Environment Variable Naming

Environment variables use dot notation converted to underscores:
- `server.port` → `AUTH_SERVER_PORT`
- `domains.localhost.oauth.client_id` → `AUTH_DOMAINS_LOCALHOST_OAUTH_CLIENT_ID`
- `domains.app_example_com.cookie.secure` → `AUTH_DOMAINS_APP_EXAMPLE_COM_COOKIE_SECURE`

## Usage Examples

### 1. Basic Single Domain Setup

**config.yaml:**
```yaml
server:
  port: "8080"
  default_domain: "localhost"

domains:
  localhost:
    name: "localhost"
    url_prefix: ""
    cookie_name: "auth_token"
    base_url: "http://localhost:8080"
    oauth:
      client_id: "demo-client"
      client_secret: "demo-secret"
      scopes: ["openid", "profile", "email"]
      auth_url: "https://sso.example.com/auth"
      token_url: "https://sso.example.com/token"
      userinfo_url: "https://sso.example.com/userinfo"
      state_string: "random-state"
    cookie:
      path: "/"
      max_age: 3600
      secure: false
      http_only: true
```

**Run:**
```bash
go run main.go
```

**Endpoints:**
- `http://localhost:8080/auth`
- `http://localhost:8080/login`
- `http://localhost:8080/callback`

### 2. Multi-Domain Production Setup

**config.yaml:**
```yaml
server:
  port: "8080"
  gin_mode: "release"
  default_domain: "app.company.com"

domains:
  app.company.com:
    url_prefix: "/sso"
    cookie_name: "app_session"
    # Production OAuth settings
    
  api.company.com:
    url_prefix: "/auth"
    cookie_name: "api_token"
    # API OAuth settings
    
  admin.company.com:
    url_prefix: "/oauth"
    cookie_name: "admin_session"
    # Admin OAuth settings
```

**Run:**
```bash
CONFIG_FILE=prod-config.yaml go run main.go
```

**Domain-specific endpoints:**
- `https://app.company.com/sso/auth`
- `https://api.company.com/auth/auth`
- `https://admin.company.com/oauth/auth`

### 3. Docker Setup

**Dockerfile:**
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o auth-service .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .
COPY config.yaml .

EXPOSE 8080
CMD ["./auth-service"]
```

**docker-compose.yml:**
```yaml
version: '3.8'
services:
  auth-service:
    build: .
    ports:
      - "8080:8080"
    environment:
      - AUTH_SERVER_GIN_MODE=release
      - CONFIG_FILE=/app/config.yaml
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    restart: unless-stopped
```

### 4. Kubernetes Deployment

**configmap.yaml:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
data:
  config.yaml: |
    server:
      port: "8080"
      gin_mode: "release"
    domains:
      # Your domain configurations...
```

**deployment.yaml:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config
          mountPath: /app/config.yaml
          subPath: config.yaml
        env:
        - name: CONFIG_FILE
          value: "/app/config.yaml"
      volumes:
      - name: config
        configMap:
          name: auth-service-config
```

## Domain Resolution

The service resolves domains in this order:

1. **Exact match**: Request host matches a configured domain exactly
2. **Default domain**: Falls back to `server.default_domain`
3. **First available**: Uses the first configured domain as last resort

**Examples:**
- Request to `app.example.com` → Uses `app.example.com` domain config
- Request to `unknown.example.com` → Uses default domain config
- Request to `localhost:8080` → Uses `localhost` domain config

## Nginx Configuration

Update your nginx configuration to handle multiple domains:

```nginx
upstream auth# Auth Service Configuration Guide

## Configuration Options

The auth service supports configuration via environment variables and command line flags:

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_URL_PREFIX` | `""` | URL prefix for all routes (e.g., `/auth-service`) |
| `AUTH_COOKIE_NAME` | `oauth_token` | Name of the authentication cookie |
| `AUTH_PORT` | `8080` | Port to listen on |
| `AUTH_BASE_URL` | `http://localhost:8080` | Base URL for OAuth redirect URI generation |

### Command Line Flags

| Flag | Description |
|------|-------------|
| `-prefix` | URL prefix for all routes |
| `-cookie` | Name of the authentication cookie |
| `-port` | Port to listen on |
| `-base-url` | Base URL for OAuth redirect URI generation |

*Note: Command line flags take precedence over environment variables.*

## Usage Examples

### 1. Default Configuration (No Prefix)

```bash
# Using default settings
go run main.go

# Or with environment variables
export AUTH_COOKIE_NAME="my_auth_token"
export AUTH_PORT="9000"
go run main.go
```

**Endpoints:**
- Auth check: `GET /auth`
- Login: `GET /login`
- Callback: `GET /callback`
- Logout: `GET /logout`
- User info: `GET /userinfo`
- Health: `GET /health`

### 2. With URL Prefix

```bash
# Using command line flags
go run main.go -prefix="/auth-service" -cookie="sso_token" -port="8080"

# Or with environment variables
export AUTH_URL_PREFIX="/auth-service"
export AUTH_COOKIE_NAME="sso_token"
export AUTH_PORT="8080"
export AUTH_BASE_URL="https://auth.example.com"
go run main.go
```

**Endpoints:**
- Auth check: `GET /auth-service/auth`
- Login: `GET /auth-service/login`
- Callback: `GET /auth-service/callback`
- Logout: `GET /auth-service/logout`
- User info: `GET /auth-service/userinfo`
- Health: `GET /auth-service/health`

### 3. Production Configuration

```bash
# Production example with HTTPS
export AUTH_URL_PREFIX="/sso"
export AUTH_COOKIE_NAME="session_token"
export AUTH_PORT="8080"
export AUTH_BASE_URL="https://auth.company.com"
export GIN_MODE="release"
go run main.go
```

### 4. Docker Example

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o auth-service .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .

# Set environment variables
ENV AUTH_URL_PREFIX="/auth"
ENV AUTH_COOKIE_NAME="auth_token"
ENV AUTH_PORT="8080"
ENV AUTH_BASE_URL="https://auth.example.com"
ENV GIN_MODE="release"

EXPOSE 8080
CMD ["./auth-service"]
```

### 5. Docker Compose

```yaml
version: '3.8'
services:
  auth-service:
    build: .
    ports:
      - "8080:8080"
    environment:
      - AUTH_URL_PREFIX=/auth-service
      - AUTH_COOKIE_NAME=sso_session