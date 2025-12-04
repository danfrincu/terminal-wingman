package types

import "time"

// Config holds the server configuration
type Config struct {
	// Screen settings
	Screen ScreenConfig `json:"screen"`

	// Server settings
	Server ServerConfig `json:"server"`

	// Authentication settings
	Auth AuthConfig `json:"auth"`

	// Rate limiting settings
	RateLimit RateLimitConfig `json:"rate_limit"`

	// Logging settings
	LogLevel string `json:"log_level"`
}

// ScreenConfig holds screen session configuration
type ScreenConfig struct {
	SessionName        string `json:"session_name"`
	MaxScrollbackLines int    `json:"max_scrollback_lines"`
	CacheTTL           int    `json:"cache_ttl"`
	HardcopyTimeout    int    `json:"hardcopy_timeout"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Transport   string `json:"transport"`
	HealthCheck bool   `json:"health_check"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Type      string `json:"type"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Token     string `json:"token"`
	KeyID     string `json:"key_id"`
	SecretKey string `json:"secret_key"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled bool    `json:"enabled"`
	Rate    float64 `json:"rate"`
	Burst   int     `json:"burst"`
}

// WindowInfo represents information about a screen window
type WindowInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// TerminalContent represents terminal content
type TerminalContent struct {
	Content   string  `json:"content"`
	WindowID  string  `json:"window_id"`
	Lines     int     `json:"lines"`
	Timestamp int64   `json:"timestamp"`
	Error     string  `json:"error,omitempty"`
}

// TerminalInfo represents terminal information
type TerminalInfo struct {
	WindowID     string            `json:"window_id"`
	SessionName  string            `json:"session_name"`
	Dimensions   map[string]string `json:"dimensions"`
	CurrentPath  string            `json:"current_path"`
}

// CacheEntry represents a cached item
type CacheEntry struct {
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Token     string `json:"token,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Payload   string `json:"payload,omitempty"`
}

// HealthStatus represents the health status of the server
type HealthStatus struct {
	Status            string `json:"status"`
	ScreenConnection  bool   `json:"screen_connection"`
	SessionName       string `json:"session_name"`
}

// ToolResult represents the result of a tool execution
type ToolResult struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
	Status int         `json:"status,omitempty"`
}

