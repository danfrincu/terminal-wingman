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
	// AllowInput enables write tools (e.g. send_keys) that inject keystrokes
	// into screen windows. Off by default so the server stays read-only.
	AllowInput bool `json:"allow_input"`
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

// CommandResult is the result of sending a command via send_keys in write mode.
type CommandResult struct {
	Command     string `json:"command"`
	WindowID    string `json:"window_id"`
	Enter       bool   `json:"enter"`
	Completed   bool   `json:"completed"`
	Output      string `json:"output,omitempty"`
	OutputLines int    `json:"output_lines,omitempty"`
	CmdsFile    string `json:"cmds_file,omitempty"`
	OutputFile  string `json:"output_file,omitempty"`
	Message     string `json:"message"`
}

// SearchMatch is a single scrollback line that matched a search.
type SearchMatch struct {
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
	Context    string `json:"context,omitempty"`
}

// SearchResult is the result of searching a window's scrollback.
type SearchResult struct {
	WindowID   string        `json:"window_id"`
	Pattern    string        `json:"pattern"`
	Matches    []SearchMatch `json:"matches"`
	TotalLines int           `json:"total_lines"`
}

// CommandSummary is one entry of the command buffer (without its full output).
type CommandSummary struct {
	Index      int    `json:"index"`
	Timestamp  string `json:"timestamp"`
	Command    string `json:"command"`
	WindowID   string `json:"window_id,omitempty"`
	OutputFile string `json:"output_file"`
}

// CommandOutput is a stored command's output resurfaced from history.
type CommandOutput struct {
	Index      int    `json:"index"`
	Command    string `json:"command"`
	Timestamp  string `json:"timestamp"`
	WindowID   string `json:"window_id,omitempty"`
	Output     string `json:"output"`
	OutputFile string `json:"output_file"`
}

