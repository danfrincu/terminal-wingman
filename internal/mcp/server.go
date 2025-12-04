package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"terminal-wingman/internal/auth"
	"terminal-wingman/internal/ratelimit"
	"terminal-wingman/internal/screen"
	"terminal-wingman/pkg/types"
	"time"
)

// MCPServer represents the MCP server implementation
type MCPServer struct {
	screenManager *screen.Manager
	authStrategy  auth.AuthenticationStrategy
	rateLimiter   *ratelimit.RateLimiter
	config        *types.Config
}

// NewMCPServer creates a new MCP server instance
func NewMCPServer(config *types.Config, screenManager *screen.Manager) (*MCPServer, error) {
	server := &MCPServer{
		screenManager: screenManager,
		config:        config,
	}

	// Setup authentication strategy
	if config.Auth.Type != "none" {
		authStrategy, err := auth.CreateAuthStrategy(config.Auth)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth strategy: %w", err)
		}
		server.authStrategy = authStrategy
		log.Printf("Authentication enabled: %s for user '%s'", config.Auth.Type, config.Auth.Username)
	}

	// Setup rate limiter
	if config.RateLimit.Enabled {
		server.rateLimiter = ratelimit.NewRateLimiter(config.RateLimit.Rate, config.RateLimit.Burst)
		// Start cleanup routine for stale keys
		server.rateLimiter.StartCleanupRoutine(time.Hour, 24*time.Hour)
		log.Printf("Rate limiting enabled: %.1f requests/second, burst %d", config.RateLimit.Rate, config.RateLimit.Burst)
	}

	return server, nil
}

// authenticate handles authentication for requests
func (s *MCPServer) authenticate(params map[string]interface{}) (string, error) {
	if s.authStrategy == nil {
		return "anonymous", nil
	}

	authRequest := auth.ExtractAuthRequest(params)
	username, err := s.authStrategy.Authenticate(authRequest)
	if err != nil {
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	return username, nil
}

// checkRateLimit checks if the request is within rate limits
func (s *MCPServer) checkRateLimit(clientID string) error {
	if s.rateLimiter == nil {
		return nil
	}

	allowed, retryAfter := s.rateLimiter.CheckRateLimit(clientID, 1)
	if !allowed {
		return fmt.Errorf("rate limit exceeded, retry after %.2f seconds", retryAfter)
	}

	return nil
}

// ReadTerminal reads current terminal content from a window
func (s *MCPServer) ReadTerminal(params map[string]interface{}) (*types.TerminalContent, error) {
	// Handle authentication
	clientID, err := s.authenticate(params)
	if err != nil {
		return &types.TerminalContent{Error: err.Error()}, err
	}

	// Handle rate limiting
	if err := s.checkRateLimit(clientID); err != nil {
		return &types.TerminalContent{Error: err.Error()}, err
	}

	// Extract window_id parameter (optional)
	windowID := ""
	if wid, exists := params["window_id"]; exists {
		if widStr, ok := wid.(string); ok {
			windowID = widStr
		}
	}

	// Read terminal content
	return s.screenManager.ReadTerminal(windowID)
}

// ReadScrollback reads scrollback history from a window
func (s *MCPServer) ReadScrollback(params map[string]interface{}) (*types.TerminalContent, error) {
	// Handle authentication
	clientID, err := s.authenticate(params)
	if err != nil {
		return &types.TerminalContent{Error: err.Error()}, err
	}

	// Handle rate limiting
	if err := s.checkRateLimit(clientID); err != nil {
		return &types.TerminalContent{Error: err.Error()}, err
	}

	// Extract parameters
	windowID := ""
	if wid, exists := params["window_id"]; exists {
		if widStr, ok := wid.(string); ok {
			windowID = widStr
		}
	}

	// Get default scrollback settings
	defaultScrollback, maxScrollback := screen.GetDefaultScrollback()

	lines := defaultScrollback
	if l, exists := params["lines"]; exists {
		switch v := l.(type) {
		case int:
			lines = v
		case float64:
			lines = int(v)
		case string:
			// Try to parse string as int
			if parsed, err := fmt.Sscanf(v, "%d", &lines); err != nil || parsed != 1 {
				lines = defaultScrollback
			}
		}
	}

	// Cap at configured scrollback limit
	if lines > maxScrollback {
		lines = maxScrollback
	}

	// Read scrollback
	return s.screenManager.ReadScrollback(windowID, lines)
}

// ListWindows lists all windows in the screen session
func (s *MCPServer) ListWindows(params map[string]interface{}) ([]types.WindowInfo, error) {
	// Handle authentication
	clientID, err := s.authenticate(params)
	if err != nil {
		return []types.WindowInfo{}, err
	}

	// Handle rate limiting
	if err := s.checkRateLimit(clientID); err != nil {
		return []types.WindowInfo{}, err
	}

	// List windows
	return s.screenManager.ListWindows()
}

// UseWindow switches to a specific window
func (s *MCPServer) UseWindow(params map[string]interface{}) (map[string]interface{}, error) {
	// Handle authentication
	clientID, err := s.authenticate(params)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}, err
	}

	// Handle rate limiting
	if err := s.checkRateLimit(clientID); err != nil {
		return map[string]interface{}{"error": err.Error()}, err
	}

	// Extract window_id parameter (required)
	windowID := ""
	if wid, exists := params["window_id"]; exists {
		if widStr, ok := wid.(string); ok {
			windowID = widStr
		}
	}

	if windowID == "" {
		err := fmt.Errorf("window_id parameter is required")
		return map[string]interface{}{"error": err.Error()}, err
	}

	// Switch to window
	if err := s.screenManager.SetWindow(windowID); err != nil {
		return map[string]interface{}{"error": err.Error()}, err
	}

	return map[string]interface{}{
		"success":   true,
		"window_id": windowID,
		"message":   fmt.Sprintf("Switched to window %s", windowID),
	}, nil
}

// GetHealthStatus returns the health status of the server
func (s *MCPServer) GetHealthStatus() *types.HealthStatus {
	status := &types.HealthStatus{
		Status:           "healthy",
		ScreenConnection: true,
		SessionName:      s.screenManager.GetSessionName(),
	}

	// Test screen connection by trying to list windows
	if _, err := s.screenManager.ListWindows(); err != nil {
		status.Status = "unhealthy"
		status.ScreenConnection = false
	}

	return status
}

// Close closes the MCP server and its resources
func (s *MCPServer) Close() error {
	// Nothing to close for screen manager currently
	return nil
}

// MCPResponse represents a standard MCP response
type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP error response
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// HandleToolCall handles MCP tool calls
func (s *MCPServer) HandleToolCall(toolName string, params map[string]interface{}) (interface{}, error) {
	switch toolName {
	case "read_terminal":
		return s.ReadTerminal(params)
	case "read_scrollback":
		return s.ReadScrollback(params)
	case "list_windows":
		return s.ListWindows(params)
	case "use_window":
		return s.UseWindow(params)
	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

// HandleResourceCall handles MCP resource calls
func (s *MCPServer) HandleResourceCall(resourceURI string, params map[string]interface{}) (interface{}, error) {
	// Resource calls not implemented in v1
	return nil, fmt.Errorf("resources not yet implemented")
}

// SerializeResponse serializes a response to JSON
func SerializeResponse(result interface{}, err error) []byte {
	response := &MCPResponse{}

	if err != nil {
		response.Error = &MCPError{
			Code:    -1,
			Message: err.Error(),
		}
	} else {
		response.Result = result
	}

	data, _ := json.Marshal(response)
	return data
}
