package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"terminal-wingman/internal/mcp"
	"terminal-wingman/internal/screen"
	"terminal-wingman/pkg/types"
	"time"

	"github.com/gorilla/mux"
)

// Server represents the main server instance
type Server struct {
	config        *types.Config
	screenManager *screen.Manager
	mcpServer     *mcp.MCPServer
	httpServer    *http.Server
	healthServer  *http.Server
	wg            sync.WaitGroup
	shutdown      chan struct{}
}

// NewServer creates a new server instance
func NewServer(config *types.Config) (*Server, error) {
	// Create screen manager
	screenManager, err := screen.NewManager(config.Screen)
	if err != nil {
		return nil, fmt.Errorf("failed to create screen manager: %w", err)
	}

	// Create MCP server
	mcpServer, err := mcp.NewMCPServer(config, screenManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP server: %w", err)
	}

	return &Server{
		config:        config,
		screenManager: screenManager,
		mcpServer:     mcpServer,
		shutdown:      make(chan struct{}),
	}, nil
}

// Start starts the server
func (s *Server) Start() error {
	// Only log startup info for non-stdio transports (stdio uses stderr for protocol communication)
	if s.config.Server.Transport != "stdio" {
		log.Printf("Starting Terminal Wingman MCP Server...")
		log.Printf("  Screen Session: %s", s.config.Screen.SessionName)
		log.Printf("  Server: %s:%d (transport: %s)",
			s.config.Server.Host, s.config.Server.Port, s.config.Server.Transport)
		log.Printf("  Auth: %s", s.config.Auth.Type)
		log.Printf("  Rate Limit: enabled=%v", s.config.RateLimit.Enabled)
		log.Printf("  Max Scrollback: %d lines", s.config.Screen.MaxScrollbackLines)
	}

	// Start health check server if enabled
	if s.config.Server.HealthCheck {
		if err := s.startHealthCheckServer(); err != nil {
			return fmt.Errorf("failed to start health check server: %w", err)
		}
	}

	// Start main server based on transport type
	switch s.config.Server.Transport {
	case "stdio":
		return s.startStdioServer()
	case "streamable-http", "http":
		return s.startHTTPServer()
	default:
		return fmt.Errorf("unsupported transport type: %s", s.config.Server.Transport)
	}
}

// startHealthCheckServer starts the health check HTTP server
func (s *Server) startHealthCheckServer() error {
	router := mux.NewRouter()
	router.HandleFunc("/health", s.handleHealthCheck).Methods("GET")

	healthPort := s.config.Server.Port + 1
	s.healthServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.config.Server.Host, healthPort),
		Handler: router,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("Health check endpoint available at http://%s:%d/health", s.config.Server.Host, healthPort)
		if err := s.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Health check server error: %v", err)
		}
	}()

	return nil
}

// handleHealthCheck handles health check requests
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := s.mcpServer.GetHealthStatus()

	w.Header().Set("Content-Type", "application/json")

	if !status.ScreenConnection {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(status)
}

// startStdioServer starts the stdio-based server
func (s *Server) startStdioServer() error {
	// In stdio mode, disable logging to stderr to avoid confusing the MCP client
	// Only actual errors should go to stderr
	log.SetOutput(io.Discard)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Channel to signal stdio handler completion
	stdioDone := make(chan struct{})

	// Start stdio handler in goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleStdio()
		close(stdioDone)
	}()

	// Wait for shutdown signal or stdio handler to finish
	select {
	case <-sigChan:
		// Received shutdown signal, let stdio handler finish naturally
		// Don't close stdin - let EOF propagate naturally when parent closes it
	case <-stdioDone:
		// Stdio handler finished (stdin closed by parent)
	case <-s.shutdown:
		// Shutdown requested
	}

	return s.Stop()
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      interface{}            `json:"id"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params,omitempty"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// handleStdio handles stdio-based MCP communication
func (s *Server) handleStdio() {
	scanner := bufio.NewScanner(os.Stdin)
	// Buffer sized for worst-case: 204,800 lines x 236 cols x 4 bytes/char + JSON overhead
	// 1MB initial (efficient for small requests), 256MB max (handles full scrollback)
	scanner.Buffer(make([]byte, 1024*1024), 256*1024*1024) // 1MB initial, 256MB max

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Parse JSON-RPC request
		var request JSONRPCRequest
		if err := json.Unmarshal(line, &request); err != nil {
			log.Printf("Failed to parse JSON-RPC request: %v", err)
			s.writeStdioError(nil, -32700, fmt.Sprintf("Parse error: %v", err))
			continue
		}

		// Handle the request
		s.handleJSONRPCRequest(&request)
	}

	// Scanner exits when stdin reaches EOF (parent closes it)
	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("Scanner error: %v", err)
	}

	// Signal shutdown when stdin closes
	select {
	case <-s.shutdown:
		// Already shutting down
	default:
		close(s.shutdown)
	}

	log.Println("Stdio handler finished")
}

// handleJSONRPCRequest processes a JSON-RPC request
func (s *Server) handleJSONRPCRequest(request *JSONRPCRequest) {
	// Check if this is a notification (no ID) - notifications should not receive responses
	isNotification := request.ID == nil

	// Handle different MCP methods
	switch request.Method {
	case "initialize":
		s.handleInitialize(request)
	case "tools/list":
		s.handleToolsList(request)
	case "tools/call":
		s.handleToolsCall(request)
	case "resources/list":
		s.handleResourcesList(request)
	case "resources/read":
		s.handleResourcesRead(request)
	case "notifications/initialized":
		// This is a notification from the client that initialization is complete
		// Per JSON-RPC 2.0 spec, notifications should not receive responses
		log.Println("Client initialization complete (notification)")
	default:
		// Only send error response if this is not a notification
		if !isNotification {
			s.writeStdioError(request.ID, -32601, fmt.Sprintf("Method not found: %s", request.Method))
		} else {
			log.Printf("Ignoring unknown notification: %s", request.Method)
		}
	}
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(request *JSONRPCRequest) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]interface{}{
				"name":    "terminal-wingman",
				"version": "1.0.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{
					"listChanged": false,
				},
			},
		},
	}
	s.writeStdioResponse(&response)
}

// handleToolsList handles the tools/list request
func (s *Server) handleToolsList(request *JSONRPCRequest) {
	// Get scrollback settings for descriptions
	defaultScrollback, maxScrollback := screen.GetDefaultScrollback()

	tools := []map[string]interface{}{
		{
			"name":        "list_windows",
			"description": fmt.Sprintf("List all windows in the screen session '%s'", s.screenManager.GetSessionName()),
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "read_terminal",
			"description": "Read current visible terminal content from a screen window",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"window_id": map[string]interface{}{
						"type":        "string",
						"description": "Window ID/number to read from (optional, defaults to current)",
					},
				},
			},
		},
		{
			"name":        "read_scrollback",
			"description": fmt.Sprintf("Read scrollback history from a screen window (default: %d lines, max: %d lines from .screenrc, absolute max: 100000 lines)", defaultScrollback, maxScrollback),
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"window_id": map[string]interface{}{
						"type":        "string",
						"description": "Window ID/number to read from (optional)",
					},
					"lines": map[string]interface{}{
						"type":        "number",
						"description": fmt.Sprintf("Number of lines to retrieve (default: %d, max: %d, absolute max: 100000)", defaultScrollback, maxScrollback),
					},
				},
			},
		},
		{
			"name":        "use_window",
			"description": "Switch focus to a different window in the screen session",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"window_id": map[string]interface{}{
						"type":        "string",
						"description": "Window ID/number to switch to (required)",
					},
				},
				"required": []string{"window_id"},
			},
		},
	}

	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
	s.writeStdioResponse(&response)
}

// handleToolsCall handles the tools/call request
func (s *Server) handleToolsCall(request *JSONRPCRequest) {
	// Extract tool name and arguments
	toolName, ok := request.Params["name"].(string)
	if !ok {
		s.writeStdioError(request.ID, -32602, "Missing or invalid 'name' parameter")
		return
	}

	// Extract arguments
	var args map[string]interface{}
	if argsParam, exists := request.Params["arguments"]; exists {
		if argsMap, ok := argsParam.(map[string]interface{}); ok {
			args = argsMap
		}
	}
	if args == nil {
		args = make(map[string]interface{})
	}

	// Call the tool
	result, err := s.mcpServer.HandleToolCall(toolName, args)

	if err != nil {
		response := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": fmt.Sprintf("Error: %v", err),
					},
				},
				"isError": true,
			},
		}
		s.writeStdioResponse(&response)
		return
	}

	// Format result as MCP tool response
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": formatToolResult(result),
				},
			},
		},
	}
	s.writeStdioResponse(&response)
}

// handleResourcesList handles the resources/list request
func (s *Server) handleResourcesList(request *JSONRPCRequest) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      request.ID,
		Result: map[string]interface{}{
			"resources": []interface{}{},
		},
	}
	s.writeStdioResponse(&response)
}

// handleResourcesRead handles the resources/read request
func (s *Server) handleResourcesRead(request *JSONRPCRequest) {
	s.writeStdioError(request.ID, -32601, "Resources not yet implemented")
}

// formatToolResult formats the tool result for MCP response
func formatToolResult(result interface{}) string {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", result)
	}
	return string(data)
}

// writeStdioResponse writes a JSON-RPC response to stdout
func (s *Server) writeStdioResponse(response *JSONRPCResponse) {
	data, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	fmt.Fprintf(os.Stdout, "%s\n", data)
	os.Stdout.Sync()
}

// writeStdioError writes a JSON-RPC error response to stdout
func (s *Server) writeStdioError(id interface{}, code int, message string) {
	response := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	s.writeStdioResponse(&response)
}

// startHTTPServer starts the HTTP-based server
func (s *Server) startHTTPServer() error {
	router := mux.NewRouter()

	// MCP endpoints
	router.HandleFunc("/mcp", s.handleMCPRequest).Methods("POST")
	router.HandleFunc("/mcp/tools/{tool}", s.handleToolCall).Methods("POST")
	router.HandleFunc("/mcp/resources", s.handleResourceCall).Methods("GET")

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port),
		Handler: router,
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start HTTP server
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log.Printf("HTTP server listening on %s", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	select {
	case <-sigChan:
		log.Println("Received shutdown signal")
	case <-s.shutdown:
		log.Println("Shutdown requested")
	}

	return s.Stop()
}

// handleMCPRequest handles general MCP requests
func (s *Server) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var request map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// TODO: Implement full MCP protocol handling
	response := map[string]interface{}{
		"result": "MCP request handling not yet implemented",
	}

	json.NewEncoder(w).Encode(response)
}

// handleToolCall handles MCP tool calls
func (s *Server) handleToolCall(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	toolName := vars["tool"]

	w.Header().Set("Content-Type", "application/json")

	var params map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	result, err := s.mcpServer.HandleToolCall(toolName, params)
	response := mcp.SerializeResponse(result, err)

	w.Write(response)
}

// handleResourceCall handles MCP resource calls
func (s *Server) handleResourceCall(w http.ResponseWriter, r *http.Request) {
	resourceURI := r.URL.Query().Get("uri")
	if resourceURI == "" {
		http.Error(w, "Missing uri parameter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Extract query parameters as params
	params := make(map[string]interface{})
	for key, values := range r.URL.Query() {
		if key != "uri" && len(values) > 0 {
			params[key] = values[0]
		}
	}

	result, err := s.mcpServer.HandleResourceCall(resourceURI, params)
	response := mcp.SerializeResponse(result, err)

	w.Write(response)
}

// Stop gracefully stops the server
func (s *Server) Stop() error {
	log.Println("Stopping server...")

	// Signal shutdown (safely handle if already closed)
	select {
	case <-s.shutdown:
		// Already closed
	default:
		close(s.shutdown)
	}

	// Stop HTTP servers with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}

	if s.healthServer != nil {
		if err := s.healthServer.Shutdown(ctx); err != nil {
			log.Printf("Health server shutdown error: %v", err)
		}
	}

	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All goroutines finished")
	case <-time.After(15 * time.Second):
		log.Println("Timeout waiting for goroutines to finish")
	}

	// Close MCP server
	if s.mcpServer != nil {
		if err := s.mcpServer.Close(); err != nil {
			log.Printf("Error closing MCP server: %v", err)
		}
	}

	log.Println("Server stopped")
	return nil
}
