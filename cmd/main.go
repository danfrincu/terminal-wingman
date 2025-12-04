package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"terminal-wingman/internal/auth"
	"terminal-wingman/internal/screen"
	"terminal-wingman/internal/server"
	"terminal-wingman/pkg/types"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var config types.Config

var rootCmd = &cobra.Command{
	Use:   "terminal-wingman",
	Short: "Terminal Wingman MCP Server",
	Long:  `A read-only terminal access MCP server for GNU screen sessions with authentication and rate limiting.`,
	Run:   runServer,
}

func init() {
	// Screen session flags
	rootCmd.Flags().StringVar(&config.Screen.SessionName, "session", "", "Screen session name (required)")
	rootCmd.Flags().IntVar(&config.Screen.MaxScrollbackLines, "max-scrollback-lines", 0, "Override max scrollback lines (default: from .screenrc or 10000)")
	rootCmd.Flags().IntVar(&config.Screen.CacheTTL, "cache-ttl", 30, "Cache TTL in seconds")
	rootCmd.Flags().IntVar(&config.Screen.HardcopyTimeout, "hardcopy-timeout", 5, "Hardcopy timeout in seconds")

	// Server flags
	rootCmd.Flags().StringVar(&config.Server.Host, "server-host", "localhost", "MCP server host")
	rootCmd.Flags().IntVar(&config.Server.Port, "server-port", 8080, "MCP server port")
	rootCmd.Flags().StringVar(&config.Server.Transport, "transport", "streamable-http", "Transport protocol (stdio, streamable-http)")
	rootCmd.Flags().BoolVar(&config.Server.HealthCheck, "health-check", false, "Enable health check endpoint at /health")

	// Logging flags
	rootCmd.Flags().StringVar(&config.LogLevel, "log-level", "INFO", "Logging level (DEBUG, INFO, WARNING, ERROR)")

	// Rate limiting flags
	rootCmd.Flags().BoolVar(&config.RateLimit.Enabled, "rate-limit", false, "Enable rate limiting")
	rootCmd.Flags().Float64Var(&config.RateLimit.Rate, "rate-limit-rate", 10.0, "Requests per second")
	rootCmd.Flags().IntVar(&config.RateLimit.Burst, "rate-limit-burst", 20, "Maximum burst size")

	// Authentication flags
	rootCmd.Flags().StringVar(&config.Auth.Type, "auth-type", "none", "Authentication type (none, password, token)")
	rootCmd.Flags().StringVar(&config.Auth.Username, "auth-username", "", "Username for authentication")
	rootCmd.Flags().StringVar(&config.Auth.Password, "auth-password-value", "", "Password for authentication (NOT RECOMMENDED)")
	rootCmd.Flags().BoolP("auth-password", "", false, "Prompt for authentication password")
	rootCmd.Flags().StringVar(&config.Auth.Token, "auth-token", "", "Authentication token")
	rootCmd.Flags().BoolVar(&generateToken, "auth-generate-token", false, "Generate a random token and print it")

	// Mark session as required
	rootCmd.MarkFlagRequired("session")
}

var generateToken bool

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Handle token generation first
	if generateToken, _ := cmd.Flags().GetBool("auth-generate-token"); generateToken {
		token, err := auth.GenerateToken()
		if err != nil {
			log.Fatalf("Failed to generate token: %v", err)
		}
		fmt.Printf("Generated authentication token: %s\n", token)
		fmt.Printf("Use this with --auth-type=token --auth-token=%s\n", token)
		if config.Auth.Username == "" {
			fmt.Println("WARNING: No auth username provided. Use --auth-username to specify a username.")
		}
		return
	}

	// Validate session name is provided
	if config.Screen.SessionName == "" {
		log.Fatal("Screen session name is required (--session)")
	}

	// Handle authentication password input
	if promptAuthPass, _ := cmd.Flags().GetBool("auth-password"); promptAuthPass {
		fmt.Print("Enter authentication password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read authentication password: %v", err)
		}
		fmt.Println() // Print newline after password input
		config.Auth.Password = string(password)
	}

	// Validate authentication configuration
	if err := validateAuthConfig(); err != nil {
		log.Fatalf("Authentication configuration error: %v", err)
	}

	// Set max scrollback if not provided
	if config.Screen.MaxScrollbackLines == 0 {
		// Will be read from .screenrc by the screen manager
		_, maxScrollback := screen.GetDefaultScrollback()
		config.Screen.MaxScrollbackLines = maxScrollback
		// Don't log in stdio mode as it pollutes stderr
		if config.Server.Transport != "stdio" {
			log.Printf("Using scrollback settings: max=%d (from .screenrc or defaults)", maxScrollback)
		}
	}

	// Start the server
	if err := startServer(&config); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func validateAuthConfig() error {
	switch config.Auth.Type {
	case "none":
		return nil
	case "password":
		if config.Auth.Username == "" {
			return fmt.Errorf("authentication username required with --auth-type=password")
		}
		if config.Auth.Password == "" {
			return fmt.Errorf("no authentication password provided with --auth-type=password")
		}
	case "token":
		if config.Auth.Username == "" {
			return fmt.Errorf("authentication username required with --auth-type=token")
		}
		if config.Auth.Token == "" {
			return fmt.Errorf("authentication token required with --auth-type=token")
		}
	default:
		return fmt.Errorf("unsupported authentication type: %s", config.Auth.Type)
	}
	return nil
}

func startServer(config *types.Config) error {
	// Create and start the server
	srv, err := server.NewServer(config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	return srv.Start()
}
