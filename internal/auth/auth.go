package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"terminal-wingman/pkg/types"
	"time"
)

// AuthenticationStrategy interface for different authentication methods
type AuthenticationStrategy interface {
	Authenticate(request *types.AuthRequest) (string, error)
}

// PasswordAuthentication implements username/password authentication
type PasswordAuthentication struct {
	username string
	password string
}

// NewPasswordAuthentication creates a new password authentication strategy
func NewPasswordAuthentication(username, password string) *PasswordAuthentication {
	return &PasswordAuthentication{
		username: username,
		password: password,
	}
}

// Authenticate validates username and password
func (p *PasswordAuthentication) Authenticate(request *types.AuthRequest) (string, error) {
	if request.Username == "" || request.Password == "" {
		return "", fmt.Errorf("username and password required")
	}

	if request.Username == p.username && request.Password == p.password {
		return p.username, nil
	}

	return "", fmt.Errorf("invalid credentials")
}

// TokenAuthentication implements token-based authentication
type TokenAuthentication struct {
	token    string
	username string
}

// NewTokenAuthentication creates a new token authentication strategy
func NewTokenAuthentication(token, username string) *TokenAuthentication {
	return &TokenAuthentication{
		token:    token,
		username: username,
	}
}

// Authenticate validates the authentication token
func (t *TokenAuthentication) Authenticate(request *types.AuthRequest) (string, error) {
	if request.Token == "" {
		return "", fmt.Errorf("token required")
	}

	if request.Token == t.token {
		return t.username, nil
	}

	return "", fmt.Errorf("invalid token")
}

// HMACAuthentication implements HMAC-based request signing authentication
type HMACAuthentication struct {
	keyID     string
	secretKey string
	username  string
}

// NewHMACAuthentication creates a new HMAC authentication strategy
func NewHMACAuthentication(keyID, secretKey, username string) *HMACAuthentication {
	return &HMACAuthentication{
		keyID:     keyID,
		secretKey: secretKey,
		username:  username,
	}
}

// Authenticate validates HMAC signature
func (h *HMACAuthentication) Authenticate(request *types.AuthRequest) (string, error) {
	// Check required fields
	if request.KeyID == "" || request.Signature == "" || request.Timestamp == 0 || request.Payload == "" {
		return "", fmt.Errorf("keyID, signature, timestamp, and payload required for HMAC authentication")
	}

	// Check key ID
	if request.KeyID != h.keyID {
		return "", fmt.Errorf("invalid key ID")
	}

	// Verify timestamp (within 5 minutes)
	now := time.Now().Unix()
	if abs(now-request.Timestamp) > 300 { // 5 minutes
		return "", fmt.Errorf("authentication timestamp expired")
	}

	// Create signing string
	signingString := fmt.Sprintf("%d:%s", request.Timestamp, request.Payload)

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(h.secretKey))
	mac.Write([]byte(signingString))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Compare signatures (constant-time comparison to prevent timing attacks)
	if !hmac.Equal([]byte(expectedSignature), []byte(request.Signature)) {
		return "", fmt.Errorf("invalid signature")
	}

	return h.username, nil
}

// abs returns the absolute value of x
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// GenerateToken generates a random authentication token
func GenerateToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// GenerateHMACKeys generates random HMAC key ID and secret key
func GenerateHMACKeys() (keyID, secretKey string, err error) {
	// Generate key ID (16 random bytes)
	keyIDBytes := make([]byte, 8)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	keyID = "key_" + hex.EncodeToString(keyIDBytes)

	// Generate secret key (32 random bytes)
	secretKeyBytes := make([]byte, 32)
	if _, err := rand.Read(secretKeyBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate secret key: %w", err)
	}
	secretKey = hex.EncodeToString(secretKeyBytes)

	return keyID, secretKey, nil
}

// CreateAuthStrategy creates an authentication strategy based on config
func CreateAuthStrategy(config types.AuthConfig) (AuthenticationStrategy, error) {
	switch config.Type {
	case "password":
		if config.Username == "" || config.Password == "" {
			return nil, fmt.Errorf("username and password required for password authentication")
		}
		return NewPasswordAuthentication(config.Username, config.Password), nil

	case "token":
		if config.Username == "" || config.Token == "" {
			return nil, fmt.Errorf("username and token required for token authentication")
		}
		return NewTokenAuthentication(config.Token, config.Username), nil

	case "hmac":
		if config.Username == "" || config.KeyID == "" || config.SecretKey == "" {
			return nil, fmt.Errorf("username, keyID, and secretKey required for HMAC authentication")
		}
		return NewHMACAuthentication(config.KeyID, config.SecretKey, config.Username), nil

	case "none":
		return nil, nil

	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", config.Type)
	}
}

// ExtractAuthRequest extracts authentication data from parameters
func ExtractAuthRequest(params map[string]interface{}) *types.AuthRequest {
	request := &types.AuthRequest{}

	if username, ok := params["username"].(string); ok {
		request.Username = username
	}

	if password, ok := params["password"].(string); ok {
		request.Password = password
	}

	if token, ok := params["token"].(string); ok {
		request.Token = token
	}

	if keyID, ok := params["key_id"].(string); ok {
		request.KeyID = keyID
	}

	if signature, ok := params["signature"].(string); ok {
		request.Signature = signature
	}

	if timestamp, ok := params["timestamp"]; ok {
		switch t := timestamp.(type) {
		case int64:
			request.Timestamp = t
		case int:
			request.Timestamp = int64(t)
		case float64:
			request.Timestamp = int64(t)
		case string:
			if ts, err := strconv.ParseInt(t, 10, 64); err == nil {
				request.Timestamp = ts
			}
		}
	}

	if payload, ok := params["payload"].(string); ok {
		request.Payload = payload
	}

	return request
}
