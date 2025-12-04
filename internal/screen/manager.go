package screen

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"terminal-wingman/pkg/types"
	"time"
)

const (
	DefaultScrollback      = 1000
	DefaultMaxScrollback   = 10000
	AbsoluteMaxScrollback  = 100000 // Safety limit to prevent excessive memory usage (will be overridden by .screenrc if higher)
	DefaultCacheTTL        = 30 * time.Second
	DefaultHardcopyTimeout = 5 * time.Second
)

// Manager handles screen session management
type Manager struct {
	sessionName       string
	currentWindowID   string
	cacheTTL          time.Duration
	hardcopyTimeout   time.Duration
	maxScrollback     int
	defaultScrollback int
	windowsCache      *windowsCache
	mu                sync.RWMutex
}

// windowsCache caches the list of windows
type windowsCache struct {
	windows   []types.WindowInfo
	timestamp time.Time
	mu        sync.RWMutex
}

// NewManager creates a new screen manager
func NewManager(config types.ScreenConfig) (*Manager, error) {
	if config.SessionName == "" {
		return nil, fmt.Errorf("session name is required")
	}

	// Read scrollback settings from .screenrc
	defaultScrollback, maxScrollback := GetDefaultScrollback()

	// Override with config if provided
	if config.MaxScrollbackLines > 0 {
		maxScrollback = config.MaxScrollbackLines
	}

	cacheTTL := time.Duration(config.CacheTTL) * time.Second
	if cacheTTL == 0 {
		cacheTTL = DefaultCacheTTL
	}

	hardcopyTimeout := time.Duration(config.HardcopyTimeout) * time.Second
	if hardcopyTimeout == 0 {
		hardcopyTimeout = DefaultHardcopyTimeout
	}

	manager := &Manager{
		sessionName:       config.SessionName,
		cacheTTL:          cacheTTL,
		hardcopyTimeout:   hardcopyTimeout,
		maxScrollback:     maxScrollback,
		defaultScrollback: defaultScrollback,
		windowsCache:      &windowsCache{},
	}

	// Validate session exists
	if err := manager.ValidateSession(); err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	return manager, nil
}

// getScrollbackFromScreenrc reads the defscrollback setting from ~/.screenrc
func getScrollbackFromScreenrc() (int, bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return DefaultScrollback, false
	}

	screenrcPath := filepath.Join(homeDir, ".screenrc")
	file, err := os.Open(screenrcPath)
	if err != nil {
		return DefaultScrollback, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "defscrollback ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if scrollback, err := strconv.Atoi(parts[1]); err == nil && scrollback > 0 {
					return scrollback, true
				}
			}
		}
	}

	return DefaultScrollback, false
}

// GetDefaultScrollback returns the default and max scrollback lines
// If .screenrc has defscrollback, use that value for both
// Otherwise use DefaultScrollback and DefaultMaxScrollback
func GetDefaultScrollback() (defaultLines int, maxLines int) {
	configuredScrollback, found := getScrollbackFromScreenrc()
	if found {
		// User has configured defscrollback, use it as both default and max
		return configuredScrollback, configuredScrollback
	}
	// No defscrollback found, use defaults
	return DefaultScrollback, DefaultMaxScrollback
}

// ValidateSession checks if the screen session exists
func (m *Manager) ValidateSession() error {
	sessions, err := m.listScreenSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	for _, session := range sessions {
		if session == m.sessionName {
			return nil
		}
	}

	return fmt.Errorf("screen session '%s' not found", m.sessionName)
}

// listScreenSessions lists all available screen sessions
func (m *Manager) listScreenSessions() ([]string, error) {
	var stdout bytes.Buffer
	cmd := exec.Command("screen", "-ls")
	cmd.Stdout = &stdout

	// screen -ls returns non-zero exit codes in various cases:
	// - exit 1: sessions exist (on some systems)
	// - exit 1: no sessions exist (on some systems)
	// We ignore the exit code and just parse the output
	_ = cmd.Run()

	// Parse output: lines like "12345.sessionname	(Attached)" or "12345.sessionname	(Detached)"
	output := stdout.String()
	lines := strings.Split(output, "\n")
	var sessions []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ".") && (strings.Contains(line, "Detached") || strings.Contains(line, "Attached")) {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				sessionPart := parts[0]
				if dotIndex := strings.Index(sessionPart, "."); dotIndex != -1 {
					sessionName := sessionPart[dotIndex+1:]
					sessions = append(sessions, sessionName)
				}
			}
		}
	}

	return sessions, nil
}

// ListWindows lists all windows in the screen session
func (m *Manager) ListWindows() ([]types.WindowInfo, error) {
	// Check cache first
	m.windowsCache.mu.RLock()
	if time.Since(m.windowsCache.timestamp) < m.cacheTTL && len(m.windowsCache.windows) > 0 {
		windows := m.windowsCache.windows
		m.windowsCache.mu.RUnlock()
		return windows, nil
	}
	m.windowsCache.mu.RUnlock()

	// Cache miss, fetch from screen
	windows, err := m.fetchWindowsList()
	if err != nil {
		return nil, err
	}

	// Update cache
	m.windowsCache.mu.Lock()
	m.windowsCache.windows = windows
	m.windowsCache.timestamp = time.Now()
	m.windowsCache.mu.Unlock()

	return windows, nil
}

// fetchWindowsList fetches the window list from screen
func (m *Manager) fetchWindowsList() ([]types.WindowInfo, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("screen", "-S", m.sessionName, "-Q", "windows")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Set wide COLUMNS to avoid truncation
	cmd.Env = append(os.Environ(), "COLUMNS=500", "LINES=50")

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to list windows: %w (stderr: %s)", err, stderr.String())
	}

	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return []types.WindowInfo{}, nil
	}

	return parseWindowsList(output), nil
}

// parseWindowsList parses screen windows output
// Format: "0 term  1 build  2 cursor  3* todo  4- git"
func parseWindowsList(output string) []types.WindowInfo {
	var windows []types.WindowInfo
	fields := strings.Fields(output)

	for i := 0; i < len(fields); i++ {
		field := fields[i]

		// Check if this field is a window number
		windowNum := ""
		if num, err := strconv.Atoi(field); err == nil {
			windowNum = strconv.Itoa(num)
		} else {
			// Check if field ends with * or - (active indicators)
			if strings.HasSuffix(field, "*") || strings.HasSuffix(field, "-") {
				// Extract number from field like "3*"
				numPart := field[:len(field)-1]
				if num, err := strconv.Atoi(numPart); err == nil {
					windowNum = strconv.Itoa(num)
				}
			}
		}

		if windowNum != "" {
			// This is a window number, next field (if exists) is the name
			name := windowNum
			active := strings.HasSuffix(field, "*")

			// Check if next field is the window name
			if i+1 < len(fields) {
				nextField := fields[i+1]
				// If next field is not a number, it's the name
				if _, err := strconv.Atoi(nextField); err != nil {
					// Check if it has active indicator
					if strings.HasSuffix(nextField, "*") || strings.HasSuffix(nextField, "-") {
						name = nextField
						active = strings.HasSuffix(nextField, "*")
					} else {
						name = nextField
					}
				}
			}

			windows = append(windows, types.WindowInfo{
				ID:     windowNum,
				Name:   name,
				Active: active,
			})
		}
	}

	return windows
}

// ReadTerminal reads the current visible terminal content
func (m *Manager) ReadTerminal(windowID string) (*types.TerminalContent, error) {
	content, err := m.captureWindow(windowID, false)
	if err != nil {
		return &types.TerminalContent{
			Error: err.Error(),
		}, err
	}

	lines := strings.Count(content, "\n")

	return &types.TerminalContent{
		Content:   content,
		WindowID:  windowID,
		Lines:     lines,
		Timestamp: time.Now().Unix(),
	}, nil
}

// ReadScrollback reads scrollback history from a window
func (m *Manager) ReadScrollback(windowID string, lines int) (*types.TerminalContent, error) {
	// Validate and cap lines
	if lines <= 0 {
		lines = m.defaultScrollback
	}
	if lines > m.maxScrollback {
		lines = m.maxScrollback
	}
	// Apply absolute safety limit to prevent excessive memory usage
	if lines > AbsoluteMaxScrollback {
		lines = AbsoluteMaxScrollback
	}

	content, err := m.captureWindow(windowID, true)
	if err != nil {
		return &types.TerminalContent{
			Error: err.Error(),
		}, err
	}

	// Limit to requested number of lines
	content = limitLines(content, lines)
	lineCount := strings.Count(content, "\n")

	return &types.TerminalContent{
		Content:   content,
		WindowID:  windowID,
		Lines:     lineCount,
		Timestamp: time.Now().Unix(),
	}, nil
}

// captureWindow captures window content using screen hardcopy
func (m *Manager) captureWindow(windowID string, includeScrollback bool) (string, error) {
	// Validate window exists if windowID is specified
	if windowID != "" {
		windows, err := m.ListWindows()
		if err != nil {
			return "", fmt.Errorf("failed to list windows: %w", err)
		}

		found := false
		for _, win := range windows {
			if win.ID == windowID {
				found = true
				break
			}
		}

		if !found {
			return "", fmt.Errorf("window '%s' not found in session '%s'", windowID, m.sessionName)
		}
	}

	var stderr bytes.Buffer

	// Use a fixed temporary file path (like ssh-wingman does)
	tempFile := "/tmp/terminal-wingman-capture"
	defer os.Remove(tempFile)

	// Build screen command
	args := []string{"-S", m.sessionName}
	if windowID != "" {
		args = append(args, "-p", windowID)
	}
	args = append(args, "-X", "hardcopy")
	if includeScrollback {
		args = append(args, "-h")
	}
	args = append(args, tempFile)

	// Execute hardcopy command
	cmd := exec.Command("screen", args...)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("hardcopy failed: %w (stderr: %s)", err, stderr.String())
	}

	// Small sleep to ensure screen finishes writing the file
	// Screen's hardcopy -X command may return before file is fully written
	time.Sleep(100 * time.Millisecond)

	// Wait for file to exist with timeout
	// Increased from 1s to 3s to handle large scrollback buffers (100+ MB)
	maxWait := 3 * time.Second
	waitInterval := 10 * time.Millisecond
	totalWait := time.Duration(0)

	for totalWait < maxWait {
		if _, err := os.Stat(tempFile); err == nil {
			// File exists, wait a bit more for write to complete
			time.Sleep(50 * time.Millisecond)
			break
		}
		time.Sleep(waitInterval)
		totalWait += waitInterval
	}

	// Read captured content directly
	content, err := os.ReadFile(tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to read captured content: %w", err)
	}

	return string(content), nil
}

// limitLines returns the last N lines from content
func limitLines(content string, lines int) string {
	allLines := strings.Split(content, "\n")
	if len(allLines) <= lines {
		return content
	}
	return strings.Join(allLines[len(allLines)-lines:], "\n")
}

// SetWindow switches to a specific window
func (m *Manager) SetWindow(windowID string) error {
	if windowID == "" {
		return fmt.Errorf("window ID is required")
	}

	// Validate window exists
	windows, err := m.ListWindows()
	if err != nil {
		return fmt.Errorf("failed to list windows: %w", err)
	}

	found := false
	for _, win := range windows {
		if win.ID == windowID {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("window '%s' not found in session '%s'", windowID, m.sessionName)
	}

	// Execute select command
	cmd := exec.Command("screen", "-S", m.sessionName, "-p", windowID, "-X", "select", windowID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to switch to window %s: %w (stderr: %s)", windowID, err, stderr.String())
	}

	// Update current window
	m.mu.Lock()
	m.currentWindowID = windowID
	m.mu.Unlock()

	// Invalidate cache to reflect new active window
	m.windowsCache.mu.Lock()
	m.windowsCache.timestamp = time.Time{}
	m.windowsCache.mu.Unlock()

	return nil
}

// GetWindowInfo returns information about a specific window
func (m *Manager) GetWindowInfo(windowID string) (*types.WindowInfo, error) {
	windows, err := m.ListWindows()
	if err != nil {
		return nil, err
	}

	for _, win := range windows {
		if win.ID == windowID {
			return &win, nil
		}
	}

	return nil, fmt.Errorf("window '%s' not found", windowID)
}

// GetCurrentWindow returns the current window ID
func (m *Manager) GetCurrentWindow() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentWindowID
}

// GetSessionName returns the session name
func (m *Manager) GetSessionName() string {
	return m.sessionName
}
