# Terminal Wingman MCP Server

A read-only terminal access MCP (Model Context Protocol) server for GNU `screen` sessions. Provides safe, structured access to screen windows and scrollback history with authentication and rate limiting.

## Features

- **Read-only terminal access**: Read current screen and scrollback history
- **Window management**: List windows and switch between them
- **.screenrc awareness**: Automatically reads `defscrollback` settings
- **Multiple authentication methods**: None, password, or token-based
- **Rate limiting**: Prevent abuse with configurable limits
- **Multiple transports**: stdio and HTTP
- **Health check endpoint**: Monitor server status
- **Safe execution**: Timeout protection and automatic cleanup

## Installation

```bash
cd ~/git/terminal-wingman
go mod tidy
go build -o terminal-wingman ./cmd
```

## Usage

### Basic Usage (HTTP Transport)

```bash
# Start server with default settings
./terminal-wingman --session work

# Start with authentication
./terminal-wingman \
  --session work \
  --auth-type token \
  --auth-username dan \
  --auth-token <your_token>
```

### Generate Authentication Token

```bash
./terminal-wingman --auth-generate-token --auth-username dan
```

### Stdio Transport (for Cursor)

```bash
./terminal-wingman --session work --transport stdio
```

## Command Line Options

```
Flags:
  --session string              Screen session name (required)
  --max-scrollback-lines int    Override max scrollback lines (default: from .screenrc or 10000)
  --cache-ttl int               Cache TTL in seconds (default: 30)
  --hardcopy-timeout int        Hardcopy timeout in seconds (default: 5)
  --server-host string          MCP server host (default: "localhost")
  --server-port int             MCP server port (default: 8080)
  --transport string            Transport protocol (stdio, streamable-http) (default: "streamable-http")
  --auth-type string            Authentication type (none, password, token) (default: "none")
  --auth-username string        Username for authentication
  --auth-password               Prompt for authentication password
  --auth-password-value string  Password for authentication (NOT RECOMMENDED)
  --auth-token string           Authentication token
  --auth-generate-token         Generate a random token and print it
  --rate-limit                  Enable rate limiting
  --rate-limit-rate float       Requests per second (default: 10)
  --rate-limit-burst int        Maximum burst size (default: 20)
  --log-level string            Logging level (DEBUG, INFO, WARNING, ERROR) (default: "INFO")
  --health-check                Enable health check endpoint at /health
```

## MCP Tools

### `read_terminal`
Read current visible terminal content from a screen window.

**Parameters**:
- `window_id` (optional): Window ID/number to read from

**Example**:
```bash
curl -X POST http://localhost:8080/mcp/tools/read_terminal \
  -H "Content-Type: application/json" \
  -d '{}'
```

### `read_scrollback`
Read scrollback history from a screen window.

**Parameters**:
- `window_id` (optional): Window ID/number to read from
- `lines` (optional): Number of lines (default: from .screenrc or 1000)

**Example**:
```bash
curl -X POST http://localhost:8080/mcp/tools/read_scrollback \
  -H "Content-Type: application/json" \
  -d '{"lines": 2000}'
```

### `list_windows`
List all windows in the screen session.

**Example**:
```bash
curl -X POST http://localhost:8080/mcp/tools/list_windows \
  -H "Content-Type: application/json" \
  -d '{}'
```

### `use_window`
Switch to a specific window.

**Parameters**:
- `window_id` (required): Window ID/number to switch to

**Example**:
```bash
curl -X POST http://localhost:8080/mcp/tools/use_window \
  -H "Content-Type: application/json" \
  -d '{"window_id": "12"}'
```

## Cursor Integration

Add to your `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "~/git/terminal-wingman/terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio"]
    }
  }
}
```

With authentication:

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "~/git/terminal-wingman/terminal-wingman",
      "args": [
        "--session", "work",
        "--transport", "stdio",
        "--auth-type", "token",
        "--auth-username", "dan",
        "--auth-token", "your_token_here"
      ]
    }
  }
}
```

## Scrollback Configuration

Terminal Wingman automatically reads your `~/.screenrc` file for the `defscrollback` setting:

```bash
# In ~/.screenrc
defscrollback 10000
```

Priority order:
1. Command-line `--max-scrollback-lines` flag (highest)
2. .screenrc `defscrollback` setting
3. Default values (1000 default, 10000 max)

## Health Check

When `--health-check` is enabled, a health endpoint is available at:
```
http://localhost:8081/health
```

## Security Notes

- All operations are read-only except `use_window` which switches window focus
- Uses screen's `hardcopy` command for safe content capture
- All screen commands have timeout protection
- Temporary files are automatically cleaned up
- Rate limiting prevents abuse
- Authentication prevents unauthorized access

## Architecture

```
terminal-wingman/
├── cmd/                    # Main application entry point
├── internal/
│   ├── auth/              # Authentication strategies
│   ├── screen/            # Screen session management
│   ├── mcp/               # MCP protocol implementation
│   ├── ratelimit/         # Rate limiting
│   └── server/            # HTTP/transport server
└── pkg/
    ├── types/             # Type definitions
    └── utils/             # Utility functions
```

## Testing

```bash
# Run with screen session "work"
./terminal-wingman --session work

# Test tools
curl -X POST http://localhost:8080/mcp/tools/list_windows -d '{}'
curl -X POST http://localhost:8080/mcp/tools/read_terminal -d '{"window_id": "12"}'
curl -X POST http://localhost:8080/mcp/tools/read_scrollback -d '{"window_id": "12", "lines": 2000}'
curl -X POST http://localhost:8080/mcp/tools/use_window -d '{"window_id": "11"}'
```

## Differences from ssh-wingman

1. **Read-only by default**: Only `use_window` modifies state
2. **Safer execution**: Uses `screen -X hardcopy` for content capture
3. **Better error handling**: Timeouts, validation, automatic cleanup
4. **Structured output**: Proper JSON serialization
5. **Caching**: Reduces unnecessary screen command execution
6. **Both transports**: stdio for Cursor, HTTP for testing
7. **.screenrc awareness**: Respects user's scrollback configuration
8. **Window switching**: Includes `use_window` tool

## See Also

- [GNU Screen Documentation](https://www.gnu.org/software/screen/manual/screen.html)
- [Model Context Protocol](https://modelcontextprotocol.io/)
