# Terminal Wingman MCP Server

A terminal access MCP (Model Context Protocol) server for GNU `screen` sessions. Provides safe, structured access to screen windows and scrollback history with authentication and rate limiting. It is read-only by default. You can turn on an optional write mode with `--allow-input`, which adds a `send_keys` tool for typing commands into a window.

## Features

- **Read-only terminal access**: Read current screen and scrollback history
- **Window management**: List windows and switch between them
- **Optional write mode**: a `send_keys` tool that types into a window as if typed at the keyboard. It is turned on with `--allow-input` and is off by default. The typed text is checked against what appears on the window and resent if characters are dropped, so a command either arrives complete or returns an error
- **Command history**: in write mode, each submitted command and its captured output is written under `~/.terminal-wingman` and kept in a recent-commands buffer, so output can be re-fetched and a window's history resumed after a restart
- **Scrollback search**: find a pattern in a window's scrollback and get back the matching lines with their line numbers, in read-only or write mode
- **.screenrc awareness**: Automatically reads `defscrollback` settings
- **Multiple authentication methods**: None, password, or token-based
- **Rate limiting**: Prevent abuse with configurable limits
- **Multiple transports**: stdio and HTTP
- **Health check endpoint**: Monitor server status
- **Safe execution**: Timeout protection and automatic cleanup

## Installation

### Option 1: Pre-built Binaries (Recommended)
1. Download the latest release for your OS from the [Releases page](../../releases).
2. Extract the archive (e.g., `tar -xzf terminal-wingman_Linux_x86_64.tar.gz`).
3. Move the binary to a location in your PATH:
```bash
sudo mv terminal-wingman /usr/local/bin/
```

### Option 2: Build from Source
```bash
git clone [https://github.com/danfrincu/terminal-wingman.git](https://github.com/danfrincu/terminal-wingman.git)
cd terminal-wingman
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
  --auth-username <your_user_here> \
  --auth-token <your_token>
```

### Generate Authentication Token

```bash
./terminal-wingman --auth-generate-token --auth-username <your_user_here>
```

### Stdio Transport (for Cursor, Claude Code, Windsurf)

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
  --allow-input                 Enable write tools (send_keys) that inject keystrokes into windows (default: read-only)
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

### `send_keys` (write mode)
Type text into a window as if entered at the keyboard, optionally submitting it with Enter. This tool is only available when the server is started with `--allow-input`. Without that flag the tool is not advertised and any call is rejected.

When the text is a submitted command (`enter` is true), the server records it to the command history, waits for it to finish, and returns the captured output along with the paths of the files it was logged to. See "Command history" below.

**Parameters**:
- `text` (required): Text to type into the window
- `window_id` (optional): Window ID/number to send to (defaults to the current window)
- `enter` (optional, default `true`): Append a carriage return to submit the input
- `verify` (optional, default `true`): Before submitting, confirm the text appeared on the window and resend it if characters were dropped. If it cannot confirm the full text, it returns an error instead of sending a partial command. Set it to `false` for input that does not echo, such as passwords
- `wait` (optional, default `5`): Seconds to wait for a submitted command to finish before capturing its output. Completion is detected when the window's shell returns to its prompt. If the command is still running when the wait elapses, the output captured so far is returned and you can read again later for the rest

**Result** (for a submitted command): `completed` (whether it finished within `wait`), `output` and `output_lines`, and `cmds_file` / `output_file` (where it was logged).

**Example** (server must be running with `--allow-input`):
```bash
curl -X POST http://localhost:8080/mcp/tools/send_keys \
  -H "Content-Type: application/json" \
  -d '{"text": "ls -la", "window_id": "12", "enter": true}'
```

### `command_output` (write mode)
Return the stored output of a previously sent command from the command history, so you can re-fetch a command's output without reading the screen again.

**Parameters**:
- `index` (optional, default `0`): How many commands back to fetch, where `0` is the most recent

### `list_commands` (write mode)
List the recent command buffer, newest first, as summaries (index, timestamp, window, command, and output file) without the full output. Use `command_output` with an index to fetch a command's output.

**Parameters**:
- `count` (optional): Maximum number of recent commands to return (default: all, up to the 50-entry buffer)

### `load_history` (write mode)
Merge a window's persisted commands from disk back into the buffer. Use it to resume a window whose history was recorded earlier, for example after a window was closed by accident. Screen reopens a closed window with the same number, so loading that number brings its commands back.

**Parameters**:
- `window` (required): Window ID/number whose persisted commands to load
- `count` (optional): Maximum number of that window's commands to load (default: all available)

### `search`
Search a window's scrollback for a pattern and return the matching lines with their line numbers and surrounding context. The pattern is a regular expression, or a literal substring if it is not a valid regex. This is a read operation, so it works in both read-only and write mode.

**Parameters**:
- `pattern` (required): Pattern to search for
- `window_id` (optional): Window ID/number to search (defaults to the current window)
- `context` (optional, default `0`): Number of context lines to include around each match

**Example**:
```bash
curl -X POST http://localhost:8080/mcp/tools/search \
  -H "Content-Type: application/json" \
  -d '{"pattern": "error", "window_id": "0", "context": 2}'
```

# IDE Integration

## Cursor Integration

Add to your `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "/path/to/terminal-wingman",
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
      "command": "/path/to/terminal-wingman",
      "args": [
        "--session", "work",
        "--transport", "stdio",
        "--auth-type", "token",
        "--auth-username", "your_user_here",
        "--auth-token", "your_token_here"
      ]
    }
  }
}
```

## Windsurf Integration
Add to your `~/.codeium/windsurf/mcp_config.json`

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio"]
    }
  }
}
```

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "/path/to/terminal-wingman",
      "args": [
        "--session", "work",
        "--transport", "stdio",
        "--auth-type", "token",
        "--auth-username", "your_user_here",
        "--auth-token", "your_token_here"
      ]
    }
  }
}
```

## Claude Code Integration
Add to your `~/.claude.json`

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio"]
    }
  }
}
```

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "/path/to/terminal-wingman",
      "args": [
        "--session", "work",
        "--transport", "stdio",
        "--auth-type", "token",
        "--auth-username", "your_user_here",
        "--auth-token", "your_token_here"
      ]
    }
  }
}
```

## Write Mode (enabling `send_keys`)

Write mode is **off by default**. Start the server with `--allow-input` to expose the `send_keys` tool. A common setup is to register a read-only and a read-write server separately so write access is explicit.

### Option A: same binary, two servers (differ only by `--allow-input`)

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "/path/to/terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio"]
    },
    "terminal-wingman-rw": {
      "command": "/path/to/terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio", "--allow-input"]
    }
  }
}
```

### Option B: separate RO and RW binaries

Build a second, identically-compiled binary under a distinct name so the read-only and read-write servers can never be confused (the read-write one is just the same binary invoked with `--allow-input`):

```bash
go build -o terminal-wingman    ./cmd   # read-only
go build -o terminal-wingman-rw ./cmd   # read-write (run with --allow-input)
```

```json
{
  "mcpServers": {
    "terminal-wingman": {
      "command": "/path/to/terminal-wingman",
      "args": ["--session", "work", "--transport", "stdio"]
    },
    "terminal-wingman-rw": {
      "command": "/path/to/terminal-wingman-rw",
      "args": ["--session", "work", "--transport", "stdio", "--allow-input"]
    }
  }
}
```

With either option the tools are namespaced per server (e.g. `terminal-wingman-rw`'s `send_keys`), so the agent reads through the read-only server and only writes through the read-write one.

Once connected, the agent calls `send_keys` like any other tool. Example argument payloads:

```jsonc
// run a command in the current window (Enter is appended by default)
{ "text": "ls -la" }

// target a specific window
{ "text": "emerge --info", "window_id": "3", "enter": true }

// type without submitting, and skip echo verification (e.g. a non-echoing prompt)
{ "text": "y", "window_id": "3", "enter": false, "verify": false }
```

Raw stdio (JSON-RPC) call, for testing outside an IDE:

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"1.0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_keys","arguments":{"text":"ls -la","window_id":"0","enter":true}}}' \
 | ./terminal-wingman --session work --transport stdio --allow-input
```

Or over HTTP (server started with `--allow-input`):

```bash
curl -X POST http://localhost:8080/mcp/tools/send_keys \
  -H "Content-Type: application/json" \
  -d '{"text": "ls -la", "window_id": "0", "enter": true}'
```

Notes:
- Keystrokes are injected with `screen -X stuff`. The text is passed as a single argument and never runs through a host shell, so it cannot run commands on the host. Only the program running in the target window interprets it.
- `verify` (default `true`) is meant for single-line input that echoes, such as shell commands. It types the text, confirms it appeared on the window, resends it if characters were dropped, and then submits. Set `verify` to `false` for input that does not echo.

## Command history

In write mode the server keeps a trail of every submitted command and its output. This lets you re-fetch a command's output later and resume a window's history after a restart.

Files are written under `~/.terminal-wingman/` (created if it does not exist), one pair per command:
- `.<user>-<timestamp>-window_id_<n>.cmds` holds the command
- `.<user>-<timestamp>-window_id_<n>.cmds.output` holds its output

`<user>` is the account the server runs as, `<timestamp>` (`YYYY-MM-DD_HH-MM-SS`) is when the command ran, and `<n>` is the window it ran in. So ten commands produce twenty files, and the name shows which window each belongs to.

In memory the server keeps the most recent 50 commands as a buffer, which `command_output` and `list_commands` read from. On startup the buffer is seeded from disk, but only with commands whose window is still open in the session, so a fresh server reflects the windows you actually have. Commands from windows that are gone stay on disk and are not loaded automatically. Use `load_history` with a window number to pull those back in on demand, which is how you resume after accidentally closing a window.

Completion and capture work without injecting anything into the window. When a command is submitted, the server finds that window's shell and watches the terminal's foreground process group; the command is finished when the foreground returns to the shell's prompt. The output is then read from the window by locating the command's own echo line and taking what follows it. If a command is still running when `wait` elapses, the output captured so far is stored and refreshed the next time you read.

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

- Operations are read-only except for `use_window`, which switches window focus, and `send_keys`, which types into a window. `send_keys` is only available when the server is started with `--allow-input`, and that flag is off by default. Without it the tool is not advertised and any call is rejected
- `send_keys` passes its text as a single argument to `screen -X stuff`, so it never goes through a host shell and cannot run commands on the host. Only the program in the target window interprets the text
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

## Features of terminal-wingman

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
