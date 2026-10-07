package screen

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"terminal-wingman/internal/history"
	"terminal-wingman/pkg/types"
)

// flushDelay gives screen time to flush a finished command's output to the
// window before we capture it.
const flushDelay = 100 * time.Millisecond

// SendCommand sends text to a window and, for a submitted command in write
// mode, records it and captures its output. It waits up to `wait` for the
// command to finish (detected by the window's shell returning to its prompt);
// if it is still running at `wait`, the partial output is captured and the
// caller can read again later for more.
func (m *Manager) SendCommand(windowID, text string, enter, verify bool, wait time.Duration) (*types.CommandResult, error) {
	if err := m.SendKeys(windowID, text, enter, verify); err != nil {
		return nil, err
	}

	res := &types.CommandResult{Command: text, WindowID: windowID, Enter: enter, Message: "Sent keys to window"}

	// History and output capture apply only to submitted commands in write mode
	// targeting a specific window.
	if !enter || m.history == nil || windowID == "" {
		return res, nil
	}

	ts := time.Now()
	rec, err := m.history.RecordCommand(strings.TrimRight(text, "\r\n"), windowID, ts)
	if err != nil {
		res.Message = "Sent command; could not record history: " + err.Error()
		return res, nil
	}
	res.CmdsFile = rec.CmdsFile
	res.OutputFile = rec.OutputFile

	if pid, perr := m.windowShellPID(windowID); perr == nil {
		res.Completed = m.waitForPrompt(pid, wait)
	} else {
		// Cannot resolve the shell pid, so fall back to a plain wait.
		time.Sleep(wait)
	}

	time.Sleep(flushDelay)
	if capture, cerr := m.captureWindow(windowID, true); cerr == nil {
		if out, ok := extractCommandOutput(capture, rec.Command); ok {
			_ = m.history.WriteOutput(rec, out)
			res.Output = out
			res.OutputLines = countLines(out)
		}
	}

	if res.Completed {
		res.Message = "Command completed; output captured"
	} else {
		res.Message = "Command still running after wait; partial output captured (read again for more)"
	}
	return res, nil
}

// CommandOutput resurfaces a stored command's output from the history buffer and
// its on-disk file, where index 0 is the most recent command.
func (m *Manager) CommandOutput(index int) (*types.CommandOutput, error) {
	if m.history == nil {
		return nil, fmt.Errorf("command history is not enabled (start the server with --allow-input)")
	}
	rec, ok := m.history.Get(index)
	if !ok {
		return nil, fmt.Errorf("no command at index %d", index)
	}
	out, err := history.ReadOutput(rec)
	if err != nil {
		return nil, err
	}
	return &types.CommandOutput{
		Index:      index,
		Command:    rec.Command,
		Timestamp:  rec.Timestamp.Format("2006-01-02 15:04:05"),
		WindowID:   rec.WindowID,
		Output:     out,
		OutputFile: rec.OutputFile,
	}, nil
}

// ListCommands returns the command buffer, newest first, as lightweight
// summaries (no full output). The Index of each entry matches the index
// accepted by CommandOutput (0 = most recent). count <= 0 returns all.
func (m *Manager) ListCommands(count int) ([]types.CommandSummary, error) {
	if m.history == nil {
		return nil, fmt.Errorf("command history is not enabled (start the server with --allow-input)")
	}
	recs := m.history.Last(count)
	out := make([]types.CommandSummary, 0, len(recs))
	for i, r := range recs {
		out = append(out, types.CommandSummary{
			Index:      i,
			Timestamp:  r.Timestamp.Format("2006-01-02 15:04:05"),
			Command:    r.Command,
			WindowID:   r.WindowID,
			OutputFile: r.OutputFile,
		})
	}
	return out, nil
}

// LoadWindowHistory merges a window's persisted commands from disk into the
// buffer (even if the window was closed and reopened), returning how many were
// added. Write mode only.
func (m *Manager) LoadWindowHistory(windowID string, count int) (int, error) {
	if m.history == nil {
		return 0, fmt.Errorf("command history is not enabled (start the server with --allow-input)")
	}
	if windowID == "" {
		return 0, fmt.Errorf("window is required")
	}
	return m.history.LoadWindow(windowID, count)
}

// Search scans a window's full scrollback for a pattern (regular expression, or
// a literal substring if the pattern is not a valid regex) and returns the
// matching lines with their 1-based line numbers and surrounding context.
func (m *Manager) Search(windowID, pattern string, contextLines int) (*types.SearchResult, error) {
	if pattern == "" {
		return nil, fmt.Errorf("pattern is required")
	}
	if contextLines < 0 {
		contextLines = 0
	}
	capture, err := m.captureWindow(windowID, true)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(pattern))
	}

	lines := strings.Split(capture, "\n")
	var matches []types.SearchMatch
	for i, ln := range lines {
		if !re.MatchString(ln) {
			continue
		}
		start := i - contextLines
		if start < 0 {
			start = 0
		}
		end := i + contextLines + 1
		if end > len(lines) {
			end = len(lines)
		}
		matches = append(matches, types.SearchMatch{
			LineNumber: i + 1,
			Line:       ln,
			Context:    strings.Join(lines[start:end], "\n"),
		})
	}
	return &types.SearchResult{
		WindowID:   windowID,
		Pattern:    pattern,
		Matches:    matches,
		TotalLines: len(lines),
	}, nil
}

// extractCommandOutput returns the output that followed a command in a captured
// hardcopy. It finds the last line whose trailing text is the command (its echo
// at a prompt) and returns the lines after it, dropping a trailing prompt line
// and surrounding blank lines.
func extractCommandOutput(capture, command string) (string, bool) {
	command = strings.TrimRight(command, "\r\n")
	lines := strings.Split(capture, "\n")
	last := -1
	for i, ln := range lines {
		if strings.HasSuffix(strings.TrimRight(ln, " \t"), command) {
			last = i
		}
	}
	if last < 0 {
		return "", false
	}
	out := lines[last+1:]
	out = trimTrailingBlanks(out)
	if len(out) > 0 && looksLikePrompt(out[len(out)-1]) {
		out = trimTrailingBlanks(out[:len(out)-1])
	}
	return strings.Join(out, "\n"), true
}

func trimTrailingBlanks(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// looksLikePrompt is a heuristic for a trailing shell prompt line.
func looksLikePrompt(line string) bool {
	t := strings.TrimRight(line, " \t")
	if t == "" {
		return false
	}
	switch t[len(t)-1] {
	case '$', '#', '%', '>':
		return true
	}
	return false
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}
