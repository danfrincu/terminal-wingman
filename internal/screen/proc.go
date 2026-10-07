package screen

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// windowShellPID finds the shell process backing a window by scanning /proc for
// a process whose environment has STY matching this session and WINDOW matching
// windowID. GNU screen sets both variables in every window's shell.
func (m *Manager) windowShellPID(windowID string) (int, error) {
	paths, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range paths {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		env, err := os.ReadFile(filepath.Join(p, "environ"))
		if err != nil {
			continue
		}
		var sty, win string
		for _, kv := range bytes.Split(env, []byte{0}) {
			s := string(kv)
			switch {
			case strings.HasPrefix(s, "STY="):
				sty = s[4:]
			case strings.HasPrefix(s, "WINDOW="):
				win = s[7:]
			}
		}
		if win == windowID && (sty == m.sessionName || strings.HasSuffix(sty, "."+m.sessionName)) {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("could not find shell pid for window %q in session %q", windowID, m.sessionName)
}

// WindowLive reports whether a window currently exists in this session, reusing
// the same shell-pid resolution used for command completion.
func (m *Manager) WindowLive(windowID string) bool {
	if windowID == "" {
		return false
	}
	_, err := m.windowShellPID(windowID)
	return err == nil
}

// atPrompt reports whether a window's shell has no foreground command running,
// i.e. the controlling terminal's foreground process group (tpgid) equals the
// shell's own process group (pgrp). It reads /proc/<pid>/stat.
func atPrompt(pid int) (bool, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false, err
	}
	// comm (field 2) is parenthesized and may contain spaces or parens, so parse
	// the numeric fields after the final ')'. After it: state(3) ppid(4) pgrp(5)
	// session(6) tty_nr(7) tpgid(8) ...
	s := string(data)
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 {
		return false, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	fields := strings.Fields(s[rp+1:])
	if len(fields) < 6 {
		return false, fmt.Errorf("short /proc/%d/stat", pid)
	}
	pgrp, tpgid := fields[2], fields[5]
	return pgrp == tpgid, nil
}

// waitForPrompt waits until the window's shell returns to its prompt (its
// foreground command has finished), up to timeout. It first allows a short
// grace period for a command to take the foreground, so that an instant builtin
// (which never forks) is reported as done rather than hanging. Returns true if
// the shell reached the prompt, false on timeout.
func (m *Manager) waitForPrompt(shellPID int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	graceUntil := time.Now().Add(300 * time.Millisecond)
	started := false
	for time.Now().Before(deadline) {
		prompt, err := atPrompt(shellPID)
		if err != nil {
			return false
		}
		if !prompt {
			started = true
		} else if started || time.Now().After(graceUntil) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
