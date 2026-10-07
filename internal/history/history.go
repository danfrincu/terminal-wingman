// Package history records each command sent in write mode to its own pair of
// timestamped files under ~/.terminal-wingman, and keeps the most recent
// commands in an in-memory ring so their captured output can be resurfaced
// without re-reading the screen. Filenames embed the window the command ran in
// (".<user>-<timestamp>-window_id_<n>.cmds"), so history can be re-seeded per
// window after a restart.
package history

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// BufferSize is how many recent commands are kept in memory.
	BufferSize = 50
	// tsLayout is the timestamp used in the per-command filenames.
	tsLayout = "2006-01-02_15-04-05"
	// windowMarker separates the timestamp from the window id in filenames.
	windowMarker = "-window_id_"
)

// Record is one executed command and the files that hold it and its output.
type Record struct {
	Command    string    `json:"command"`
	Timestamp  time.Time `json:"timestamp"`
	WindowID   string    `json:"window_id"`
	Base       string    `json:"-"`
	CmdsFile   string    `json:"cmds_file"`
	OutputFile string    `json:"output_file"`
}

// History writes per-command files to dir and keeps the newest BufferSize
// records in memory (oldest pushed out as new ones arrive).
type History struct {
	mu   sync.Mutex
	dir  string
	user string
	buf  []Record
}

// currentUser returns the username the server runs as, used in filenames.
func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if n := os.Getenv("USER"); n != "" {
		return n
	}
	return "unknown"
}

// DefaultDir returns ~/.terminal-wingman.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".terminal-wingman"), nil
}

// New creates (if needed) the history directory and seeds the in-memory ring
// from the newest command files already on disk. When windowLive is non-nil,
// only commands whose window still exists (windowLive returns true) are
// auto-seeded; the rest stay on disk and can be pulled in later with LoadWindow.
func New(dir string, windowLive func(windowID string) bool) (*History, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create history dir %q: %w", dir, err)
	}
	h := &History{dir: dir, user: currentUser()}
	h.loadFromDisk(windowLive)
	return h, nil
}

type nameRec struct {
	t      time.Time
	window string
	base   string
}

// scanNames lists this user's command files on disk (newest last), parsing the
// timestamp and window from each name without reading file contents.
func (h *History) scanNames() []nameRec {
	prefix := "." + h.user + "-"
	paths, _ := filepath.Glob(filepath.Join(h.dir, prefix+"*.cmds"))
	var out []nameRec
	for _, p := range paths {
		base := strings.TrimSuffix(filepath.Base(p), ".cmds")
		t, w, err := parseRecordName(strings.TrimPrefix(base, prefix))
		if err != nil {
			continue
		}
		out = append(out, nameRec{t: t, window: w, base: base})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].t.Before(out[j].t) })
	return out
}

func (h *History) recordFromName(nr nameRec) Record {
	cmds := filepath.Join(h.dir, nr.base+".cmds")
	return Record{
		Command:    readFirstLine(cmds),
		Timestamp:  nr.t,
		WindowID:   nr.window,
		Base:       nr.base,
		CmdsFile:   cmds,
		OutputFile: filepath.Join(h.dir, nr.base+".cmds.output"),
	}
}

func (h *History) loadFromDisk(windowLive func(string) bool) {
	names := h.scanNames()
	var keep []nameRec
	for _, nr := range names {
		if windowLive == nil || windowLive(nr.window) {
			keep = append(keep, nr)
		}
	}
	if len(keep) > BufferSize {
		keep = keep[len(keep)-BufferSize:]
	}
	for _, nr := range keep {
		h.buf = append(h.buf, h.recordFromName(nr))
	}
}

// RecordCommand writes the command to its .cmds file and adds it to the ring.
func (h *History) RecordCommand(command, windowID string, ts time.Time) (Record, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	base := fmt.Sprintf(".%s-%s%s%s", h.user, ts.Format(tsLayout), windowMarker, windowID)
	b := base
	for n := 2; ; n++ {
		if _, err := os.Stat(filepath.Join(h.dir, b+".cmds")); os.IsNotExist(err) {
			break
		}
		b = fmt.Sprintf("%s_%d", base, n)
	}

	rec := Record{
		Command:    command,
		Timestamp:  ts,
		WindowID:   windowID,
		Base:       b,
		CmdsFile:   filepath.Join(h.dir, b+".cmds"),
		OutputFile: filepath.Join(h.dir, b+".cmds.output"),
	}
	if err := os.WriteFile(rec.CmdsFile, []byte(command+"\n"), 0o644); err != nil {
		return Record{}, err
	}
	h.buf = append(h.buf, rec)
	if len(h.buf) > BufferSize {
		h.buf = h.buf[len(h.buf)-BufferSize:]
	}
	return rec, nil
}

// WriteOutput writes (or overwrites) a command's captured output file.
func (h *History) WriteOutput(rec Record, output string) error {
	return os.WriteFile(rec.OutputFile, []byte(output), 0o644)
}

// Get returns the record at index, where 0 is the most recent command.
func (h *History) Get(index int) (Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if index < 0 || index >= len(h.buf) {
		return Record{}, false
	}
	return h.buf[len(h.buf)-1-index], true
}

// Last returns up to n of the most recent records, newest first.
func (h *History) Last(n int) []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n <= 0 || n > len(h.buf) {
		n = len(h.buf)
	}
	out := make([]Record, 0, n)
	for i := len(h.buf) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, h.buf[i])
	}
	return out
}

// LoadWindow merges up to count of a window's persisted commands from disk into
// the buffer (regardless of whether the window is still open), so a user can
// resume where they left off in a reopened window. Returns how many were added.
func (h *History) LoadWindow(windowID string, count int) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sel []nameRec
	for _, nr := range h.scanNames() {
		if nr.window == windowID {
			sel = append(sel, nr)
		}
	}
	if count > 0 && len(sel) > count {
		sel = sel[len(sel)-count:]
	}

	existing := make(map[string]bool, len(h.buf))
	for _, r := range h.buf {
		existing[r.Base] = true
	}
	added := 0
	for _, nr := range sel {
		if existing[nr.base] {
			continue
		}
		h.buf = append(h.buf, h.recordFromName(nr))
		added++
	}
	sort.Slice(h.buf, func(i, j int) bool { return h.buf[i].Timestamp.Before(h.buf[j].Timestamp) })
	if len(h.buf) > BufferSize {
		h.buf = h.buf[len(h.buf)-BufferSize:]
	}
	return added, nil
}

// ReadOutput reads a record's stored output file ("" if not written yet).
func ReadOutput(rec Record) (string, error) {
	b, err := os.ReadFile(rec.OutputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

// parseRecordName parses a command file's name (minus the ".<user>-" prefix and
// ".cmds" suffix) into its timestamp and window id. It tolerates a "_N"
// collision suffix and older names that lack the window marker.
func parseRecordName(s string) (time.Time, string, error) {
	if len(s) < len(tsLayout) {
		return time.Time{}, "", fmt.Errorf("name %q too short", s)
	}
	t, err := time.ParseInLocation(tsLayout, s[:len(tsLayout)], time.Local)
	if err != nil {
		return time.Time{}, "", err
	}
	window := ""
	if rest := s[len(tsLayout):]; strings.HasPrefix(rest, windowMarker) {
		window = strings.SplitN(strings.TrimPrefix(rest, windowMarker), "_", 2)[0]
	}
	return t, window, nil
}

func readFirstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if sc.Scan() {
		return sc.Text()
	}
	return ""
}
