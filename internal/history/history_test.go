package history

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRecordCommandFilesAndBuffer(t *testing.T) {
	dir := t.TempDir()
	h, err := New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 10, 6, 21, 15, 3, 0, time.Local)
	rec, err := h.RecordCommand("ls -la", "3", ts)
	if err != nil {
		t.Fatal(err)
	}

	wantName := "." + h.user + "-2026-10-06_21-15-03-window_id_3.cmds"
	if got := filepath.Base(rec.CmdsFile); got != wantName {
		t.Errorf("cmds filename = %q, want %q", got, wantName)
	}
	if b, _ := os.ReadFile(rec.CmdsFile); strings.TrimSpace(string(b)) != "ls -la" {
		t.Errorf("cmds content = %q, want %q", string(b), "ls -la")
	}

	if err := h.WriteOutput(rec, "total 0\nfile1\n"); err != nil {
		t.Fatal(err)
	}
	out, err := ReadOutput(rec)
	if err != nil {
		t.Fatal(err)
	}
	if out != "total 0\nfile1\n" {
		t.Errorf("output = %q", out)
	}

	g, ok := h.Get(0)
	if !ok || g.Command != "ls -la" {
		t.Errorf("Get(0) = %+v ok=%v, want command ls -la", g, ok)
	}
}

func TestBufferRingAndCollision(t *testing.T) {
	dir := t.TempDir()
	h, _ := New(dir, nil)
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.Local)
	total := BufferSize + 5
	for i := 0; i < total; i++ {
		// three commands share each second, exercising the collision suffix.
		ts := start.Add(time.Duration(i/3) * time.Second)
		if _, err := h.RecordCommand("cmd"+strconv.Itoa(i), "0", ts); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(h.Last(1000)); got != BufferSize {
		t.Errorf("buffer size = %d, want %d", got, BufferSize)
	}
	g, _ := h.Get(0)
	if want := "cmd" + strconv.Itoa(total-1); g.Command != want {
		t.Errorf("newest = %q, want %q", g.Command, want)
	}
}

func TestLoadFromDiskSeedsNewest50(t *testing.T) {
	dir := t.TempDir()
	h, _ := New(dir, nil)
	start := time.Date(2026, 10, 6, 8, 0, 0, 0, time.Local)
	for i := 0; i < 60; i++ {
		ts := start.Add(time.Duration(i) * time.Second)
		rec, _ := h.RecordCommand("c"+strconv.Itoa(i), "0", ts)
		_ = h.WriteOutput(rec, "out"+strconv.Itoa(i))
	}

	// A fresh History over the same dir should seed the newest 50 from disk.
	h2, err := New(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	last := h2.Last(1000)
	if len(last) != BufferSize {
		t.Fatalf("seeded %d, want %d", len(last), BufferSize)
	}
	if last[0].Command != "c59" {
		t.Errorf("seeded newest = %q, want c59", last[0].Command)
	}
	if last[len(last)-1].Command != "c10" {
		t.Errorf("seeded oldest = %q, want c10 (newest 50 of 60)", last[len(last)-1].Command)
	}
	g, ok := h2.Get(0)
	if !ok {
		t.Fatal("Get(0) after reload failed")
	}
	if out, _ := ReadOutput(g); out != "out59" {
		t.Errorf("resurfaced output = %q, want out59", out)
	}
}

func TestParseRecordName(t *testing.T) {
	cases := []struct {
		in     string
		window string
		ok     bool
	}{
		{"2026-10-06_21-15-03-window_id_0", "0", true},
		{"2026-10-06_21-15-03-window_id_10", "10", true},
		{"2026-10-06_21-15-03-window_id_0_2", "0", true}, // collision suffix
		{"2026-10-06_21-15-03", "", true},                // old format, no window
		{"not-a-timestamp", "", false},
	}
	for _, c := range cases {
		_, w, err := parseRecordName(c.in)
		if (err == nil) != c.ok {
			t.Errorf("parseRecordName(%q) ok=%v, want %v (err=%v)", c.in, err == nil, c.ok, err)
			continue
		}
		if err == nil && w != c.window {
			t.Errorf("parseRecordName(%q) window=%q, want %q", c.in, w, c.window)
		}
	}
}

func TestSeedFilterAndLoadWindow(t *testing.T) {
	dir := t.TempDir()
	seed, _ := New(dir, nil)
	base := time.Date(2026, 10, 7, 9, 0, 0, 0, time.Local)
	for i := 0; i < 4; i++ {
		win := "0"
		if i%2 == 1 {
			win = "1"
		}
		if _, err := seed.RecordCommand("cmd"+strconv.Itoa(i), win, base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	// A restart that considers no window live seeds nothing.
	dead, _ := New(dir, func(string) bool { return false })
	if n := len(dead.Last(100)); n != 0 {
		t.Errorf("dead-session seed = %d, want 0", n)
	}

	// Restart where only window 0 is live seeds just window 0's commands.
	liveZero, _ := New(dir, func(w string) bool { return w == "0" })
	got := liveZero.Last(100)
	if len(got) != 2 {
		t.Fatalf("window-0 seed = %d, want 2", len(got))
	}
	for _, r := range got {
		if r.WindowID != "0" {
			t.Errorf("seeded a non-window-0 record: %+v", r)
		}
	}

	// LoadWindow pulls a closed window's history on demand.
	added, err := dead.LoadWindow("1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Errorf("LoadWindow added %d, want 2", added)
	}
	for _, r := range dead.Last(100) {
		if r.WindowID != "1" {
			t.Errorf("LoadWindow pulled a non-window-1 record: %+v", r)
		}
	}
}
