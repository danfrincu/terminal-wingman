package screen

import (
	"reflect"
	"strings"
	"testing"

	"terminal-wingman/pkg/types"
)

func TestParseWindowsList(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   []types.WindowInfo
	}{
		{
			// `screen -Q windows` where every window carries a flag char (here the
			// '$' login flag): window 0 exists and has a multi-word title, window 2
			// is current ('*'), window 1 is previous ('-').
			name:   "flags and multi-word title",
			output: "0$ vim notes  1-$ bash  2*$ top  3$ 3  4$ 4  9$ 9",
			want: []types.WindowInfo{
				{ID: "0", Name: "vim notes", Active: false},
				{ID: "1", Name: "bash", Active: false},
				{ID: "2", Name: "top", Active: true},
				{ID: "3", Name: "3", Active: false},
				{ID: "4", Name: "4", Active: false},
				{ID: "9", Name: "9", Active: false},
			},
		},
		{
			// The simple format with no extra flags still works.
			name:   "simple format",
			output: "0 term  1 build  2* todo  3- git",
			want: []types.WindowInfo{
				{ID: "0", Name: "term", Active: false},
				{ID: "1", Name: "build", Active: false},
				{ID: "2", Name: "todo", Active: true},
				{ID: "3", Name: "git", Active: false},
			},
		},
		{
			// A '$' inside a title must not be mistaken for a flag.
			name:   "dollar sign in title",
			output: "0$ echo $HOME  1$ 1",
			want: []types.WindowInfo{
				{ID: "0", Name: "echo $HOME", Active: false},
				{ID: "1", Name: "1", Active: false},
			},
		},
		{
			name:   "multi-digit window numbers",
			output: "9$ 9  10*$ editor  11$ 11",
			want: []types.WindowInfo{
				{ID: "9", Name: "9", Active: false},
				{ID: "10", Name: "editor", Active: true},
				{ID: "11", Name: "11", Active: false},
			},
		},
		{
			name:   "empty output",
			output: "",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseWindowsList(tt.output)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseWindowsList(%q)\n got: %#v\nwant: %#v", tt.output, got, tt.want)
			}
		})
	}
}

func TestBuildStuffPayload(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		enter bool
		want  string
	}{
		{"with enter", "ls -la", true, "ls -la\r"},
		{"without enter", "ls -la", false, "ls -la"},
		{"empty with enter sends bare CR", "", true, "\r"},
		{"preserves dollar and spaces", "echo $HOME  x", false, "echo $HOME  x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildStuffPayload(tt.text, tt.enter); got != tt.want {
				t.Errorf("buildStuffPayload(%q, %v) = %q, want %q", tt.text, tt.enter, got, tt.want)
			}
		})
	}
}

func TestStripWhitespaceVerification(t *testing.T) {
	// A long command SendKeys wants to confirm landed on the window.
	cmd := "deploy --target staging --retries 3 --timeout 60 --verbose"
	want := stripWhitespace(cmd)

	tests := []struct {
		name    string
		capture string // simulated hardcopy of the window
		ok      bool
	}{
		{
			name:    "clean single line echo",
			capture: "user@hostname ~ $ " + cmd,
			ok:      true,
		},
		{
			name: "wrapped across lines with trailing padding",
			// screen wraps a long line and may pad the last line with spaces.
			capture: "user@hostname ~ $ deploy --target staging --retries 3 --timeout 6\n" +
				"0 --verbose        ",
			ok: true,
		},
		{
			name: "space lost at the wrap boundary still matches",
			// if the wrap falls on a space, trimming can drop it; whitespace-
			// insensitive comparison tolerates that.
			capture: "user@hostname ~ $ deploy --target staging --retries 3\n" +
				"--timeout 60 --verbose",
			ok: true,
		},
		{
			name:    "dropped leading bytes do NOT match",
			capture: "user@hostname ~ $ ploy --target staging --retries 3 --timeout 60 --verbose",
			ok:      false,
		},
		{
			name:    "earlier occurrence in scrollback is ignored (suffix only)",
			capture: cmd + "\nsome output\nuser@hostname ~ $ ploy --target staging",
			ok:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.HasSuffix(stripWhitespace(tt.capture), want)
			if got != tt.ok {
				t.Errorf("suffix match = %v, want %v\n capture=%q", got, tt.ok, tt.capture)
			}
		})
	}
}
