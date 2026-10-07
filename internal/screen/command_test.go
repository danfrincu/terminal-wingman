package screen

import "testing"

func TestExtractCommandOutput(t *testing.T) {
	tests := []struct {
		name    string
		capture string
		command string
		want    string
		found   bool
	}{
		{
			name:    "simple with trailing prompt",
			capture: "user@host ~ $ ls -la\ntotal 8\nfile1\nfile2\nuser@host ~ $ ",
			command: "ls -la",
			want:    "total 8\nfile1\nfile2",
			found:   true,
		},
		{
			name:    "still running, no trailing prompt yet",
			capture: "user@host ~ $ long-build\nstep 1\nstep 2",
			command: "long-build",
			want:    "step 1\nstep 2",
			found:   true,
		},
		{
			name:    "uses the last echo of the command",
			capture: "user@host ~ $ make\nold output\nuser@host ~ $ make\ncompiling\ndone\nuser@host ~ $ ",
			command: "make",
			want:    "compiling\ndone",
			found:   true,
		},
		{
			name:    "command not present",
			capture: "user@host ~ $ whoami\nroot\nuser@host ~ $ ",
			command: "ls -la",
			want:    "",
			found:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractCommandOutput(tt.capture, tt.command)
			if ok != tt.found || got != tt.want {
				t.Errorf("extractCommandOutput()\n got: (%q, %v)\nwant: (%q, %v)", got, ok, tt.want, tt.found)
			}
		})
	}
}

func TestLooksLikePrompt(t *testing.T) {
	yes := []string{"user@host ~ $", "root@host ~ #", "~ %", "foo>"}
	no := []string{"total 8", "", "compiling done"}
	for _, s := range yes {
		if !looksLikePrompt(s) {
			t.Errorf("looksLikePrompt(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikePrompt(s) {
			t.Errorf("looksLikePrompt(%q) = true, want false", s)
		}
	}
}

func TestCountLines(t *testing.T) {
	for in, want := range map[string]int{"": 0, "a": 1, "a\nb": 2, "a\nb\n": 2} {
		if got := countLines(in); got != want {
			t.Errorf("countLines(%q) = %d, want %d", in, got, want)
		}
	}
}
