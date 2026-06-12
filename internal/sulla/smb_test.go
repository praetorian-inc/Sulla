package sulla

import (
	"fmt"
	"testing"
)

func TestCompileExcludedShares(t *testing.T) {
	t.Run("valid regex", func(t *testing.T) {
		patterns := []string{`^IPC\$$`, `^ADMIN\$$`}
		compiled := compileExcludedShares(patterns)
		if len(compiled) != 2 {
			t.Fatalf("got %d patterns, want 2", len(compiled))
		}
		if !compiled[0].MatchString("IPC$") {
			t.Error("expected IPC$ to match")
		}
	})

	t.Run("invalid regex falls back to literal", func(t *testing.T) {
		patterns := []string{"[invalid"}
		compiled := compileExcludedShares(patterns)
		if len(compiled) != 1 {
			t.Fatalf("got %d patterns, want 1", len(compiled))
		}
		if !compiled[0].MatchString("[invalid") {
			t.Error("expected literal match for invalid regex")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		patterns := []string{`^admin\$$`}
		compiled := compileExcludedShares(patterns)
		if !compiled[0].MatchString("ADMIN$") {
			t.Error("expected case-insensitive match")
		}
	})
}

func TestIsSigningError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"signing required", fmt.Errorf("server: signing required"), true},
		{"doesn't support signing", fmt.Errorf("host doesn't support signing"), true},
		{"unrelated error", fmt.Errorf("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSigningError(tt.err)
			if got != tt.want {
				t.Errorf("isSigningError = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsShareExcluded(t *testing.T) {
	compiled := compileExcludedShares([]string{`^IPC\$$`, `^ADMIN\$$`})

	tests := []struct {
		share string
		want  bool
	}{
		{"IPC$", true},
		{"ADMIN$", true},
		{"data", false},
	}

	for _, tt := range tests {
		t.Run(tt.share, func(t *testing.T) {
			got := isShareExcluded(tt.share, compiled)
			if got != tt.want {
				t.Errorf("isShareExcluded(%q) = %v, want %v", tt.share, got, tt.want)
			}
		})
	}
}
