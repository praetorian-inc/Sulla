package sulla

import (
	"testing"
	"time"
)

func TestFormatCount64(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1000000, "1,000,000"},
		{123456789, "123,456,789"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatCount64(tt.input)
			if got != tt.want {
				t.Errorf("formatCount64(%d) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatCount(t *testing.T) {
	if got := formatCount(1234); got != "1,234" {
		t.Errorf("formatCount(1234) = %q, want %q", got, "1,234")
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  string
	}{
		{"zero", 0, "0s"},
		{"sub-minute", 12 * time.Second, "12s"},
		{"exact minute", 60 * time.Second, "1m"},
		{"mixed", 2*time.Minute + 34*time.Second, "2m34s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.input)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactProofContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single line match",
			input: "  [rule1] Rule: Test\n  Match:   AKIA1234567890\n\nFile: next.txt",
			want:  "  [rule1] Rule: Test\n  Match:   [REDACTED]\n\nFile: next.txt",
		},
		{
			name:  "multi-line match (PEM key)",
			input: "  Match:   -----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n\nFile: next.txt",
			want:  "  Match:   [REDACTED]\n\nFile: next.txt",
		},
		{
			name:  "no matches unchanged",
			input: "File: test.txt\n  [rule1] Rule: Test\n  Location: line 5",
			want:  "File: test.txt\n  [rule1] Rule: Test\n  Location: line 5",
		},
		{
			name:  "boundary at === separator",
			input: "  Match:   secret123\n===\nNext section",
			want:  "  Match:   [REDACTED]\n===\nNext section",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactProofContent(tt.input)
			if got != tt.want {
				t.Errorf("redactProofContent mismatch:\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		input Severity
		want  string
	}{
		{SeverityCritical, "Critical"},
		{SeverityHigh, "High"},
		{SeverityMedium, "Medium"},
		{SeverityLow, "Low"},
		{Severity(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRuleSeverity(t *testing.T) {
	tests := []struct {
		ruleID string
		want   Severity
	}{
		{"np.pem.1", SeverityCritical},
		{"np.huggingface.1", SeverityLow},
		{"np.unknown.999", SeverityMedium}, // unknown defaults to Medium
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			got := ruleSeverity(tt.ruleID)
			if got != tt.want {
				t.Errorf("ruleSeverity(%q) = %v, want %v", tt.ruleID, got, tt.want)
			}
		})
	}
}

func TestResolveOutputFormats(t *testing.T) {
	tests := []struct {
		name      string
		requested []string
		want      []string
	}{
		{
			name:      "empty falls back to txt",
			requested: nil,
			want:      []string{"txt"},
		},
		{
			name:      "txt only",
			requested: []string{"txt"},
			want:      []string{"txt"},
		},
		{
			name:      "sarif only",
			requested: []string{"sarif"},
			want:      []string{"sarif"},
		},
		{
			name:      "capability-sdk alone expands to txt",
			requested: []string{"capability-sdk"},
			want:      []string{"txt"},
		},
		// Regression: capability-sdk proof blob is built from the .txt file.
		// If capability-sdk is paired with a non-txt format, txt must still be
		// written so the aggregator in generateCapabilitySDKOutput has content
		// to redact and embed.
		{
			name:      "sarif+capability-sdk forces txt",
			requested: []string{"sarif", "capability-sdk"},
			want:      []string{"txt", "sarif"},
		},
		{
			name:      "jsonl+capability-sdk forces txt",
			requested: []string{"jsonl", "capability-sdk"},
			want:      []string{"txt", "jsonl"},
		},
		{
			name:      "txt+sarif+capability-sdk keeps order, no duplicate txt",
			requested: []string{"txt", "sarif", "capability-sdk"},
			want:      []string{"txt", "sarif"},
		},
		{
			name:      "json+capability-sdk forces txt prepend",
			requested: []string{"json", "capability-sdk"},
			want:      []string{"txt", "json"},
		},
		{
			name:      "capability-sdk strips out without duplicating when txt present",
			requested: []string{"capability-sdk", "txt"},
			want:      []string{"txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveOutputFormats(tt.requested)
			if len(got) != len(tt.want) {
				t.Fatalf("resolveOutputFormats(%v) = %v, want %v", tt.requested, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("resolveOutputFormats(%v) = %v, want %v", tt.requested, got, tt.want)
				}
			}
		})
	}
}

func TestGetOutputFilePath(t *testing.T) {
	tests := []struct {
		basePath string
		format   string
		want     string
	}{
		{"output/scan.txt", "json", "output/scan.json"},
		{"output/scan.txt", "jsonl", "output/scan.jsonl"},
		{"output/scan.txt", "sarif", "output/scan.sarif"},
		{"output/scan.txt", "txt", "output/scan.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := getOutputFilePath(tt.basePath, tt.format)
			if got != tt.want {
				t.Errorf("getOutputFilePath(%q, %q) = %q, want %q", tt.basePath, tt.format, got, tt.want)
			}
		})
	}
}
