package sulla

import "testing"

func TestParseTargetLine(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantShare string
		wantErr   bool
	}{
		{
			name:      "UNC path",
			input:     `\\server\share`,
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:      "UNC path with escaped backslashes",
			input:     `\\\\server\\share`,
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:      "CSV format",
			input:     "server,share",
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:      "CSV with whitespace",
			input:     "  server , share  ",
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:    "empty host in CSV",
			input:   ",share",
			wantErr: true,
		},
		{
			name:    "garbage input",
			input:   "justahostname",
			wantErr: true,
		},
		{
			name:      "UNC path with subpath",
			input:     `\\server\share\subdir\file`,
			wantHost:  "server",
			wantShare: `share\subdir\file`,
		},
		{
			name:    "UNC path missing share",
			input:   `\\server`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, share, err := parseTargetLine(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got host=%q share=%q", host, share)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if share != tt.wantShare {
				t.Errorf("share = %q, want %q", share, tt.wantShare)
			}
		})
	}
}

func TestIsQuickModeTarget(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "exact filename match", path: "/data/id_rsa", want: true},
		{name: "contains match", path: "/ci/docker-compose.yml", want: true},
		{name: "extension match .pem", path: "/certs/server.pem", want: true},
		{name: "extension match .env", path: "/app/.env", want: true},
		{name: "non-matching file", path: "/images/photo.jpg", want: false},
		{name: "contains .env in filename", path: "/config/.env.production", want: true},
		{name: "exact .htpasswd match", path: "/web/.htpasswd", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isQuickModeTarget(tt.path)
			if got != tt.want {
				t.Errorf("isQuickModeTarget(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"corp.local", "corp_local"},
		{"host:share", "host_share"},
		{"path/to\\file", "path_to_file"},
		{"already_clean", "already_clean"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestTargetTag(t *testing.T) {
	config := Config{Host: "server.corp.local", Share: "data$"}
	got := targetTag(config)
	want := "[server.corp.local/data$]"
	if got != want {
		t.Errorf("targetTag = %q, want %q", got, want)
	}
}
