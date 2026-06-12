package sulla

import "testing"

func TestParseUNCToTarget(t *testing.T) {
	tests := []struct {
		name      string
		unc       string
		wantHost  string
		wantShare string
		wantPath  string
	}{
		{
			name:      "standard UNC",
			unc:       `\\server\share`,
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:      "with subpath",
			unc:       `\\server\share\subdir\file`,
			wantHost:  "server",
			wantShare: "share",
			wantPath:  `subdir\file`,
		},
		{
			name:     "single component",
			unc:      `\\server`,
			wantHost: "server",
		},
		{
			name: "empty string",
			unc:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseUNCToTarget(tt.unc)
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Share != tt.wantShare {
				t.Errorf("Share = %q, want %q", got.Share, tt.wantShare)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

func TestParseRemoteServerName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantShare string
	}{
		{
			name:      "star prefix",
			input:     `*\server\share`,
			wantHost:  "server",
			wantShare: "share",
		},
		{
			name:      "backslash prefix",
			input:     `\\server\share`,
			wantHost:  "server",
			wantShare: "share",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRemoteServerName(tt.input)
			if got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Share != tt.wantShare {
				t.Errorf("Share = %q, want %q", got.Share, tt.wantShare)
			}
		})
	}
}

func TestExtractNamespaceFromDN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "valid DFS DN",
			dn:   "CN=link1,CN=MyNamespace,CN=Dfs-Configuration,CN=System,DC=corp,DC=local",
			want: "MyNamespace",
		},
		{
			name: "missing Dfs-Configuration",
			dn:   "CN=something,CN=System,DC=corp,DC=local",
			want: "",
		},
		{
			name: "too few parts before Dfs-Configuration",
			dn:   "CN=Dfs-Configuration,CN=System",
			want: "",
		},
		{
			name: "case insensitive Dfs-Configuration",
			dn:   "CN=link1,CN=MyNS,CN=dfs-configuration,CN=System,DC=corp,DC=local",
			want: "MyNS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNamespaceFromDN(tt.dn)
			if got != tt.want {
				t.Errorf("extractNamespaceFromDN(%q) = %q, want %q", tt.dn, got, tt.want)
			}
		})
	}
}

func TestDecodeUTF16LEIfPresent(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "plain ASCII",
			input: []byte("hello"),
			want:  "hello",
		},
		{
			name:  "UTF-16LE encoded",
			input: []byte{'h', 0x00, 'i', 0x00},
			want:  "hi",
		},
		{
			name:  "short input",
			input: []byte("ab"),
			want:  "ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeUTF16LEIfPresent(tt.input)
			if got != tt.want {
				t.Errorf("decodeUTF16LEIfPresent = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseDFSTargetListBytes(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantCount int
		wantFirst DFSTarget
	}{
		{
			name:      "single UNC path in ASCII",
			input:     []byte("prefix\\\\server\\share\x00"),
			wantCount: 1,
			wantFirst: DFSTarget{Host: "server", Share: "share"},
		},
		{
			name:      "empty blob",
			input:     []byte{},
			wantCount: 0,
		},
		{
			name: "UTF-16LE encoded UNC",
			input: func() []byte {
				// Encode \\server\share as UTF-16LE
				s := `\\server\share`
				b := make([]byte, len(s)*2)
				for i, c := range s {
					b[i*2] = byte(c)
					b[i*2+1] = 0x00
				}
				return b
			}(),
			wantCount: 1,
			wantFirst: DFSTarget{Host: "server", Share: "share"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDFSTargetListBytes(tt.input)
			if len(got) != tt.wantCount {
				t.Fatalf("got %d targets, want %d", len(got), tt.wantCount)
			}
			if tt.wantCount > 0 {
				if got[0].Host != tt.wantFirst.Host || got[0].Share != tt.wantFirst.Share {
					t.Errorf("first target = %+v, want %+v", got[0], tt.wantFirst)
				}
			}
		})
	}
}

func TestDeduplicateTargetsWithDFS(t *testing.T) {
	t.Run("removes physical backend, adds namespace", func(t *testing.T) {
		targets := []Target{
			{Host: "fileserver.corp.local", Share: "finance$"},
			{Host: "dc1.corp.local", Share: "apps"},
		}
		dfsLinks := map[string][]DFSLink{
			`fileserver.corp.local\finance$`: {
				{Namespace: "dfs", LinkPath: "finance", DFSPath: `\\corp.local\dfs\finance`},
			},
		}
		got, removed := deduplicateTargetsWithDFS(targets, dfsLinks, "corp.local")
		if removed != 1 {
			t.Errorf("removed = %d, want 1", removed)
		}
		// Should have: dc1/apps (kept) + corp.local/dfs (added)
		if len(got) != 2 {
			t.Fatalf("got %d targets, want 2", len(got))
		}
	})

	t.Run("no DFS links passthrough", func(t *testing.T) {
		targets := []Target{{Host: "server", Share: "share"}}
		got, removed := deduplicateTargetsWithDFS(targets, nil, "corp.local")
		if removed != 0 || len(got) != 1 {
			t.Errorf("expected passthrough, got removed=%d len=%d", removed, len(got))
		}
	})

	t.Run("namespace root not duplicated", func(t *testing.T) {
		targets := []Target{
			{Host: "corp.local", Share: "dfs"},
			{Host: "fileserver.corp.local", Share: "data$"},
		}
		dfsLinks := map[string][]DFSLink{
			`fileserver.corp.local\data$`: {
				{Namespace: "dfs", LinkPath: "data"},
			},
		}
		got, removed := deduplicateTargetsWithDFS(targets, dfsLinks, "corp.local")
		if removed != 1 {
			t.Errorf("removed = %d, want 1", removed)
		}
		// Should NOT add a second corp.local/dfs since it already exists
		dfsCount := 0
		for _, tgt := range got {
			if tgt.Share == "dfs" {
				dfsCount++
			}
		}
		if dfsCount != 1 {
			t.Errorf("expected 1 dfs target, got %d", dfsCount)
		}
	})
}

func TestDeduplicateReplicatedShares(t *testing.T) {
	t.Run("keeps first SYSVOL, removes duplicates", func(t *testing.T) {
		targets := []Target{
			{Host: "dc1.corp.local", Share: "SYSVOL"},
			{Host: "dc2.corp.local", Share: "SYSVOL"},
			{Host: "dc1.corp.local", Share: "NETLOGON"},
			{Host: "dc2.corp.local", Share: "NETLOGON"},
		}
		got, removed := deduplicateReplicatedShares(targets, "corp.local")
		if removed != 2 {
			t.Errorf("removed = %d, want 2", removed)
		}
		if len(got) != 2 {
			t.Errorf("got %d targets, want 2", len(got))
		}
	})

	t.Run("non-replicated shares preserved", func(t *testing.T) {
		targets := []Target{
			{Host: "fs1", Share: "data"},
			{Host: "fs2", Share: "apps"},
		}
		got, removed := deduplicateReplicatedShares(targets, "corp.local")
		if removed != 0 || len(got) != 2 {
			t.Errorf("non-replicated should be preserved: removed=%d len=%d", removed, len(got))
		}
	})

	t.Run("mixed targets", func(t *testing.T) {
		targets := []Target{
			{Host: "dc1", Share: "SYSVOL"},
			{Host: "fs1", Share: "data"},
			{Host: "dc2", Share: "SYSVOL"},
		}
		got, removed := deduplicateReplicatedShares(targets, "corp.local")
		if removed != 1 {
			t.Errorf("removed = %d, want 1", removed)
		}
		if len(got) != 2 {
			t.Errorf("got %d targets, want 2", len(got))
		}
	})
}
