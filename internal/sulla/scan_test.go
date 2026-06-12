package sulla

import (
	"regexp"
	"testing"
)

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name   string
		header []byte
		want   bool
	}{
		{"empty input", []byte{}, false},
		{"plain text", []byte("Hello, world! This is text."), false},
		{"ELF header", []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, true},
		{"ZIP/PK header", []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}, true},
		{"PE/MZ header", []byte{'M', 'Z', 0x90, 0x00, 0, 0, 0, 0}, true},
		{"gzip header", []byte{0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0}, true},
		{"PDF header (not binary)", []byte{'%', 'P', 'D', 'F', '-', '1', '.', '4'}, false},
		{"high null ratio", append(make([]byte, 20), []byte("abc")...), true},
		{
			name: "borderline null ratio (exactly 10%)",
			// 10 bytes, 1 null = exactly 10% → nulls(1) > len(10)/10(1) is false
			header: []byte{0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinary(tt.header)
			if got != tt.want {
				t.Errorf("isBinary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsExtractable(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".docx", true},
		{".pdf", true},
		{".tar.gz", true},
		{".txt", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			got := isExtractable(tt.ext)
			if got != tt.want {
				t.Errorf("isExtractable(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestGetExtension(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"archive.tar.gz", ".tar.gz"},
		{"document.txt", ".txt"},
		{"noext", ""},
		{"multi.dots.conf", ".conf"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := getExtension(tt.path)
			if got != tt.want {
				t.Errorf("getExtension(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestShouldExcludeExt(t *testing.T) {
	excluded := map[string]bool{"exe": true, "dll": true, "tar.gz": true}

	tests := []struct {
		path string
		want bool
	}{
		{"program.exe", true},
		{"script.py", false},
		{"archive.tar.gz", true},
		{"FILE.EXE", true}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := shouldExcludeExt(tt.path, excluded)
			if got != tt.want {
				t.Errorf("shouldExcludeExt(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestShouldExcludeDir(t *testing.T) {
	excl := dirExclusions{
		exact:    map[string]bool{"node_modules": true, ".git": true},
		patterns: []*regexp.Regexp{regexp.MustCompile(`^\.svn$`)},
	}

	tests := []struct {
		name string
		want bool
	}{
		{"node_modules", true},
		{".svn", true},
		{"src", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldExcludeDir(tt.name, excl)
			if got != tt.want {
				t.Errorf("shouldExcludeDir(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestBuildExcludedExtensions(t *testing.T) {
	t.Run("default exclusions present", func(t *testing.T) {
		config := Config{}
		exts := buildExcludedExtensions(config)
		if !exts["exe"] {
			t.Error("expected 'exe' in default exclusions")
		}
		if !exts["dll"] {
			t.Error("expected 'dll' in default exclusions")
		}
	})

	t.Run("NoExclusion empties set", func(t *testing.T) {
		config := Config{NoExclusion: true}
		exts := buildExcludedExtensions(config)
		if exts["exe"] {
			t.Error("NoExclusion should remove default exclusions")
		}
	})

	t.Run("ExtractBinary removes extractable types", func(t *testing.T) {
		config := Config{ExtractBinary: true}
		exts := buildExcludedExtensions(config)
		if exts["pdf"] {
			t.Error("ExtractBinary should remove 'pdf' from exclusions")
		}
		if exts["docx"] {
			t.Error("ExtractBinary should remove 'docx' from exclusions")
		}
		// Non-extractable types should remain
		if !exts["exe"] {
			t.Error("'exe' should still be excluded with ExtractBinary")
		}
	})
}

func TestIsLiteralString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"node_modules", true},
		{"simple", true},
		{".*", false},
		{"[a-z]+", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isLiteralString(tt.input)
			if got != tt.want {
				t.Errorf("isLiteralString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildExcludedDirectories(t *testing.T) {
	config := Config{
		AdditionalFolders: []string{"custom_dir", `^temp\d+$`},
	}
	excl := buildExcludedDirectories(config)

	// Default literal folders should be in exact map
	if !excl.exact["node_modules"] {
		t.Error("expected 'node_modules' in exact exclusions")
	}

	// Custom literal folder
	if !excl.exact["custom_dir"] {
		t.Error("expected 'custom_dir' in exact exclusions")
	}

	// Regex pattern should be in patterns slice
	if len(excl.patterns) == 0 {
		t.Fatal("expected at least 1 regex pattern")
	}
	if !excl.patterns[len(excl.patterns)-1].MatchString("temp123") {
		t.Error("expected regex to match 'temp123'")
	}
}

func TestToUNCPathSMB(t *testing.T) {
	tests := []struct {
		name    string
		smbPath string
		config  Config
		want    string
	}{
		{
			name:    "normal path",
			smbPath: "dir/subdir/file.txt",
			config:  Config{Host: "server", Share: "share"},
			want:    `\\server\share\dir\subdir\file.txt`,
		},
		{
			name:    "DFSPath set",
			smbPath: "dir/file.txt",
			config:  Config{Host: "server", Share: "share", DFSPath: `\\corp.local\dfs`},
			want:    `\\corp.local\dfs\dir\file.txt`,
		},
		{
			name:    "strips leading dot-slash",
			smbPath: `.\file.txt`,
			config:  Config{Host: "server", Share: "share"},
			want:    `\\server\share\file.txt`,
		},
		{
			name:    "strips leading backslash",
			smbPath: `\dir\file.txt`,
			config:  Config{Host: "server", Share: "share"},
			want:    `\\server\share\dir\file.txt`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toUNCPathSMB(tt.smbPath, tt.config)
			if got != tt.want {
				t.Errorf("toUNCPathSMB(%q) = %q, want %q", tt.smbPath, got, tt.want)
			}
		})
	}
}
