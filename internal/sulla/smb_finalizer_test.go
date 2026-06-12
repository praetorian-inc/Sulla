package sulla

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestGoSMB2ForkPresent is a build-time guard that fails if the in-tree
// fork of github.com/hirochachacha/go-smb2 is missing. The fork patches
// a finalizer-driven panic that crashed sulla during AD-wide share
// discovery (see third_party/go-smb2/NOTICE.md). If the fork is deleted
// or the `replace` directive in go.mod is removed, scans regress to a
// process-killing panic that no application-level recover() can catch.
// Fail here so CI catches it rather than a customer.
func TestGoSMB2ForkPresent(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	notice := filepath.Join(repoRoot, "third_party", "go-smb2", "NOTICE.md")

	data, err := os.ReadFile(notice)
	if err != nil {
		t.Fatalf("missing third_party/go-smb2/NOTICE.md — fork not vendored: %v", err)
	}
	for _, want := range []string{
		"Modifications to github.com/hirochachacha/go-smb2",
		"PacketCodec",
		"session.go",
		"conn.go",
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("NOTICE.md missing expected marker %q — fork may have been replaced without updating documentation", want)
		}
	}
}
