package sulla

import (
	"os"
	"path/filepath"
	"testing"

	titusscanner "github.com/praetorian-inc/titus/pkg/scanner"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
)

const validRuleOne = `rules:
- name: Custom Test Rule One
  id: custom.test.1
  pattern: 'TESTSECRETONE-[0-9]{6}'
`

const validRuleTwo = `rules:
- name: Custom Test Rule Two
  id: custom.test.2
  pattern: 'TESTSECRETTWO-[a-f0-9]{8}'
`

// writeRule writes a rule YAML file into dir and returns its path.
func writeRule(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write rule fixture %s: %v", path, err)
	}
	return path
}

func TestLoadCustomRules_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := writeRule(t, dir, "one.yml", validRuleOne)

	rules, err := loadCustomRules([]string{path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "custom.test.1" {
		t.Errorf("expected rule ID custom.test.1, got %q", rules[0].ID)
	}
}

func TestLoadCustomRules_Directory(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "one.yml", validRuleOne)
	writeRule(t, dir, "two.yml", validRuleTwo)
	// A non-rule file that must be ignored.
	writeRule(t, dir, "README.md", "# not a rule")

	rules, err := loadCustomRules([]string{dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules from directory, got %d", len(rules))
	}
	got := map[string]bool{}
	for _, r := range rules {
		got[r.ID] = true
	}
	if !got["custom.test.1"] || !got["custom.test.2"] {
		t.Errorf("expected both custom rules loaded, got %v", got)
	}
}

func TestLoadCustomRules_MultiplePaths(t *testing.T) {
	dir := t.TempDir()
	p1 := writeRule(t, dir, "one.yml", validRuleOne)
	p2 := writeRule(t, dir, "two.yml", validRuleTwo)

	rules, err := loadCustomRules([]string{p1, p2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules from two file paths, got %d", len(rules))
	}
}

func TestLoadCustomRules_InvalidRule(t *testing.T) {
	dir := t.TempDir()
	// Missing pattern -> ValidateRule must reject.
	path := writeRule(t, dir, "bad.yml", "rules:\n- name: No Pattern\n  id: custom.bad\n")

	_, err := loadCustomRules([]string{path})
	if err == nil {
		t.Fatal("expected error for rule missing pattern, got nil")
	}
}

func TestLoadCustomRules_NonexistentPath(t *testing.T) {
	_, err := loadCustomRules([]string{filepath.Join(t.TempDir(), "does-not-exist.yml")})
	if err == nil {
		t.Fatal("expected error for nonexistent path, got nil")
	}
}

func TestLoadCustomRules_MultiRuleFileRejected(t *testing.T) {
	dir := t.TempDir()
	multi := `rules:
- name: Rule A
  id: custom.multi.a
  pattern: 'AAA-[0-9]{4}'
- name: Rule B
  id: custom.multi.b
  pattern: 'BBB-[0-9]{4}'
`
	path := writeRule(t, dir, "multi.yml", multi)

	_, err := loadCustomRules([]string{path})
	if err == nil {
		t.Fatal("expected error for multi-rule file (one rule per file), got nil")
	}
}

func TestLoadCustomRules_EmptyDirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	// Directory with only a non-rule file -> zero rules loaded.
	writeRule(t, dir, "README.md", "# not a rule")

	_, err := loadCustomRules([]string{dir})
	if err == nil {
		t.Fatal("expected error when paths yield no rules, got nil")
	}
}

func TestLoadCustomRules_DirectoryNoRuleFiles(t *testing.T) {
	dir := t.TempDir()
	// Directory exists but contains no .yml/.yaml rule files — a common
	// accidental "no rules" case that must not silently scan with zero rules.
	writeRule(t, dir, "README.md", "# not a rule")
	writeRule(t, dir, "notes.txt", "just some notes")

	_, err := loadCustomRules([]string{dir})
	if err == nil {
		t.Fatal("expected error when path yields no rule files, got nil")
	}
}

func TestCustomRule_ProducesDetection(t *testing.T) {
	dir := t.TempDir()
	path := writeRule(t, dir, "one.yml", validRuleOne)

	rules, err := loadCustomRules([]string{path})
	if err != nil {
		t.Fatalf("loadCustomRules: %v", err)
	}

	core, err := titusscanner.NewCoreWithRules(rules, nil, nil)
	if err != nil {
		t.Fatalf("NewCoreWithRules: %v", err)
	}
	defer core.Close()

	result, err := core.Scan("here is a leak TESTSECRETONE-123456 in a file", "test.txt")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected custom rule to match, got no matches")
	}
	if result.Matches[0].RuleID != "custom.test.1" {
		t.Errorf("expected match from custom.test.1, got %q", result.Matches[0].RuleID)
	}
}

func TestLoadCustomRules_ExtendedModePatternAccepted(t *testing.T) {
	dir := t.TempDir()
	// (?x) extended/verbose mode is supported by Titus's regexp2 matcher and is
	// used by many built-in rules, but Go's stdlib regexp rejects it. Such a
	// rule must load and scan, not be rejected at load time.
	rule := "rules:\n- name: Extended Mode Rule\n  id: custom.extended.1\n  pattern: |\n    (?x)\n    EXTMODE-\n    [A-Z0-9]{8}\n"
	path := writeRule(t, dir, "ext.yml", rule)

	rules, err := loadCustomRules([]string{path})
	if err != nil {
		t.Fatalf("expected extended-mode rule to load, got error: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "custom.extended.1" {
		t.Fatalf("expected 1 extended-mode rule (custom.extended.1), got %d rules", len(rules))
	}

	core, err := titusscanner.NewCoreWithRules(rules, nil, nil)
	if err != nil {
		t.Fatalf("NewCoreWithRules: %v", err)
	}
	defer core.Close()
	res, err := core.Scan("token EXTMODE-ABCD1234 here", "t.txt")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Fatal("expected extended-mode rule to match")
	}
}

func TestLoadCustomRules_DuplicateCustomID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "a.yml", validRuleOne)
	// Same ID as validRuleOne (custom.test.1) in a different file.
	dup := "rules:\n- name: Duplicate ID\n  id: custom.test.1\n  pattern: 'OTHER-[0-9]{3}'\n"
	writeRule(t, dir, "b.yml", dup)

	_, err := loadCustomRules([]string{dir})
	if err == nil {
		t.Fatal("expected error for duplicate custom rule ID across files, got nil")
	}
}

func TestBuiltinIDConflict(t *testing.T) {
	custom := []*titustypes.Rule{{ID: "acme.token.1"}, {ID: "acme.token.2"}}
	builtin := []*titustypes.Rule{{ID: "np.aws.1"}, {ID: "acme.token.2"}}

	if got := builtinIDConflict(custom, builtin); got != "acme.token.2" {
		t.Errorf("expected conflict acme.token.2, got %q", got)
	}
	// Disjoint sets -> no conflict.
	if got := builtinIDConflict(custom[:1], builtin[:1]); got != "" {
		t.Errorf("expected no conflict, got %q", got)
	}
}
