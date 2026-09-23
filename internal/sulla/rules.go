package sulla

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	titusrule "github.com/praetorian-inc/titus/pkg/rule"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
)

// builtinIDConflict returns the first custom rule ID that also exists among the
// built-in rules, or "" if none conflict. Custom rules must use distinct IDs so
// their SARIF metadata and findings are not silently shadowed by a built-in.
func builtinIDConflict(custom, builtin []*titustypes.Rule) string {
	builtinIDs := make(map[string]struct{}, len(builtin))
	for _, r := range builtin {
		builtinIDs[r.ID] = struct{}{}
	}
	for _, r := range custom {
		if _, ok := builtinIDs[r.ID]; ok {
			return r.ID
		}
	}
	return ""
}

// validateRuleFields checks that a custom rule has the required fields. Unlike
// titusrule.ValidateRule it does not compile the pattern, so extended-mode
// "(?x)" patterns supported by Titus's regexp2 matcher are not rejected here.
func validateRuleFields(rule *titustypes.Rule) error {
	switch {
	case rule.ID == "":
		return fmt.Errorf("rule ID is required")
	case rule.Name == "":
		return fmt.Errorf("rule name is required")
	case rule.Pattern == "":
		return fmt.Errorf("rule pattern is required")
	}
	return nil
}

// isRuleFile reports whether path has a Titus rule YAML extension.
func isRuleFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}

// loadCustomRules loads and validates user-supplied Titus rules from the given
// paths. Each path may be a single YAML file or a directory, which is walked
// recursively for *.yml/*.yaml files. Every rule file must contain exactly one
// rule (one rule per file); files holding multiple rules are rejected.
//
// It returns the loaded rules in path order, or the first error encountered.
func loadCustomRules(paths []string) ([]*titustypes.Rule, error) {
	loader := titusrule.NewLoader()
	var rules []*titustypes.Rule
	seenIDs := make(map[string]string) // rule ID -> path it was first loaded from

	loadFile := func(path string) error {
		rule, err := loader.LoadRuleFile(path)
		if err != nil {
			return fmt.Errorf("custom rule %s: %w", path, err)
		}
		// Validate required fields, but do NOT compile the pattern here:
		// titusrule.ValidateRule uses Go's stdlib regexp, which rejects
		// extended-mode "(?x)" patterns that Titus's regexp2 matcher (and many
		// built-in rules) accept. Pattern compilation is left to the matcher in
		// NewCoreWithRules, which reports invalid patterns per rule.
		if err := validateRuleFields(rule); err != nil {
			return fmt.Errorf("custom rule %s: %w", path, err)
		}
		if firstPath, ok := seenIDs[rule.ID]; ok {
			return fmt.Errorf("custom rule %s: duplicate rule ID %q (already defined in %s)", path, rule.ID, firstPath)
		}
		seenIDs[rule.ID] = path
		rules = append(rules, rule)
		return nil
	}

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("custom rule path %s: %w", path, err)
		}

		if !info.IsDir() {
			if err := loadFile(path); err != nil {
				return nil, err
			}
			continue
		}

		// Directory: walk for rule files, skipping everything else.
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !isRuleFile(p) {
				return nil
			}
			return loadFile(p)
		})
		if err != nil {
			return nil, err
		}
	}

	// Guard against silently scanning with no rules: the caller supplied paths
	// but none of them yielded a rule file (e.g. a directory with no
	// .yml/.yaml files, or a wrong path/extension).
	if len(rules) == 0 {
		return nil, fmt.Errorf("no custom rules found in the given path(s): %s", strings.Join(paths, ", "))
	}

	return rules, nil
}
