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

	loadFile := func(path string) error {
		rule, err := loader.LoadRuleFile(path)
		if err != nil {
			return fmt.Errorf("custom rule %s: %w", path, err)
		}
		if err := titusrule.ValidateRule(rule); err != nil {
			return fmt.Errorf("custom rule %s: %w", path, err)
		}
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
