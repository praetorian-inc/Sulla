package sulla

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	titussarif "github.com/praetorian-inc/titus/pkg/sarif"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
)

// validateOutputFormats parses a comma-separated --output-format value and
// returns the list of canonical formats. The legacy "tabularium" value is
// rewritten to "capability-sdk" with a stderr deprecation warning; the alias
// will be removed in the next release. Empty input yields an empty list.
func validateOutputFormats(input string) ([]string, error) {
	valid := map[string]bool{
		"txt":            true,
		"json":           true,
		"jsonl":          true,
		"sarif":          true,
		"capability-sdk": true,
		"tabularium":     true,
	}
	var out []string
	if input == "" {
		return out, nil
	}
	for _, format := range strings.Split(input, ",") {
		format = strings.TrimSpace(strings.ToLower(format))
		if !valid[format] {
			return nil, fmt.Errorf("invalid output format %q. Valid formats: txt, json, jsonl, sarif, capability-sdk", format)
		}
		if format == "tabularium" {
			logln("[!] --output-format tabularium is deprecated; use capability-sdk instead. Continuing as capability-sdk.")
			format = "capability-sdk"
		}
		out = append(out, format)
	}
	return out, nil
}

// sanitizeFilename replaces characters that are problematic in filenames
func sanitizeFilename(s string) string {
	// Replace dots and other problematic characters with underscores
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// printSummary displays an expanded summary of all scan results.
func printSummary(results []ScanResult, totalTime time.Duration) {
	var scanned, failed, timedOut int
	var totalFiles, totalDirs, totalSkipped int64
	var totalMatches int
	var sevTotals [4]int
	mergedRules := make(map[string]int)
	uniqueHosts := make(map[string]struct{})
	var findingTargets int

	for _, r := range results {
		uniqueHosts[r.Host] = struct{}{}
		if r.Error != nil {
			failed++
			continue
		}
		scanned++
		if r.TimedOut {
			timedOut++
		}
		totalFiles += r.FileCount
		totalDirs += r.DirCount
		totalSkipped += r.SkippedFiles
		totalMatches += r.MatchCount
		if r.MatchCount > 0 {
			findingTargets++
		}
		for i := 0; i < 4; i++ {
			sevTotals[i] += r.SeverityCounts[i]
		}
		for rule, cnt := range r.RuleCounts {
			mergedRules[rule] += cnt
		}
	}

	logln("\n=== Scan Summary ===")
	logf("Target shares: %-7s (%d unique hosts)\n",
		formatCount(len(results)), len(uniqueHosts))
	logf("Scanned:       %d\n", scanned)
	logf("Failed:        %d\n", failed)
	logf("Timed out:     %d\n", timedOut)

	logf("\nFiles scanned:      %s across %s directories\n",
		formatCount64(totalFiles), formatCount64(totalDirs))
	logf("Files skipped:      %s\n", formatCount64(totalSkipped))

	logf("\nPotential secrets:  %d across %d targets\n", totalMatches, findingTargets)
	logf("  Critical: %d  High: %d  Medium: %d  Low: %d\n",
		sevTotals[SeverityCritical], sevTotals[SeverityHigh],
		sevTotals[SeverityMedium], sevTotals[SeverityLow])

	if len(mergedRules) > 0 {
		type ruleCount struct {
			id    string
			count int
		}
		var sorted []ruleCount
		for id, cnt := range mergedRules {
			sorted = append(sorted, ruleCount{id, cnt})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		top := sorted
		if len(top) > 3 {
			top = top[:3]
		}
		parts := make([]string, len(top))
		for i, rc := range top {
			parts[i] = fmt.Sprintf("%s (%d)", rc.id, rc.count)
		}
		logf("Top rules:          %s\n", strings.Join(parts, ", "))
	}

	logf("\nTotal time:         %s\n", formatDuration(totalTime))
}

// formatCount formats an int with comma separators.
func formatCount(n int) string {
	return formatCount64(int64(n))
}

// formatCount64 formats an int64 with comma separators.
func formatCount64(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// formatDuration formats a duration as e.g. "2m34s" or "12s".
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) % 60
	if s == 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

// redactProofContent replaces secret match values in text-format proof content
// with [REDACTED]. Match content can span multiple lines (PEM keys, multi-line
// credentials), so we walk line-by-line and suppress continuation lines until
// the next structural boundary (blank line, next finding, next file header).
func redactProofContent(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inMatch := false
	for _, line := range lines {
		if strings.HasPrefix(line, "  Match:") {
			result = append(result, "  Match:   [REDACTED]")
			inMatch = true
			continue
		}
		if inMatch {
			if line == "" || strings.HasPrefix(line, "  [") || strings.HasPrefix(line, "File:") || strings.HasPrefix(line, "===") {
				inMatch = false
				result = append(result, line)
			}
			// else: skip multi-line secret continuation
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// zipOutputFiles collects the tracked txt/json output files into a single zip
// archive, then removes the originals. The zip is named to match the
// capability-sdk output convention: {sanitized_domain_or_host__share}.zip and
// placed in the same directory as the output files.
func zipOutputFiles(config Config) error {
	// Filter tracked files to output formats we want in the archive
	zipExts := map[string]bool{".txt": true, ".json": true, ".jsonl": true, ".sarif": true, ".csv": true}
	var toZip []string
	for _, p := range createdFiles.list() {
		if zipExts[strings.ToLower(filepath.Ext(p))] {
			toZip = append(toZip, p)
		}
	}
	if len(toZip) == 0 {
		return nil
	}

	// Determine zip filename using capability-sdk output naming convention
	var zipBase string
	if config.Domain != "" {
		zipBase = sanitizeFilename(config.Domain)
	} else {
		zipBase = sanitizeFilename(config.Host) + "__" + sanitizeFilename(config.Share)
	}

	// Determine output directory (same as where capability-sdk output would be placed)
	zipDir := "."
	if config.OutputFile != "" {
		if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
			zipDir = config.OutputFile
		} else {
			zipDir = filepath.Dir(config.OutputFile)
		}
	}

	zipPath := filepath.Join(zipDir, zipBase+".zip")

	zf, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file %s: %w", zipPath, err)
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	for _, path := range toZip {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %s for zipping: %w", path, err)
		}
		fw, err := zw.Create(filepath.Base(path))
		if err != nil {
			return fmt.Errorf("failed to add %s to zip: %w", path, err)
		}
		if _, err := fw.Write(data); err != nil {
			return fmt.Errorf("failed to write %s to zip: %w", path, err)
		}
	}

	// Close the zip writer before deleting originals to ensure the archive is valid
	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finalize zip: %w", err)
	}

	// Delete originals
	for _, path := range toZip {
		if err := os.Remove(path); err != nil {
			logf("[!] Warning: failed to remove %s after zipping: %v\n", path, err)
		}
	}

	logf("[+] Output archived to %s (%d files)\n", zipPath, len(toZip))
	return nil
}

// outputDiscoveredShares outputs discovered shares in UNC format
func outputDiscoveredShares(config Config, targets []Target) {
	// Build output lines in UNC format
	var lines []string
	for _, t := range targets {
		if t.DFSPath != "" {
			lines = append(lines, fmt.Sprintf("%s  (DFS: %s)", fmt.Sprintf("\\\\%s\\%s", t.Host, t.Share), t.DFSPath))
		} else {
			lines = append(lines, fmt.Sprintf("\\\\%s\\%s", t.Host, t.Share))
		}
	}
	output := strings.Join(lines, "\n") + "\n"

	// Determine output destination
	if config.SaveOutput {
		// Generate filename: {dc_or_domain}_discovered_smb_shares.txt
		nameBase := config.DomainController
		if nameBase == "" {
			nameBase = config.Domain
		}
		filename := fmt.Sprintf("%s_discovered_smb_shares.txt", sanitizeFilename(nameBase))

		// If OutputFile is a directory, write file into it
		outputPath := config.OutputFile
		if outputPath != "" {
			info, err := os.Stat(outputPath)
			if (err == nil && info.IsDir()) || strings.HasSuffix(outputPath, "/") || strings.HasSuffix(outputPath, string(os.PathSeparator)) {
				// It's a directory (or intended to be), join with filename
				if err != nil {
					// Directory doesn't exist, create it
					if err := os.MkdirAll(outputPath, 0755); err != nil {
						logf("Error: Failed to create output directory: %s\n", err)
						os.Exit(1)
					}
				}
				outputPath = filepath.Join(outputPath, filename)
			}
			// else: use outputPath as-is (user specified a filename)
		} else {
			// -o with no argument: use default filename in current directory
			outputPath = filename
		}

		if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
			logf("Error: Failed to write output file: %s\n", err)
			os.Exit(1)
		}
		createdFiles.add(outputPath)
		logf("[+] Discovered shares written to %s\n", outputPath)
	} else {
		// Output to stdout
		fmt.Print(output)
	}
}

// resolveOutputFormats returns the list of formats to write to disk. It strips
// "capability-sdk" (handled by generateCapabilitySDKOutput) and falls back to
// ["txt"] when nothing is requested.
//
// When capability-sdk is requested alongside a non-txt format (e.g.
// -of sarif,capability-sdk), the .txt file must still be written: the
// capability-sdk proof blob is built by reading ScanResult.OutputPath (a .txt
// path) and passing it through redactProofContent, which depends on the text
// format's "  Match:" prefix markers. Without this, the proof content
// degrades to "[Could not read output file: ...]".
func resolveOutputFormats(requested []string) []string {
	var out []string
	hasCapabilitySDK := false
	hasTxt := false
	for _, f := range requested {
		if f == "capability-sdk" {
			hasCapabilitySDK = true
			continue
		}
		if f == "txt" {
			hasTxt = true
		}
		out = append(out, f)
	}
	if hasCapabilitySDK && !hasTxt {
		out = append([]string{"txt"}, out...)
	}
	if len(out) == 0 {
		out = []string{"txt"}
	}
	return out
}

// It replaces or appends the appropriate extension based on the format.
func getOutputFilePath(basePath, format string) string {
	ext := filepath.Ext(basePath)
	baseWithoutExt := strings.TrimSuffix(basePath, ext)

	extMap := map[string]string{
		"txt":   ".txt",
		"json":  ".json",
		"jsonl": ".jsonl",
		"sarif": ".sarif",
	}

	return baseWithoutExt + extMap[format]
}

// interestingExclPath returns the output file path for the interesting exclusions CSV.
func interestingExclPath(config Config) string {
	var nameBase string
	if config.Domain != "" {
		nameBase = sanitizeFilename(config.Domain)
	} else {
		nameBase = sanitizeFilename(config.Host) + "__" + sanitizeFilename(config.Share)
	}
	filename := fmt.Sprintf("%s_interesting_exclusions.csv", nameBase)

	outputPath := filename
	if config.OutputFile != "" {
		if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
			outputPath = filepath.Join(config.OutputFile, filename)
		} else if strings.HasSuffix(config.OutputFile, "/") || strings.HasSuffix(config.OutputFile, string(os.PathSeparator)) {
			outputPath = filepath.Join(config.OutputFile, filename)
		}
	}
	return outputPath
}

// outputTitusResults prints finding one-liners to stdout and, if configured, saves to output files.
func outputTitusResults(config Config, matches []fileMatch) error {
	// Print one grep-friendly line per finding to stdout, deduplicating per rule+file.
	type dedupKey struct{ ruleID, filePath string }
	seen := make(map[dedupKey]int) // key → count
	var order []dedupKey
	for _, fm := range matches {
		k := dedupKey{fm.match.RuleID, fm.filePath}
		if seen[k] == 0 {
			order = append(order, k)
		}
		seen[k]++
	}
	// Build a lookup for the first match per key (for RuleName)
	nameOf := make(map[dedupKey]string, len(order))
	for _, fm := range matches {
		k := dedupKey{fm.match.RuleID, fm.filePath}
		if _, ok := nameOf[k]; !ok {
			nameOf[k] = fm.match.RuleName
		}
	}
	for _, k := range order {
		count := seen[k]
		countSuffix := ""
		if count > 1 {
			countSuffix = fmt.Sprintf(" (%d matches)", count)
		}
		fmt.Printf("[%s] %s at %s%s\n", k.ruleID, nameOf[k], k.filePath, countSuffix)
	}

	if config.SaveOutput && config.OutputFile != "" {
		formats := resolveOutputFormats(config.OutputFormats)

		for _, format := range formats {
			outputPath := getOutputFilePath(config.OutputFile, format)
			if err := outputTitusToFile(matches, format, outputPath); err != nil {
				return err
			}
			createdFiles.add(outputPath)
			logf("[+] Report saved to %s\n", outputPath)
		}
	}

	return nil
}

// outputTitusText writes a human-readable report of matches to w.
func outputTitusText(w io.Writer, matches []fileMatch) {
	// Group matches by file
	type fileGroup struct {
		path    string
		matches []fileMatch
	}
	seen := make(map[string]int)
	var groups []fileGroup
	for _, fm := range matches {
		if idx, ok := seen[fm.filePath]; ok {
			groups[idx].matches = append(groups[idx].matches, fm)
		} else {
			seen[fm.filePath] = len(groups)
			groups = append(groups, fileGroup{path: fm.filePath, matches: []fileMatch{fm}})
		}
	}

	fmt.Fprintf(w, "\n=== Titus Scan Results: %d finding(s) in %d file(s) ===\n\n", len(matches), len(groups))
	for _, g := range groups {
		fmt.Fprintf(w, "File: %s\n", g.path)
		fmt.Fprintln(w, strings.Repeat("-", 60))
		for _, fm := range g.matches {
			m := fm.match
			fmt.Fprintf(w, "  [%s] Rule: %s (%s)\n", fm.severity, m.RuleName, m.RuleID)
			fmt.Fprintf(w, "  Location: line %d, col %d\n",
				m.Location.Source.Start.Line, m.Location.Source.Start.Column)
			if len(m.Snippet.Matching) > 0 {
				fmt.Fprintf(w, "  Match:   %s\n", strings.TrimSpace(string(m.Snippet.Matching)))
			}
			fmt.Fprintln(w)
		}
	}
}

// outputTitusToFile writes matches to a file in the requested format.
func outputTitusToFile(matches []fileMatch, format, path string) error {
	switch format {
	case "txt":
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", path, err)
		}
		defer f.Close()
		outputTitusText(f, matches)
		return nil

	case "json":
		type jsonMatch struct {
			FilePath string            `json:"file_path"`
			Severity string            `json:"severity"`
			Match    *titustypes.Match `json:"match"`
		}
		var out []jsonMatch
		for _, fm := range matches {
			out = append(out, jsonMatch{FilePath: fm.filePath, Severity: fm.severity.String(), Match: fm.match})
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return os.WriteFile(path, data, 0644)

	case "jsonl":
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", path, err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		type jsonMatch struct {
			FilePath string            `json:"file_path"`
			Severity string            `json:"severity"`
			Match    *titustypes.Match `json:"match"`
		}
		for _, fm := range matches {
			if err := enc.Encode(jsonMatch{FilePath: fm.filePath, Severity: fm.severity.String(), Match: fm.match}); err != nil {
				return fmt.Errorf("failed to encode JSONL: %w", err)
			}
		}
		return nil

	case "sarif":
		report := titussarif.NewReport()

		// Add rules for matched rule IDs (reuse cached rules from startup)
		ruleMap := make(map[string]*titustypes.Rule)
		for _, r := range titusAllRules {
			ruleMap[r.ID] = r
		}
		addedRules := make(map[string]bool)
		for _, fm := range matches {
			if !addedRules[fm.match.RuleID] {
				addedRules[fm.match.RuleID] = true
				if r, ok := ruleMap[fm.match.RuleID]; ok {
					report.AddRule(r)
				}
			}
		}

		// Add results
		for _, fm := range matches {
			report.AddResult(fm.match, fm.filePath)
		}

		data, err := report.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize SARIF: %w", err)
		}
		return os.WriteFile(path, data, 0644)

	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
