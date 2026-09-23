package sulla

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/hirochachacha/go-smb2"
	"github.com/praetorian-inc/titus/pkg/enum"
)

// toUNCPathSMB converts an SMB-relative path (e.g. "dir/subdir/file.txt") to a UNC display path.
func toUNCPathSMB(smbPath string, config Config) string {
	rel := strings.ReplaceAll(smbPath, "/", `\`)
	rel = strings.TrimPrefix(rel, `\`)
	// Remove leading ".\" from root-relative walks
	rel = strings.TrimPrefix(rel, `.\`)
	if config.DFSPath != "" {
		return config.DFSPath + `\` + rel
	}
	return fmt.Sprintf(`\\%s\%s\%s`, config.Host, config.Share, rel)
}

// buildExcludedExtensions returns a set of extensions to skip during scanning.
func buildExcludedExtensions(config Config) map[string]bool {
	exts := make(map[string]bool)
	if !config.NoExclusion {
		for _, ext := range defaultExcludedExtensions {
			exts[strings.ToLower(ext)] = true
		}
	}
	for _, ext := range config.AdditionalExts {
		exts[strings.ToLower(ext)] = true
	}
	// When --extract is on, remove extractable types from the exclusion set
	// so they reach the scanner and can be routed to the extraction path.
	if config.ExtractBinary {
		for ext := range extractableExtsWithoutDot {
			delete(exts, ext)
		}
	}
	return exts
}

// isLiteralString returns true if s contains no regex metacharacters.
func isLiteralString(s string) bool {
	return regexp.QuoteMeta(s) == s
}

// buildExcludedDirectories returns a dirExclusions with exact-match names and regex patterns.
// Literal folder names (no metacharacters) use O(1) map lookup; only true regex patterns are compiled.
func buildExcludedDirectories(config Config) dirExclusions {
	excl := dirExclusions{exact: make(map[string]bool)}
	addFolder := func(folder string) {
		if isLiteralString(folder) {
			excl.exact[folder] = true
		} else if re, err := regexp.Compile(folder); err == nil {
			excl.patterns = append(excl.patterns, re)
		}
	}
	if !config.NoExclusion {
		for _, folder := range defaultExcludedFolders {
			addFolder(folder)
		}
	}
	for _, folder := range config.AdditionalFolders {
		addFolder(folder)
	}
	return excl
}

// shouldExcludeExt reports whether the file at path should be skipped based on extension.
func shouldExcludeExt(path string, excluded map[string]bool) bool {
	// Handle .tar.gz specially — filepath.Ext returns ".gz" but we want to
	// treat ".tar.gz" as a single extension to match getExtension behavior.
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") {
		return excluded["tar.gz"]
	}
	ext := strings.TrimPrefix(filepath.Ext(path), ".")
	return excluded[strings.ToLower(ext)]
}

// shouldExcludeDir reports whether a directory name matches any exclusion (exact or pattern).
func shouldExcludeDir(name string, excl dirExclusions) bool {
	if excl.exact[name] {
		return true
	}
	for _, re := range excl.patterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// getExtension returns the lowercase file extension, handling .tar.gz specially.
// sync with titus/pkg/enum/extractor.go:getExtension
func getExtension(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tar.gz") {
		return ".tar.gz"
	}
	return strings.ToLower(filepath.Ext(path))
}

// isExtractable reports whether the file extension is supported by Titus text extraction.
// sync with titus/pkg/enum/extractor.go:isExtractable
func isExtractable(ext string) bool {
	switch ext {
	case ".zip", ".jar", ".war", ".ear", ".apk", ".ipa", ".xpi", ".crx",
		".xlsx", ".docx", ".pptx", ".pdf",
		".tar", ".tar.gz", ".tgz", ".7z",
		".ipynb", ".odt", ".ods", ".odp", ".eml", ".rtf",
		".sqlite", ".db":
		return true
	}
	return false
}

// extractableExtsWithoutDot is the set of extensions (without leading dot) that isExtractable covers.
// Used by buildExcludedExtensions to un-exclude these when --extract is on.
var extractableExtsWithoutDot = map[string]bool{
	"zip": true, "jar": true, "war": true, "ear": true, "apk": true, "ipa": true, "xpi": true, "crx": true,
	"xlsx": true, "docx": true, "pptx": true, "pdf": true,
	"tar": true, "tar.gz": true, "tgz": true, "7z": true,
	"ipynb": true, "odt": true, "ods": true, "odp": true, "eml": true, "rtf": true,
	"sqlite": true, "db": true,
}

// isBinary returns true if the header bytes look like a binary (non-text) file.
// Checks for common magic bytes and a high ratio of null/control characters.
func isBinary(header []byte) bool {
	if len(header) == 0 {
		return false
	}
	// Check common binary magic bytes
	if len(header) >= 4 {
		// ELF
		if header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
			return true
		}
		// ZIP/DOCX/XLSX/JAR/APK
		if header[0] == 'P' && header[1] == 'K' && header[2] == 0x03 && header[3] == 0x04 {
			return true
		}
		// PDF
		if header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F' {
			return false // PDFs can contain text secrets — let Titus scan them
		}
		// gzip
		if header[0] == 0x1f && header[1] == 0x8b {
			return true
		}
		// PE (Windows exe/dll)
		if header[0] == 'M' && header[1] == 'Z' {
			return true
		}
	}

	// Count null bytes and non-text control characters
	nulls := 0
	for _, b := range header {
		if b == 0 {
			nulls++
		}
	}
	// If >10% of the header is null bytes, treat as binary
	return nulls > len(header)/10
}

// scanFile performs binary detection, file read, and Titus scan on a single file.
// Returns any matches found. This is the I/O-heavy work moved to worker goroutines.
// bytesToString converts a byte slice to a string without copying.
// The caller must not modify b while the returned string is in use.
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// scanFileSMB reads a file directly from an SMB share and scans it with Titus.
// Uses a single share.Open() call (saves 1 SMB round-trip vs the old two-open approach).
// headerBuf is caller-provided via sync.Pool to avoid per-file allocation.
func scanFileSMB(config Config, share *smb2.Share, path string, size int64, interesting bool, created, modified time.Time,
	headerBuf []byte, skippedFiles *int64) ([]fileMatch, *interestingExclusion) {

	const largeFileThreshold = 50 * 1024 * 1024
	const chunkSize = 50 * 1024 * 1024
	const chunkOverlap = 4 * 1024

	displayPath := toUNCPathSMB(path, config)

	// Check if this file is extractable (before size gate, since extractable files
	// use Titus extraction limits instead of MaxScanSize).
	ext := getExtension(path)
	extractable := isExtractable(ext)
	shouldExtract := extractable && (config.ExtractBinary || interesting)

	// Size gate — extractable files use the extraction limit (10MB) instead of MaxScanSize,
	// since Titus extraction already bounds memory internally.
	if shouldExtract {
		extractionMaxSize := enum.DefaultExtractionLimits().MaxSize
		if size > extractionMaxSize {
			if config.Debug {
				logf("[*] Skipping oversized extractable file (%d MB > %d MB extraction limit): %s\n",
					size/(1024*1024), extractionMaxSize/(1024*1024), displayPath)
			}
			atomic.AddInt64(skippedFiles, 1)
			if interesting && config.InterestingExcl {
				return nil, &interestingExclusion{uncPath: displayPath, size: size, reason: "oversize"}
			}
			return nil, nil
		}
	} else if config.MaxScanSize > 0 && size > config.MaxScanSize {
		if config.Debug {
			logf("[*] Skipping oversized file (%d MB > %d MB limit): %s\n",
				size/(1024*1024), config.MaxScanSize/(1024*1024), displayPath)
		}
		atomic.AddInt64(skippedFiles, 1)
		if interesting && config.InterestingExcl {
			return nil, &interestingExclusion{uncPath: displayPath, size: size, reason: "oversize"}
		}
		return nil, nil
	}

	// Single open — read header first, then full content if not binary
	f, err := share.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	// Extraction path: read full content and extract text from binary formats.
	// Bypasses header/binary detection since extractable files are always binary.
	if shouldExtract {
		content := make([]byte, size)
		n, readErr := io.ReadFull(f, content)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			if config.Debug {
				logf("[*] Read error (skipping): %s: %v\n", displayPath, readErr)
			}
			return nil, nil
		}
		content = content[:n]

		extracted, extractErr := enum.ExtractText(path, content, enum.DefaultExtractionLimits())
		if extractErr != nil {
			if config.Debug {
				logf("[*] Extraction error (skipping): %s: %v\n", displayPath, extractErr)
			}
			return nil, nil
		}

		var matches []fileMatch
		for _, ec := range extracted {
			compoundPath := displayPath + ":" + ec.Name
			result, scanErr := titusCore.Scan(bytesToString(ec.Content), compoundPath)
			if scanErr != nil {
				if config.Debug {
					logf("[*] Scan error (skipping): %s: %v\n", compoundPath, scanErr)
				}
				continue
			}
			for _, m := range result.Matches {
				matches = append(matches, fileMatch{match: m, filePath: compoundPath, severity: ruleSeverity(m.RuleID), created: created, modified: modified})
			}
		}
		return matches, nil
	}

	// Read header for binary detection (reuse caller-provided buffer)
	n, _ := f.Read(headerBuf)
	if n > 0 && isBinary(headerBuf[:n]) {
		if config.Debug {
			logf("[*] Skipping binary file: %s\n", displayPath)
		}
		atomic.AddInt64(skippedFiles, 1)
		if interesting && config.InterestingExcl {
			return nil, &interestingExclusion{uncPath: displayPath, size: size, reason: "binary"}
		}
		return nil, nil
	}

	var matches []fileMatch

	if size <= largeFileThreshold {
		// Small file: read full content
		content := make([]byte, size)
		f.Seek(0, io.SeekStart)
		n, readErr := io.ReadFull(f, content)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			if config.Debug {
				logf("[*] Read error (skipping): %s: %v\n", displayPath, readErr)
			}
			return nil, nil
		}
		content = content[:n]

		result, scanErr := titusCore.Scan(bytesToString(content), displayPath)
		if scanErr != nil {
			if config.Debug {
				logf("[*] Scan error (skipping): %s: %v\n", displayPath, scanErr)
			}
			return nil, nil
		}
		for _, m := range result.Matches {
			matches = append(matches, fileMatch{match: m, filePath: displayPath, severity: ruleSeverity(m.RuleID), created: created, modified: modified})
		}
	} else {
		// Large file: chunked reading via smb2 file handle
		if config.Debug {
			logf("[*] Large file (%d MB), scanning in chunks: %s\n", size/(1024*1024), displayPath)
		}
		seen := make(map[string]bool)
		offset := int64(0)
		chunk := make([]byte, chunkSize)

		for offset < size {
			readSize := int64(chunkSize)
			if offset+readSize > size {
				readSize = size - offset
			}

			f.Seek(offset, io.SeekStart)
			n, readErr := io.ReadFull(f, chunk[:readSize])
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				break
			}
			if n == 0 {
				break
			}

			result, scanErr := titusCore.Scan(bytesToString(chunk[:n]), displayPath)
			if scanErr == nil {
				for _, m := range result.Matches {
					key := m.RuleID + "|" + string(m.Snippet.Matching)
					if !seen[key] {
						seen[key] = true
						matches = append(matches, fileMatch{match: m, filePath: displayPath, severity: ruleSeverity(m.RuleID), created: created, modified: modified})
					}
				}
			}

			offset += int64(chunkSize) - int64(chunkOverlap)
		}
	}
	return matches, nil
}

// runTitusScanSMB walks the share via native go-smb2 and scans every eligible file with Titus.
// Uses a producer-consumer pattern: smbWalkDir sends paths to a channel, N workers scan in parallel.
func runTitusScanSMB(ctx context.Context, config Config, share *smb2.Share) (ScanStats, error) {
	if titusCore == nil {
		return ScanStats{}, fmt.Errorf("titus scanner not initialized")
	}

	tag := targetTag(config)
	excludedExts := config.ExcludedExts
	excludedDirs := config.ExcludedDirs

	// Show exclusion/quick mode info
	if config.Verbose {
		if config.QuickMode {
			depthInfo := "unlimited"
			if config.MaxDepth > 0 {
				depthInfo = fmt.Sprintf("%d", config.MaxDepth)
			}
			timeInfo := "indefinite"
			if config.MaxShareTime > 0 {
				timeInfo = fmt.Sprintf("%d min", config.MaxShareTime)
			}
			filesInfo := "unlimited"
			if config.MaxFilesPerDir > 0 {
				filesInfo = fmt.Sprintf("%d", config.MaxFilesPerDir)
			}
			logf("%s Quick mode: %d extensions, %d filenames, depth %s, %s files/dir, %s/share\n",
				tag, len(quickModeExtensions), len(quickModeExactFilenames)+len(quickModeContainsFilenames), depthInfo, filesInfo, timeInfo)
		} else if !config.NoExclusion {
			logf("%s Using default exclusions (%d extensions, %d folders)\n",
				tag, len(defaultExcludedExtensions), len(defaultExcludedFolders))
		}
		if len(config.AdditionalExts) > 0 || len(config.AdditionalFolders) > 0 {
			logf("%s Additional exclusions: %d extensions, %d folders\n",
				tag, len(config.AdditionalExts), len(config.AdditionalFolders))
		}
	}
	if !config.Verbose && config.NoExclusion {
		logf("%s WARNING: Scanning all files (no exclusions enabled)\n", tag)
	}

	var (
		allMatches   []fileMatch
		mu           sync.Mutex
		fileCount    int64
		dirCount     int64
		skippedFiles int64
	)

	// Streaming writer for interesting exclusions — writes each entry to disk
	// as it arrives via a buffered channel so nothing is lost on interrupt.
	var (
		exclCh    chan interestingExclusion
		exclDone  chan struct{}
		exclCount int64
	)
	if config.InterestingExcl {
		exclPath := interestingExclPath(config)
		exclCh = make(chan interestingExclusion, 4096)
		exclDone = make(chan struct{})
		go func() {
			defer close(exclDone)
			f, err := os.Create(exclPath)
			if err != nil {
				logf("%s Warning: failed to create interesting exclusions file: %v\n", tag, err)
				// Drain channel so workers never block
				for range exclCh {
				}
				return
			}
			defer f.Close()
			w := bufio.NewWriter(f)
			defer w.Flush()
			w.WriteString("unc_path,file_size,exclude_reason\n")
			for e := range exclCh {
				fmt.Fprintf(w, "%s,%d,%s\n", e.uncPath, e.size, e.reason)
				atomic.AddInt64(&exclCount, 1)
				// Flush periodically so data hits disk even on crash
				if atomic.LoadInt64(&exclCount)%64 == 0 {
					w.Flush()
				}
			}
			createdFiles.add(exclPath)
		}()
	}

	// Register with live status tracker
	if config.Tracker != nil {
		config.Tracker.register(tag, &fileCount, &dirCount)
		defer config.Tracker.deregister(tag)
	}

	// Buffer pool for 512-byte headers (avoids per-file allocation)
	headerPool := sync.Pool{
		New: func() interface{} { return make([]byte, 512) },
	}

	jobs := make(chan fileJob, config.FileWorkers*4)

	// Start consumer workers
	var wg sync.WaitGroup
	for i := 0; i < config.FileWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			headerBuf := headerPool.Get().([]byte)
			defer headerPool.Put(headerBuf)

			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				matches, excl := scanFileSMB(config, share, job.path, job.size, job.interesting, job.created, job.modified, headerBuf, &skippedFiles)
				atomic.AddInt64(&fileCount, 1)
				if excl != nil && exclCh != nil {
					exclCh <- *excl
				}
				if len(matches) > 0 {
					mu.Lock()
					allMatches = append(allMatches, matches...)
					mu.Unlock()
				}
			}
		}()
	}

	// Producer: walk share and send eligible files to workers
	err := smbWalkDir(ctx, share, ".", excludedDirs, config.MaxDepth, config.MaxFilesPerDir, &dirCount, func(path string, size int64, created, modified time.Time) error {
		// Keyword matches override all exclusion logic
		keywordMatch := false
		if len(config.Keywords) > 0 {
			name := strings.ToLower(filepath.Base(path))
			for _, kw := range config.Keywords {
				if strings.Contains(name, kw) {
					keywordMatch = true
					break
				}
			}
		}
		if !keywordMatch {
			if config.QuickMode {
				if !isQuickModeTarget(path) && !(config.ExtractBinary && isExtractable(getExtension(path))) {
					atomic.AddInt64(&skippedFiles, 1)
					return nil
				}
			} else if shouldExcludeExt(path, excludedExts) {
				if config.Debug {
					logf("[*] Skipping excluded: %s\n", toUNCPathSMB(path, config))
				}
				atomic.AddInt64(&skippedFiles, 1)
				return nil
			}
		}
		// Mark as interesting if keyword matched or (quick mode and passed allowlist)
		interesting := keywordMatch || config.QuickMode
		select {
		case jobs <- fileJob{path: path, size: size, interesting: interesting, created: created, modified: modified}:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	close(jobs)
	wg.Wait()

	timedOut := ctx.Err() == context.DeadlineExceeded
	if err != nil && ctx.Err() == nil {
		return ScanStats{}, fmt.Errorf("walking share: %w", err)
	}
	// If the parent context was cancelled (e.g. Ctrl+C), abort entirely
	if ctx.Err() != nil && !timedOut {
		return ScanStats{}, ctx.Err()
	}

	fc := atomic.LoadInt64(&fileCount)
	dc := atomic.LoadInt64(&dirCount)
	sf := atomic.LoadInt64(&skippedFiles)
	if timedOut {
		logf("%s Time limit reached — scanned %d files in %d directories (partial)\n", tag, fc, dc)
	} else if config.Verbose {
		logf("%s Scanned %d files in %d directories\n", tag, fc, dc)
	}

	// Build severity and rule counts from matches
	var sevCounts [4]int
	ruleCounts := make(map[string]int)
	for _, m := range allMatches {
		sevCounts[m.severity]++
		ruleCounts[m.match.RuleID]++
	}

	stats := ScanStats{
		HasFindings:    len(allMatches) > 0,
		TimedOut:       timedOut,
		FileCount:      fc,
		DirCount:       dc,
		SkippedFiles:   sf,
		MatchCount:     len(allMatches),
		SeverityCounts: sevCounts,
		RuleCounts:     ruleCounts,
	}

	// Close the streaming interesting exclusions writer and wait for it to flush
	if exclCh != nil {
		close(exclCh)
		<-exclDone
		if n := atomic.LoadInt64(&exclCount); n > 0 && config.Verbose {
			logf("[+] Interesting exclusions written to %s (%d entries)\n", interestingExclPath(config), n)
		}
	}

	if len(allMatches) == 0 {
		if config.Verbose {
			logf("%s No secrets discovered in this share.\n", tag)
		}
		return stats, nil
	}

	if err := outputTitusResults(config, allMatches); err != nil {
		return stats, err
	}
	return stats, nil
}

// getOutputFilePath returns the output file path for a given format.
