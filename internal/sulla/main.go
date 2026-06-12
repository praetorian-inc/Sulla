package sulla

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	titusrule "github.com/praetorian-inc/titus/pkg/rule"
	titusscanner "github.com/praetorian-inc/titus/pkg/scanner"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
)

// Main is the entry point for the sulla CLI.
// The version string is injected from cmd/sulla via build-time ldflags.
func Main(version string) {
	config := parseArgs(version)

	// Initialize Titus scanner (skip in discovery-only mode)
	if !config.DiscoveryOnly {
		// Load all builtin rules
		allRules, err := titusscanner.GetBuiltinRules()
		if err != nil {
			logf("Error: Failed to load builtin rules: %v\n", err)
			os.Exit(1)
		}
		titusAllRules = allRules // cache for SARIF output

		// Load the default ruleset to get its rule IDs
		loader := titusrule.NewLoader()
		rulesets, err := loader.LoadBuiltinRulesets()
		if err != nil {
			logf("Error: Failed to load rulesets: %v\n", err)
			os.Exit(1)
		}

		// Find the "default" ruleset and build include set
		var defaultRuleset *titustypes.Ruleset
		for _, rs := range rulesets {
			if rs.ID == "default" {
				defaultRuleset = rs
				break
			}
		}
		if defaultRuleset == nil {
			logf("Error: default ruleset not found\n")
			os.Exit(1)
		}

		// Build include patterns from default ruleset rule IDs (exact match)
		includePatterns := make([]string, len(defaultRuleset.RuleIDs))
		for i, id := range defaultRuleset.RuleIDs {
			includePatterns[i] = "^" + regexp.QuoteMeta(id) + "$"
		}

		// Build exclude patterns from default excluded rules
		excludePatterns := make([]string, len(defaultExcludedRules))
		for i, id := range defaultExcludedRules {
			excludePatterns[i] = "^" + regexp.QuoteMeta(id) + "$"
		}

		// Filter rules to only those in the default ruleset, minus excluded rules
		filteredRules, err := titusrule.Filter(allRules, titusrule.FilterConfig{
			Include: includePatterns,
			Exclude: excludePatterns,
		})
		if err != nil {
			logf("Error: Failed to filter rules: %v\n", err)
			os.Exit(1)
		}
		if len(filteredRules) == 0 {
			logf("Warning: no rules matched the default ruleset — scanner will find nothing\n")
		}

		// Create scanner with filtered rules
		var titusWarnFunc func(string, ...any)
		if config.Debug {
			titusWarnFunc = func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, format, args...)
			}
		}
		titusCore, err = titusscanner.NewCoreWithRules(filteredRules, nil, titusWarnFunc)
		if err != nil {
			logf("Error: Failed to initialize Titus scanner: %v\n", err)
			os.Exit(1)
		}
		defer titusCore.Close()
		logf("[*] Titus scanner initialized (%d rules loaded, filtered from %d)\n", len(filteredRules), len(allRules))
	}

	// Pre-compute file/directory exclusions once (shared across all targets)
	config.ExcludedExts = buildExcludedExtensions(config)
	config.ExcludedDirs = buildExcludedDirectories(config)

	// Validate target selection: discovery mode OR --target-file OR (-h AND -s), mutually exclusive
	// Discovery mode triggers when: domain + credentials provided AND no -h/-s AND no -tf
	hasExplicitDC := config.DomainController != ""
	hasCredentials := config.Username != "" && config.Password != "" && config.Domain != ""
	hasTargetFile := config.TargetsFile != ""
	hasHostShare := config.Host != "" && config.Share != ""
	hasPartialHostShare := config.Host != "" || config.Share != ""

	// Discovery mode: explicit DC OR (credentials without other target methods)
	hasDiscovery := hasExplicitDC || (hasCredentials && !hasTargetFile && !hasPartialHostShare)
	isBatchMode := hasDiscovery || hasTargetFile

	// Check mutual exclusivity
	if hasExplicitDC && hasTargetFile {
		logln("Error: Cannot use --domain-controller with --target-file. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}
	if hasExplicitDC && hasPartialHostShare {
		logln("Error: Cannot use --domain-controller with -h/-s. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}
	if hasTargetFile && hasPartialHostShare {
		logln("Error: Cannot use --target-file with -h/-s. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate discovery mode requirements
	if hasDiscovery {
		if config.Username == "" || config.Password == "" || config.Domain == "" {
			logln("Error: Discovery mode requires -u <username>, -p <password>, and -d <domain>.")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Validate that at least one input method is provided
	if !hasDiscovery && !hasTargetFile && !hasHostShare {
		logln("Error: Provide -d <domain> with credentials for auto-discovery,")
		logln("       --domain-controller <dc> for explicit DC,")
		logln("       --target-file <file>, OR both -h <host> and -s <share>.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate --discovery-only only works with discovery mode
	if config.DiscoveryOnly && !hasDiscovery {
		logln("Error: --discovery-only/-do requires discovery mode (provide -d <domain> with credentials).")
		flag.Usage()
		os.Exit(1)
	}

	// Warn if -of is used with -do (it will be ignored)
	if config.DiscoveryOnly && len(config.OutputFormats) > 0 {
		logln("[!] Warning: --output-format/-of is ignored in discovery-only mode (-do)")
	}

	// capability-sdk output requires discovery mode (needs SIDs and computer
	// metadata). validateOutputFormats already rewrote any legacy
	// "tabularium" value to "capability-sdk".
	hasCapabilitySDK := false
	for _, f := range config.OutputFormats {
		if f == "capability-sdk" {
			hasCapabilitySDK = true
			break
		}
	}
	if hasCapabilitySDK && !hasDiscovery {
		logln("Error: --output-format capability-sdk requires discovery mode (provide -d <domain> with credentials).")
		flag.Usage()
		os.Exit(1)
	}
	if config.DiscoveryOnly && hasCapabilitySDK {
		var filtered []string
		for _, f := range config.OutputFormats {
			if f != "capability-sdk" {
				filtered = append(filtered, f)
			}
		}
		config.OutputFormats = filtered
	}

	// Validate/create output directory for batch mode
	if isBatchMode && config.SaveOutput {
		info, err := os.Stat(config.OutputFile)
		if err != nil {
			// Directory doesn't exist, create it
			if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
				logf("Error: Failed to create output directory: %s\n", err)
				os.Exit(1)
			}
			logf("[*] Created output directory: %s\n", config.OutputFile)
		} else if !info.IsDir() {
			logf("Error: Output path must be a directory in batch mode: %s\n", config.OutputFile)
			os.Exit(1)
		}
	}

	// Build target list
	var targets []Target
	if hasDiscovery {
		var err error
		// Fetch SIDs if capability-sdk output is requested.
		fetchSIDs := hasCapabilitySDK && !config.DiscoveryOnly
		var discoveryResult *DiscoveryResult
		targets, discoveryResult, err = discoverTargets(config, fetchSIDs)
		if err != nil {
			logf("Error during discovery: %v\n", err)
			os.Exit(1)
		}
		// Store discovery result for capability-sdk output
		config.DiscoveryResult = discoveryResult

		if len(targets) == 0 {
			logln("[*] No accessible shares discovered")
			os.Exit(0)
		}

		// Discovery-only mode: output shares and exit
		if config.DiscoveryOnly {
			outputDiscoveredShares(config, targets)
			if config.ZipOutput {
				if err := zipOutputFiles(config); err != nil {
					logf("[-] Failed to zip output files: %v\n", err)
				}
			}
			os.Exit(0)
		}

		// In normal scan mode with -o, also save discovered shares file
		if config.SaveOutput {
			outputDiscoveredShares(config, targets)
		}
	} else if hasTargetFile {
		var err error
		targets, err = parseTargetFile(config.TargetsFile)
		if err != nil {
			logf("Error parsing target file: %v\n", err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			logln("Error: No valid targets found in target file")
			os.Exit(1)
		}
		logf("[*] Loaded %d targets from %s\n", len(targets), config.TargetsFile)
	} else {
		targets = []Target{{Host: config.Host, Share: config.Share}}
	}

	// Setup global signal handler with context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logln("\nReceived interrupt, cancelling scans... (press Ctrl+C again to force exit)")
			cancel()
		case <-ctx.Done():
			return
		}
		// Second Ctrl+C force-exits
		<-sigChan
		logln("\nForce exit.")
		os.Exit(1)
	}()

	// Scan all targets, collecting results
	tracker := newShareTracker(len(targets))
	config.Tracker = tracker
	tracker.startStdinListener()
	// Start live ticker in default mode when stderr is a terminal
	if !config.Verbose && !config.Debug && isTerminal(os.Stderr) {
		tracker.startTicker()
	}
	defer tracker.stop()

	results := make([]ScanResult, len(targets))
	sem := make(chan struct{}, config.ShareWorkers)
	var wg sync.WaitGroup
	scanStartAll := time.Now()

	logf("[*] Scanning %d shares\n", len(targets))

	for i, target := range targets {
		// Create a copy of config for this target
		targetConfig := config
		targetConfig.Host = target.Host
		targetConfig.Share = target.Share
		targetConfig.DFSPath = target.DFSPath

		// Set output file for batch mode
		if isBatchMode && config.SaveOutput {
			targetConfig.OutputFile = filepath.Join(config.OutputFile,
				fmt.Sprintf("%s__%s.txt", sanitizeFilename(target.Host), sanitizeFilename(target.Share)))
		}

		wg.Add(1)
		go func(idx int, tc Config, t Target, targetNum int) {
			defer wg.Done()

			// Acquire semaphore slot with context escape to avoid deadlock on cancel
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = ScanResult{
					Host:  t.Host,
					Share: t.Share,
					Error: ctx.Err(),
				}
				atomic.AddInt64(&tracker.completed, 1)
				return
			}

			if isBatchMode {
				tc.TargetNum = targetNum
				tc.TotalTargets = len(targets)
			}

			stats, outputPath, err := scanTarget(ctx, tc)
			if stats.MatchCount > 0 {
				atomic.AddInt64(&tracker.findings, int64(stats.MatchCount))
			}
			results[idx] = ScanResult{
				Host:           t.Host,
				Share:          t.Share,
				Error:          err,
				HasFindings:    stats.HasFindings,
				OutputPath:     outputPath,
				TimedOut:       stats.TimedOut,
				FileCount:      stats.FileCount,
				DirCount:       stats.DirCount,
				SkippedFiles:   stats.SkippedFiles,
				MatchCount:     stats.MatchCount,
				SeverityCounts: stats.SeverityCounts,
				RuleCounts:     stats.RuleCounts,
			}
			if err != nil && config.Verbose {
				logf("[-] Failed: //%s/%s - %v\n", t.Host, t.Share, err)
			}
		}(i, targetConfig, target, i+1)
	}
	wg.Wait()
	totalScanTime := time.Since(scanStartAll)

	// Print summary for batch mode
	if isBatchMode {
		printSummary(results, totalScanTime)
	}

	if hasCapabilitySDK && config.DiscoveryResult != nil {
		if err := generateCapabilitySDKOutput(config, results); err != nil {
			logf("[-] Failed to generate capability-sdk output: %v\n", err)
		}
	}

	// Zip output files if requested
	if config.ZipOutput {
		if err := zipOutputFiles(config); err != nil {
			logf("[-] Failed to zip output files: %v\n", err)
		}
	}
}

// scanTarget performs the full scan workflow for a single host/share combination
// targetTag returns a short identifier for log lines, e.g. "[SHAREDATAVM.stsci.edu/VOIP]".
func targetTag(config Config) string {
	return fmt.Sprintf("[%s/%s]", config.Host, config.Share)
}

// Returns: hasFindings (whether secrets were found), outputPath (path to output file if saved), error
func scanTarget(ctx context.Context, config Config) (ScanStats, string, error) {
	if ctx.Err() != nil {
		if config.Tracker != nil {
			atomic.AddInt64(&config.Tracker.completed, 1)
		}
		return ScanStats{}, "", ctx.Err()
	}

	tag := targetTag(config)
	if config.Verbose {
		logf("%s Connecting...\n", tag)
	}

	// Register as connecting so status shows this share
	if config.Tracker != nil {
		config.Tracker.registerConnecting(tag)
	}

	conn, session, share, err := smbConnect(ctx, config)
	if err != nil {
		if config.Tracker != nil {
			config.Tracker.deregister(tag)
		}
		return ScanStats{}, "", err
	}
	defer func() {
		// Cap teardown to 10s so slow Umount/Logoff calls don't
		// starve the worker pool (the root cause of "waiting for
		// worker slot" hangs).
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		share.Umount()
		session.Logoff()
		conn.Close()
	}()

	if config.Verbose {
		if config.TotalTargets > 0 {
			logf("%s Connected via SMB, target %d/%d\n", tag, config.TargetNum, config.TotalTargets)
		} else {
			logf("%s Connected via SMB\n", tag)
		}
	}

	// Apply per-share time limit if configured
	scanCtx := ctx
	if config.MaxShareTime > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, time.Duration(config.MaxShareTime)*time.Minute)
		defer cancel()
		if config.Verbose {
			logf("%s Time limit: %d minutes per share\n", tag, config.MaxShareTime)
		}
	}

	if config.Verbose {
		logf("%s Running Titus scan...\n", tag)
	}
	scanStart := time.Now()
	stats, err := runTitusScanSMB(scanCtx, config, share)
	scanDuration := time.Since(scanStart)
	if err != nil {
		return stats, "", fmt.Errorf("scan failed: %w", err)
	}

	if config.Verbose {
		logf("%s Scan complete (%s)\n", tag, scanDuration.Round(time.Millisecond))
	}
	return stats, config.OutputFile, nil
}

// parseTargetFile reads targets from a file, supporting both CSV and UNC path formats
func parseTargetFile(filename string) ([]Target, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []Target
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		host, share, err := parseTargetLine(line)
		if err != nil {
			logf("[!] Warning: Skipping invalid line %d: %s (%v)\n", lineNum, line, err)
			continue
		}

		targets = append(targets, Target{Host: host, Share: share})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// parseTargetLine parses a single line as either CSV (host,share) or UNC path (\\host\share)
func parseTargetLine(line string) (host, share string, err error) {
	// UNC path format: \\host\share or \\\\host\\share (escaped backslashes)
	if strings.HasPrefix(line, "\\") {
		// Normalize escaped backslashes (\\\\) to single backslashes (\\)
		normalized := line
		for strings.Contains(normalized, "\\\\") {
			normalized = strings.ReplaceAll(normalized, "\\\\", "\\")
		}

		// Remove leading backslashes and split
		trimmed := strings.TrimLeft(normalized, "\\")
		parts := strings.SplitN(trimmed, "\\", 2)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid UNC path format")
		}
		return parts[0], parts[1], nil
	}

	// CSV format: host,share
	parts := strings.SplitN(line, ",", 2)
	if len(parts) == 2 {
		host = strings.TrimSpace(parts[0])
		share = strings.TrimSpace(parts[1])
		if host == "" || share == "" {
			return "", "", fmt.Errorf("empty host or share in CSV")
		}
		return host, share, nil
	}

	return "", "", fmt.Errorf("invalid format (expected 'host,share' or '\\\\host\\share')")
}

func parseArgs(version string) Config {
	var config Config
	var additionalExts string
	var additionalFolders string
	var keywords string
	var excludedShares string
	var outputFormats string
	var showVersion bool

	// Pre-process -o flag (supports optional argument) before flag.Parse()
	config.SaveOutput, config.OutputFile, os.Args = extractOutputFlag(os.Args)

	// Target selection (mutually exclusive: --domain-controller OR --target-file OR -h/-s)
	flag.StringVar(&config.DomainController, "domain-controller", "", "Domain controller for AD share discovery")
	flag.StringVar(&config.DomainController, "dc", "", "Domain controller for AD share discovery (shorthand)")
	flag.StringVar(&config.TargetsFile, "target-file", "", "File containing targets (CSV or UNC paths)")
	flag.StringVar(&config.TargetsFile, "tf", "", "File containing targets (shorthand)")
	flag.StringVar(&config.Host, "host", "", "Target IP address or hostname")
	flag.StringVar(&config.Host, "h", "", "Target IP address or hostname (shorthand)")
	flag.StringVar(&config.Share, "share", "", "SMB share name")
	flag.StringVar(&config.Share, "s", "", "SMB share name (shorthand)")

	// Authentication
	flag.StringVar(&config.Username, "username", "", "Username for authentication (optional)")
	flag.StringVar(&config.Username, "u", "", "Username for authentication (shorthand)")
	flag.StringVar(&config.Password, "password", "", "Password for authentication (optional)")
	flag.StringVar(&config.Password, "p", "", "Password for authentication (shorthand)")
	flag.StringVar(&config.Domain, "domain", "", "Domain for authentication (optional)")
	flag.StringVar(&config.Domain, "d", "", "Domain for authentication (shorthand)")

	// Exclusion options
	var showDefaultExclusions bool
	flag.BoolVar(&config.NoExclusion, "no-default-exclusions", false, "Disable all default exclusions (scan all files/folders)")
	flag.BoolVar(&showDefaultExclusions, "show-default-exclusions", false, "Show all default exclusions and exit")
	flag.StringVar(&additionalExts, "exclude-extensions", "", "Additional file extensions to exclude (comma-separated)")
	flag.StringVar(&additionalExts, "xe", "", "Additional file extensions to exclude (shorthand)")
	flag.StringVar(&additionalFolders, "exclude-directories", "", "Additional directories to exclude (comma-separated)")
	flag.StringVar(&additionalFolders, "xd", "", "Additional directories to exclude (shorthand)")
	flag.StringVar(&excludedShares, "exclude-shares", "", "Share names to exclude during discovery (comma-separated)")
	flag.StringVar(&excludedShares, "xs", "", "Share names to exclude during discovery (shorthand)")
	flag.StringVar(&keywords, "keywords", "", "Filename substrings to always include in scanning (comma-separated)")
	flag.StringVar(&keywords, "kw", "", "Filename substrings to always include (shorthand)")

	// Output options (note: -o is handled manually after flag.Parse for optional argument support)
	flag.StringVar(&outputFormats, "output-format", "", "Output formats to save (comma-separated: txt,json,jsonl,sarif,capability-sdk)")
	flag.StringVar(&outputFormats, "of", "", "Output formats to save (shorthand)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Show per-share progress (connections, scan lifecycle)")
	flag.BoolVar(&config.Verbose, "v", false, "Show per-share progress (shorthand)")
	flag.BoolVar(&config.Debug, "debug", false, "Show per-file diagnostics (skipped files, errors, chunking)")
	flag.BoolVar(&config.Debug, "de", false, "Show per-file diagnostics (shorthand)")
	var wantTimestamps bool
	flag.BoolVar(&wantTimestamps, "timestamp", false, "Prepend timestamp to every log line")
	flag.BoolVar(&wantTimestamps, "ts", false, "Prepend timestamp to every log line (shorthand)")

	// Discovery options (LDAPS and channel binding)
	flag.BoolVar(&config.UseLDAPS, "ldaps", false, "Force LDAPS (port 636); by default all methods are auto-negotiated")
	flag.BoolVar(&config.ChannelBinding, "channel-binding", false, "Require NTLMv2+CBT on LDAPS; refuse simple-bind fallback (prevents cleartext credential exposure)")
	flag.StringVar(&config.DNSServer, "dns-server", "", "Custom DNS server IP for hostname resolution")
	flag.StringVar(&config.DNSServer, "dns", "", "Custom DNS server IP (shorthand)")
	flag.BoolVar(&config.DiscoveryOnly, "discovery-only", false, "Discovery only: output shares in UNC format without scanning")
	flag.BoolVar(&config.DiscoveryOnly, "do", false, "Discovery only (shorthand)")
	flag.BoolVar(&config.NoDFS, "no-dfs", false, "Disable DFS namespace awareness (skip DFS deduplication)")

	// Scan options
	var maxScanSizeMB int
	flag.IntVar(&maxScanSizeMB, "max-scan-size", 5, "Maximum file size to scan in MB (0 = no limit, default: 5)")
	flag.IntVar(&maxScanSizeMB, "ms", 5, "Maximum file size to scan in MB (shorthand)")
	flag.IntVar(&config.MaxDepth, "max-depth", 0, "Maximum directory recursion depth (0 = unlimited)")
	flag.IntVar(&config.MaxDepth, "md", 0, "Maximum directory recursion depth (shorthand)")
	flag.IntVar(&config.MaxShareTime, "max-share-time", 45, "Maximum time per share in minutes (0 = indefinite, default: 45)")
	flag.IntVar(&config.MaxShareTime, "mst", 45, "Maximum time per share in minutes (shorthand)")
	flag.IntVar(&config.MaxFilesPerDir, "max-files-per-dir", 0, "Maximum files to scan per directory (0 = unlimited)")
	flag.IntVar(&config.MaxFilesPerDir, "mf", 0, "Maximum files to scan per directory (shorthand)")
	var fullScan bool
	flag.BoolVar(&fullScan, "full", false, "Full scan: disable quick-mode allowlist and tighter limits (scan all file types, unlimited depth/time/files-per-dir by default)")
	flag.BoolVar(&fullScan, "f", false, "Full scan (shorthand)")
	flag.BoolVar(&config.ZipOutput, "zip", false, "Zip txt/json output files into a single archive and delete originals")
	flag.BoolVar(&config.ZipOutput, "z", false, "Zip txt/json output files (shorthand)")
	flag.BoolVar(&config.ExtractBinary, "extract", false, "Extract and scan text from binary files (docx, xlsx, pptx, pdf, archives, etc.)")
	flag.BoolVar(&config.ExtractBinary, "x", false, "Extract and scan text from binary files (shorthand)")

	// Concurrency options
	flag.IntVar(&config.ShareWorkers, "share-workers", 60, "Number of parallel share workers")
	flag.IntVar(&config.ShareWorkers, "jt", 60, "Number of parallel share workers (shorthand)")
	flag.IntVar(&config.FileWorkers, "file-workers", 0, "Number of parallel file scanning goroutines per share (default: NumCPU)")
	flag.IntVar(&config.FileWorkers, "jf", 0, "Number of parallel file scanning goroutines per share (shorthand)")

	flag.BoolVar(&showVersion, "version", false, "Print version and exit")

	flag.Usage = func() {
		logf("Usage: %s [options]\n\n", os.Args[0])
		logln("A tool to mount SMB shares and scan for secrets using Titus")
		logln("\nTarget Selection (choose one):")
		logln("  -d <domain> -u -p         Auto-discover DC and scan all accessible AD shares")
		logln("  --domain-controller, -dc  Explicitly specify domain controller (optional)")
		logln("  --target-file, -tf        File with targets (CSV: host,share or UNC: \\\\host\\share)")
		logln("  -host, -h                 Target IP address or hostname  }  Required together")
		logln("  -share, -s                SMB share name                  }  if not using discovery/-tf")
		logln("\nAuthentication:")
		logln("  -username, -u       Username for authentication (required for discovery)")
		logln("  -password, -p       Password for authentication (required for discovery)")
		logln("  -domain, -d         Domain for authentication (required for discovery, e.g., corp.local)")
		logln("\nDiscovery Options (auto-negotiated by default: LDAPS+CB → LDAPS → LDAP):")
		logln("  --ldaps             Force LDAPS only (skip plain LDAP fallback)")
		logln("  --channel-binding   Require NTLMv2 with RFC 5929 channel binding; no simple-bind fallback")
		logln("  --dns-server, -dns  Custom DNS server IP for DC discovery and hostname resolution")
		logln("  --discovery-only, -do  Discovery only: output shares in UNC format, skip scanning")
		logln("  --no-dfs              Disable DFS namespace awareness (skip DFS deduplication)")
		logln("\nFiltering (supports regex patterns):")
		logln("  --show-default-exclusions             Show all default exclusions and exit")
		logln("  --no-default-exclusions       Disable all default exclusions (scan everything)")
		logln("  --exclude-extensions, -xe     Additional file extensions to exclude (comma-separated)")
		logln("  --exclude-directories, -xd    Additional directories to exclude (comma-separated)")
		logln("  --exclude-shares, -xs         Share names to exclude during discovery (comma-separated)")
		logln("\nOutput:")
		logln("  -o <path>           Single target: output file (default: <host>_<share>.txt)")
		logln("                      Batch mode: output directory (must exist)")
		logln("  --output-format, -of  Output formats to save (comma-separated: txt,json,jsonl,sarif,capability-sdk)")
		logln("                        Default: txt. Requires -o flag.")
		logln("  --zip, -z           Zip all txt/json output files and delete originals. Requires -o flag.")
		logln("  -v, --verbose       Show per-share progress (connections, scan lifecycle)")
		logln("  -de, --debug        Show per-file diagnostics (skipped files, errors, chunking)")
		logln("\nScanning:")
		logln("  --extract, -x            Extract and scan text from binary files (docx, xlsx, pdf, etc.)")
		logln("  --full, -f               Full scan: disable quick-mode (default is quick: high-value files only, depth 5, 15 min/share, 200 files/dir)")
		logln("  --max-scan-size, -ms     Max file size to scan in MB (default: 5, 0 = no limit)")
		logln("  --max-depth, -md         Max directory recursion depth (default: 0 = unlimited)")
		logln("  --max-share-time, -mst   Max time per share in minutes (default: 45, 0 = indefinite)")
		logln("  --max-files-per-dir, -mf Max files to scan per directory (default: 0 = unlimited)")
		logln("\nConcurrency:")
		logln("  --share-workers, -jt  Parallel share workers (default: 60)")
		logf("  --file-workers, -jf   Parallel file scanners per share (default: %d = NumCPU)\n", runtime.NumCPU())
		logln("\nBuilt-in Exclusions (enabled by default):")
		logln("  Shares:")
		logf("    %s\n", strings.Join(defaultExcludedShares, ", "))
		logln("  File Extensions:")
		logf("    %s\n", strings.Join(defaultExcludedExtensions, ", "))
		logln("  Directories:")
		logf("    %s\n", strings.Join(defaultExcludedFolders, ", "))
		logln("\nExamples:")
		logln("  # Auto-discover DC and scan all accessible shares in domain")
		logf("  %s -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		logln("  # Same as above, with explicit DC (skips auto-discovery)")
		logf("  %s -dc dc01.corp.local -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		logln("  # Auto-discovery with custom DNS server")
		logf("  %s -u admin -p secret123 -d corp.local -dns 10.0.0.1\n\n", os.Args[0])
		logln("  # Discovery with output to directory")
		logf("  %s -u admin -p secret123 -d corp.local -o ./results/\n\n", os.Args[0])
		logln("  # Discovery only (no scanning), output UNC paths to stdout")
		logf("  %s -u admin -p secret123 -d corp.local -do\n\n", os.Args[0])
		logln("  # Single target scan")
		logf("  %s -h 192.168.1.100 -s public\n\n", os.Args[0])
		logln("  # Batch scan from target file")
		logf("  %s -tf targets.txt -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		logln("Target file format (one per line):")
		logln("  192.168.1.10,share1       # CSV format")
		logln("  \\\\fileserver\\backup$      # UNC path")
	}

	flag.Parse()

	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	if config.ChannelBinding {
		logln("Notice: --channel-binding semantics changed. It now REQUIRES NTLMv2+CBT and refuses simple-bind fallback. Drop the flag to restore the previous auto-negotiation behavior (now the default).")
	}

	// Quick mode is the default; --full disables it.
	config.QuickMode = !fullScan

	// Quick mode: apply defaults for depth and share time unless explicitly overridden
	if config.QuickMode {
		explicitFlags := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

		if !explicitFlags["max-depth"] && !explicitFlags["md"] {
			config.MaxDepth = 5
		}
		if !explicitFlags["max-share-time"] && !explicitFlags["mst"] {
			config.MaxShareTime = 15
		}
		if !explicitFlags["max-files-per-dir"] && !explicitFlags["mf"] {
			config.MaxFilesPerDir = 200
		}
	}

	// Apply concurrency defaults
	if config.FileWorkers <= 0 {
		config.FileWorkers = max(runtime.NumCPU()*4, 16) // I/O-bound: 4x CPU count, min 16
	}
	if config.ShareWorkers <= 0 {
		config.ShareWorkers = 1
	}

	// Convert max scan size from MB to bytes (0 = no limit)
	if maxScanSizeMB > 0 {
		config.MaxScanSize = int64(maxScanSizeMB) * 1024 * 1024
	}

	// Show exclusions and exit if requested
	if showDefaultExclusions {
		fmt.Println("Default Excluded Shares (regex patterns):")
		for _, s := range defaultExcludedShares {
			fmt.Printf("  %s\n", s)
		}
		fmt.Println("\nDefault Excluded Extensions:")
		for _, e := range defaultExcludedExtensions {
			fmt.Printf("  %s\n", e)
		}
		fmt.Println("\nDefault Excluded Directories:")
		for _, d := range defaultExcludedFolders {
			fmt.Printf("  %s\n", d)
		}
		os.Exit(0)
	}

	// Parse comma-separated lists
	if additionalExts != "" {
		config.AdditionalExts = strings.Split(additionalExts, ",")
		// Trim spaces
		for i, ext := range config.AdditionalExts {
			config.AdditionalExts[i] = strings.TrimSpace(ext)
		}
	}

	if additionalFolders != "" {
		config.AdditionalFolders = strings.Split(additionalFolders, ",")
		// Trim spaces
		for i, folder := range config.AdditionalFolders {
			config.AdditionalFolders[i] = strings.TrimSpace(folder)
		}
	}

	if keywords != "" {
		for _, kw := range strings.Split(keywords, ",") {
			kw = strings.TrimSpace(strings.ToLower(kw))
			if kw != "" {
				config.Keywords = append(config.Keywords, kw)
			}
		}
	}

	// Parse excluded shares (start with defaults, add user-specified)
	if !config.NoExclusion {
		config.ExcludedShares = append(config.ExcludedShares, defaultExcludedShares...)
	}
	if excludedShares != "" {
		for _, share := range strings.Split(excludedShares, ",") {
			config.ExcludedShares = append(config.ExcludedShares, strings.TrimSpace(share))
		}
	}

	// Parse output formats
	formats, err := validateOutputFormats(outputFormats)
	if err != nil {
		logf("Error: %v\n", err)
		os.Exit(1)
	}
	config.OutputFormats = append(config.OutputFormats, formats...)

	// Generate default output filename if -o was used without a filename (single target mode only)
	// For batch mode (including auto-discovery), the OutputFile is treated as a directory and validated in main()
	// Auto-discovery mode is when credentials are provided without explicit targets
	isAutoDiscovery := config.Username != "" && config.Password != "" && config.Domain != "" && config.Host == "" && config.TargetsFile == ""
	if config.SaveOutput && config.TargetsFile == "" && config.DomainController == "" && !isAutoDiscovery {
		if config.OutputFile == "" {
			// -o with no argument: use default filename
			config.OutputFile = generateOutputFilename(config.Host, config.Share)
		} else {
			// Check if OutputFile is a directory (ends with / or is an existing directory)
			isDir := strings.HasSuffix(config.OutputFile, "/") || strings.HasSuffix(config.OutputFile, string(os.PathSeparator))
			if !isDir {
				if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
					isDir = true
				}
			}
			if isDir {
				// Create directory if it doesn't exist
				if _, err := os.Stat(config.OutputFile); os.IsNotExist(err) {
					if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
						logf("Error: Failed to create output directory: %s\n", err)
						os.Exit(1)
					}
					logf("[*] Created output directory: %s\n", config.OutputFile)
				}
				// Append default filename to directory
				config.OutputFile = filepath.Join(config.OutputFile, generateOutputFilename(config.Host, config.Share))
			}
		}
	}

	// Validate --zip requires -o
	if config.ZipOutput && !config.SaveOutput {
		logln("Error: --zip/-z requires the -o flag to specify an output path.")
		flag.Usage()
		os.Exit(1)
	}

	// Enable interesting exclusions CSV when output is being saved
	config.InterestingExcl = config.SaveOutput

	// Activate timestamps after arg validation / help text is done
	timestampMode = wantTimestamps

	return config
}

func generateOutputFilename(host, share string) string {
	return fmt.Sprintf("%s__%s.txt", sanitizeFilename(host), sanitizeFilename(share))
}

func extractOutputFlag(args []string) (bool, string, []string) {
	var newArgs []string
	saveOutput := false
	outputFile := ""

	for i := 0; i < len(args); i++ {
		if args[i] == "-o" {
			saveOutput = true
			// Check if next argument exists and is not a flag
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				outputFile = args[i+1]
				i++ // Skip the filename argument
			}
			continue
		}
		newArgs = append(newArgs, args[i])
	}

	return saveOutput, outputFile, newArgs
}
