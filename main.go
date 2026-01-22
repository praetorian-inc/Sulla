package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const dockerImage = "ghcr.io/praetorian-inc/noseyparker:latest"

type Config struct {
	Host               string
	Share              string
	Username           string
	Password           string
	Domain             string
	MountPath          string
	NoExclusion        bool
	AdditionalExts     []string
	AdditionalFolders  []string
	SaveOutput         bool
	OutputFile         string
	Verbose            bool
	UseDocker          bool
	TargetsFile        string
}

// Target represents a single host/share combination to scan
type Target struct {
	Host  string
	Share string
}

// ScanResult holds the outcome of scanning a single target
type ScanResult struct {
	Host  string
	Share string
	Error error
}

// Default file extensions to exclude (binaries, media, archives, etc.)
var defaultExcludedExtensions = []string{
	// Executables and libraries
	"exe", "dll", "so", "dylib", "bin", "app", "sys", "drv",
	// Archives
	"zip", "tar", "gz", "bz2", "xz", "7z", "rar", "iso", "dmg",
	// Media files
	"jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp",
	"mp3", "mp4", "avi", "mov", "mkv", "flv", "wmv", "wav", "flac",
	// Office documents (binary formats)
	"doc", "xls", "ppt", "docx", "xlsx", "pptx", "pdf",
	// Compiled/Object files
	"pyc", "pyo", "class", "o", "obj", "a", "lib",
	// Database files
	"db", "sqlite", "sqlite3", "mdb", "accdb",
	// Fonts
	"ttf", "otf", "woff", "woff2", "eot",
	// Other binary formats
	"dat", "pak", "cab", "msi", "deb", "rpm",
}

// Default folders to exclude (system directories, Windows paths, etc.)
var defaultExcludedFolders = []string{
	// Windows system folders
	"Program Files", "Program Files (x86)", "Windows", "System32",
	"SysWOW64", "WinSxS", "$Recycle.Bin", "ProgramData",
	// macOS system folders
	"System", "Library", "Applications",
	// Linux system folders
	"proc", "sys", "dev", "boot",
	// Common large/noisy folders
	"node_modules", ".git", "__pycache__", "vendor",
}

func main() {
	config := parseArgs()

	// Validate target selection: either --target-file OR (-h AND -s), but not both
	hasTargetFile := config.TargetsFile != ""
	hasHostShare := config.Host != "" && config.Share != ""
	hasPartialHostShare := config.Host != "" || config.Share != ""

	if hasTargetFile && hasPartialHostShare {
		fmt.Fprintln(os.Stderr, "Error: Cannot use --target-file with -h/-s. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}

	if !hasTargetFile && !hasHostShare {
		fmt.Fprintln(os.Stderr, "Error: Provide either --target-file <file> OR both -h <host> and -s <share>.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate output directory for batch mode
	if hasTargetFile && config.SaveOutput {
		info, err := os.Stat(config.OutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Output directory does not exist: %s\n", config.OutputFile)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: Output path must be a directory when using --target-file: %s\n", config.OutputFile)
			os.Exit(1)
		}
	}

	// Check if noseyparker is available (native or Docker)
	if _, err := exec.LookPath("noseyparker"); err != nil {
		// Native not found, try Docker
		if dockerAvailable() {
			config.UseDocker = true
			fmt.Fprintln(os.Stderr, "[*] noseyparker not in PATH, using Docker")
		} else {
			fmt.Fprintln(os.Stderr, "Error: noseyparker not found in PATH nor via Docker")
			fmt.Fprintln(os.Stderr, "Install noseyparker: https://github.com/praetorian-inc/noseyparker")
			fmt.Fprintln(os.Stderr, "To install via Docker, run:")
			fmt.Fprintln(os.Stderr, "  docker pull ghcr.io/praetorian-inc/noseyparker:latest")
			os.Exit(1)
		}
	}

	// Build target list
	var targets []Target
	if hasTargetFile {
		var err error
		targets, err = parseTargetFile(config.TargetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing target file: %v\n", err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "Error: No valid targets found in target file")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[*] Loaded %d targets from %s\n", len(targets), config.TargetsFile)
	} else {
		targets = []Target{{Host: config.Host, Share: config.Share}}
	}

	// Scan all targets, collecting results
	var results []ScanResult
	for i, target := range targets {
		if hasTargetFile {
			fmt.Fprintf(os.Stderr, "\n[*] === Target %d/%d: //%s/%s ===\n", i+1, len(targets), target.Host, target.Share)
		}

		// Create a copy of config for this target
		targetConfig := config
		targetConfig.Host = target.Host
		targetConfig.Share = target.Share

		// Set output file for batch mode
		if hasTargetFile && config.SaveOutput {
			targetConfig.OutputFile = filepath.Join(config.OutputFile,
				fmt.Sprintf("%s_%s.txt", sanitizeFilename(target.Host), target.Share))
		}

		err := scanTarget(targetConfig)
		results = append(results, ScanResult{
			Host:  target.Host,
			Share: target.Share,
			Error: err,
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed: //%s/%s - %v\n", target.Host, target.Share, err)
		}
	}

	// Print summary for batch mode
	if hasTargetFile {
		printSummary(results)
	}
}

// scanTarget performs the full scan workflow for a single host/share combination
func scanTarget(config Config) error {
	// Create temporary mount point
	mountPath, err := createMountPoint()
	if err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	config.MountPath = mountPath

	// Setup signal handler for cleanup
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	cleanupDone := make(chan struct{})
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, cleaning up...")
			cleanup(config)
			os.Exit(1)
		case <-cleanupDone:
			return
		}
	}()
	defer func() {
		signal.Stop(sigChan)
		close(cleanupDone)
	}()

	// Mount the SMB share
	fmt.Fprintf(os.Stderr, "[*] Mounting SMB share //%s/%s...\n", config.Host, config.Share)
	if err := mountSMB(config); err != nil {
		cleanup(config)
		return fmt.Errorf("mount failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[+] Successfully mounted to %s\n", config.MountPath)

	// Run noseyparker
	fmt.Fprintln(os.Stderr, "[*] Running noseyparker scan...")
	if err := runNoseyparker(config); err != nil {
		cleanup(config)
		return fmt.Errorf("scan failed: %w", err)
	}

	// Cleanup
	cleanup(config)
	fmt.Fprintln(os.Stderr, "[+] Scan complete")
	return nil
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
			fmt.Fprintf(os.Stderr, "[!] Warning: Skipping invalid line %d: %s (%v)\n", lineNum, line, err)
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

// sanitizeFilename replaces characters that are problematic in filenames
func sanitizeFilename(s string) string {
	// Replace dots and other problematic characters with underscores
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}

// printSummary displays a summary of all scan results
func printSummary(results []ScanResult) {
	var successful, failed int
	var failedTargets []ScanResult

	for _, r := range results {
		if r.Error == nil {
			successful++
		} else {
			failed++
			failedTargets = append(failedTargets, r)
		}
	}

	fmt.Fprintln(os.Stderr, "\n=== Scan Summary ===")
	fmt.Fprintf(os.Stderr, "Total targets: %d\n", len(results))
	fmt.Fprintf(os.Stderr, "Successful:    %d\n", successful)
	fmt.Fprintf(os.Stderr, "Failed:        %d\n", failed)

	if len(failedTargets) > 0 {
		fmt.Fprintln(os.Stderr, "\nFailed targets:")
		for _, r := range failedTargets {
			fmt.Fprintf(os.Stderr, "  - //%s/%s : %v\n", r.Host, r.Share, r.Error)
		}
	}
}

func parseArgs() Config {
	var config Config
	var additionalExts string
	var additionalFolders string

	// Pre-process -o flag (supports optional argument) before flag.Parse()
	config.SaveOutput, config.OutputFile, os.Args = extractOutputFlag(os.Args)

	// Target selection (mutually exclusive: --target-file OR -h/-s)
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
	flag.BoolVar(&config.NoExclusion, "no-exclusion", false, "Disable all default exclusions (scan all files/folders)")
	flag.StringVar(&additionalExts, "exclude", "", "Additional file extensions to exclude (comma-separated, e.g., 'log,tmp,bak')")
	flag.StringVar(&additionalFolders, "exclude-folder", "", "Additional folder names to exclude (comma-separated, e.g., 'temp,cache')")

	// Output options (note: -o is handled manually after flag.Parse for optional argument support)
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output (show excluded files)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A tool to mount SMB shares and scan for secrets using Noseyparker")
		fmt.Fprintln(os.Stderr, "\nTarget Selection (choose one):")
		fmt.Fprintln(os.Stderr, "  --target-file, -tf  File with targets (CSV: host,share or UNC: \\\\host\\share)")
		fmt.Fprintln(os.Stderr, "  -host, -h           Target IP address or hostname  }  Required together")
		fmt.Fprintln(os.Stderr, "  -share, -s          SMB share name                  }  if not using -tf")
		fmt.Fprintln(os.Stderr, "\nAuthentication:")
		fmt.Fprintln(os.Stderr, "  -username, -u       Username for authentication")
		fmt.Fprintln(os.Stderr, "  -password, -p       Password for authentication")
		fmt.Fprintln(os.Stderr, "  -domain, -d         Domain for authentication")
		fmt.Fprintln(os.Stderr, "\nFiltering:")
		fmt.Fprintln(os.Stderr, "  -no-exclusion       Disable all default exclusions (scan everything)")
		fmt.Fprintln(os.Stderr, "  -exclude            Additional file extensions to exclude (comma-separated)")
		fmt.Fprintln(os.Stderr, "  -exclude-folder     Additional folder names to exclude (comma-separated)")
		fmt.Fprintln(os.Stderr, "\nOutput:")
		fmt.Fprintln(os.Stderr, "  -o <path>           Single target: output file (default: <host>_<share>.txt)")
		fmt.Fprintln(os.Stderr, "                      Batch mode: output directory (must exist)")
		fmt.Fprintln(os.Stderr, "  -v                  Verbose output (show excluded files)")
		fmt.Fprintln(os.Stderr, "\nBuilt-in Exclusions (enabled by default):")
		fmt.Fprintln(os.Stderr, "  File Extensions:")
		fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(defaultExcludedExtensions, ", "))
		fmt.Fprintln(os.Stderr, "  Folders:")
		fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(defaultExcludedFolders, ", "))
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  # Single target scan")
		fmt.Fprintf(os.Stderr, "  %s -h 192.168.1.100 -s public\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Batch scan from target file")
		fmt.Fprintf(os.Stderr, "  %s --target-file targets.txt -u admin -p secret123\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Batch scan with output to directory")
		fmt.Fprintf(os.Stderr, "  %s -tf targets.txt -o ./results/ -u admin -p secret123\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # With domain credentials")
		fmt.Fprintf(os.Stderr, "  %s -h dc01.corp.local -s SYSVOL -u admin -p secret123 -d CORP\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Target file format (one per line):")
		fmt.Fprintln(os.Stderr, "  192.168.1.10,share1       # CSV format")
		fmt.Fprintln(os.Stderr, "  \\\\fileserver\\backup$      # UNC path")
		fmt.Fprintln(os.Stderr, "  # Comments start with #")
	}

	flag.Parse()

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

	// Generate default output filename if -o was used without a filename (single target mode only)
	// For batch mode, the OutputFile is treated as a directory and validated in main()
	if config.SaveOutput && config.OutputFile == "" && config.TargetsFile == "" {
		config.OutputFile = generateOutputFilename(config.Host, config.Share)
	}

	return config
}

func generateOutputFilename(host, share string) string {
	// Replace dots with underscores in host
	sanitizedHost := strings.ReplaceAll(host, ".", "_")
	return fmt.Sprintf("%s_%s.txt", sanitizedHost, share)
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

func createMountPoint() (string, error) {
	if runtime.GOOS == "windows" {
		// On Windows, we'll use a drive letter or UNC path directly
		// Return empty - we'll handle differently
		return "", nil
	}

	// On Linux/Unix, create a temp directory
	tmpDir, err := os.MkdirTemp("", "smb-scanner-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	return tmpDir, nil
}

func mountSMB(config Config) error {
	if runtime.GOOS == "windows" {
		return mountSMBWindows(config)
	} else if runtime.GOOS == "darwin" {
		return mountSMBMacOS(config)
	}
	return mountSMBLinux(config)
}

func dockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

func resolveHostToIP(host string) string {
	// If it's already an IP address, return as-is
	if net.ParseIP(host) != nil {
		return host
	}

	// Try to resolve hostname to IP
	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		return addrs[0]
	}

	// If resolution fails, return original host
	return host
}

func mountSMBLinux(config Config) error {
	// Build mount options
	uncPath := fmt.Sprintf("//%s/%s", config.Host, config.Share)

	var baseOpts []string

	if config.Username != "" {
		baseOpts = append(baseOpts, fmt.Sprintf("username=%s", config.Username))
	} else {
		baseOpts = append(baseOpts, "guest")
	}

	if config.Password != "" {
		baseOpts = append(baseOpts, fmt.Sprintf("password=%s", config.Password))
	}

	if config.Domain != "" {
		baseOpts = append(baseOpts, fmt.Sprintf("domain=%s", config.Domain))
	}

	// Add common options for better compatibility
	baseOpts = append(baseOpts, "ro") // Read-only for safety
	baseOpts = append(baseOpts, "nounix") // Disable Unix extensions
	baseOpts = append(baseOpts, "noserverino") // Don't use server-assigned inode numbers

	// Resolve hostname to IP and pass to mount.cifs via ip= option
	// This helps when kernel CIFS has DNS resolution issues
	resolvedIP := resolveHostToIP(config.Host)
	baseOpts = append(baseOpts, fmt.Sprintf("ip=%s", resolvedIP))

	// Try different SMB versions (Impacket supports 2.0, try that first)
	versions := []string{"2.0", "2.1", "3.0", "1.0"}

	var lastErr error
	var lastOutput string

	for _, version := range versions {
		mountOpts := make([]string, len(baseOpts))
		copy(mountOpts, baseOpts)
		mountOpts = append(mountOpts, fmt.Sprintf("vers=%s", version))

		optString := strings.Join(mountOpts, ",")

		cmd := exec.Command("mount", "-t", "cifs", uncPath, config.MountPath, "-o", optString)
		output, err := cmd.CombinedOutput()
		if err == nil {
			fmt.Fprintf(os.Stderr, "[+] Successfully mounted using SMB %s\n", version)
			return nil
		}

		lastErr = err
		lastOutput = string(output)

		// If we get a protocol negotiation error, try next version
		if strings.Contains(lastOutput, "Protocol negotiation failed") ||
		   strings.Contains(lastOutput, "Connection refused") ||
		   strings.Contains(lastOutput, "could not connect") {
			continue
		}

		// If it's a different error (auth, permission, etc), stop trying
		break
	}

	// All versions failed
	return fmt.Errorf("mount failed: %v\nOutput: %s\nNote: This may require root privileges. Try running with sudo.", lastErr, lastOutput)
}

func mountSMBMacOS(config Config) error {
	// Build SMB URL for macOS
	// Format: //[DOMAIN;]username[:password]@server/share
	var smbURL string

	if config.Username != "" {
		auth := config.Username
		if config.Domain != "" {
			auth = fmt.Sprintf("%s;%s", config.Domain, config.Username)
		}
		if config.Password != "" {
			auth = fmt.Sprintf("%s:%s", auth, config.Password)
		}
		smbURL = fmt.Sprintf("//%s@%s/%s", auth, config.Host, config.Share)
	} else {
		// Guest access
		smbURL = fmt.Sprintf("//%s/%s", config.Host, config.Share)
	}

	// Use mount_smbfs (macOS-specific SMB mount command)
	cmd := exec.Command("mount_smbfs", "-o", "ro", smbURL, config.MountPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount_smbfs failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

func mountSMBWindows(config Config) error {
	uncPath := fmt.Sprintf("\\\\%s\\%s", config.Host, config.Share)

	// Build net use command
	args := []string{"use", uncPath}

	if config.Password != "" {
		args = append(args, config.Password)
	}

	if config.Username != "" {
		user := config.Username
		if config.Domain != "" {
			user = fmt.Sprintf("%s\\%s", config.Domain, config.Username)
		}
		args = append(args, "/user:"+user)
	}

	cmd := exec.Command("net", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("net use failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

func buildIgnorePatterns(config Config) []string {
	var patterns []string

	// Add default exclusions unless disabled
	if !config.NoExclusion {
		// Add file extension patterns
		for _, ext := range defaultExcludedExtensions {
			patterns = append(patterns, fmt.Sprintf("**/*.%s", ext))
		}

		// Add folder patterns
		for _, folder := range defaultExcludedFolders {
			patterns = append(patterns, fmt.Sprintf("**/%s/**", folder))
		}
	}

	// Add additional custom extensions
	for _, ext := range config.AdditionalExts {
		patterns = append(patterns, fmt.Sprintf("**/*.%s", ext))
	}

	// Add additional custom folders
	for _, folder := range config.AdditionalFolders {
		patterns = append(patterns, fmt.Sprintf("**/%s/**", folder))
	}

	return patterns
}

func getExcludedExtensions(config Config) []string {
	var exts []string
	if !config.NoExclusion {
		exts = append(exts, defaultExcludedExtensions...)
	}
	exts = append(exts, config.AdditionalExts...)
	return exts
}

func getExcludedFolders(config Config) []string {
	var folders []string
	if !config.NoExclusion {
		folders = append(folders, defaultExcludedFolders...)
	}
	folders = append(folders, config.AdditionalFolders...)
	return folders
}

func matchesExtension(filename string, extensions []string) (bool, string) {
	ext := strings.TrimPrefix(filepath.Ext(filename), ".")
	if ext == "" {
		return false, ""
	}
	ext = strings.ToLower(ext)
	for _, excludedExt := range extensions {
		if strings.ToLower(excludedExt) == ext {
			return true, fmt.Sprintf("**/*.%s", excludedExt)
		}
	}
	return false, ""
}

func containsExcludedFolder(path string, folders []string) (bool, string) {
	pathParts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range pathParts {
		for _, folder := range folders {
			if part == folder {
				return true, fmt.Sprintf("**/%s/**", folder)
			}
		}
	}
	return false, ""
}

func reportExclusions(scanPath string, config Config) {
	if !config.Verbose {
		return
	}

	excludedExts := getExcludedExtensions(config)
	excludedFolders := getExcludedFolders(config)

	if len(excludedExts) == 0 && len(excludedFolders) == 0 {
		return
	}

	fmt.Fprintln(os.Stderr, "[*] Checking for excluded files...")

	filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Get relative path for cleaner output
		relPath, _ := filepath.Rel(scanPath, path)
		if relPath == "." {
			return nil
		}

		// Check folder exclusions first
		if matched, rule := containsExcludedFolder(relPath, excludedFolders); matched {
			timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
			fmt.Fprintf(os.Stderr, "%s  WARN exclusion: Skipping entry: %s (matched rule: %s)\n", timestamp, relPath, rule)
			if info.IsDir() {
				return filepath.SkipDir // Skip entire directory
			}
			return nil
		}

		// Check file extension exclusions
		if !info.IsDir() {
			if matched, rule := matchesExtension(info.Name(), excludedExts); matched {
				timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
				fmt.Fprintf(os.Stderr, "%s  WARN exclusion: Skipping entry: %s (matched rule: %s)\n", timestamp, relPath, rule)
			}
		}

		return nil
	})
}

func runNoseyparker(config Config) error {
	var scanPath string

	if runtime.GOOS == "windows" {
		scanPath = fmt.Sprintf("\\\\%s\\%s", config.Host, config.Share)
	} else {
		scanPath = config.MountPath
	}

	// Create a temporary datastore for noseyparker
	datastorePath, err := os.MkdirTemp("", "np-datastore-*")
	if err != nil {
		return fmt.Errorf("failed to create datastore directory: %w", err)
	}
	defer os.RemoveAll(datastorePath)

	datastore := filepath.Join(datastorePath, "datastore")

	// Build ignore patterns
	ignorePatterns := buildIgnorePatterns(config)

	// Create temporary ignore file for noseyparker
	var ignoreFile string
	if len(ignorePatterns) > 0 {
		tmpIgnore, err := os.CreateTemp("", "noseyparker-ignore-*")
		if err != nil {
			return fmt.Errorf("failed to create ignore file: %w", err)
		}
		ignoreFile = tmpIgnore.Name()
		defer os.Remove(ignoreFile)

		// Write all ignore patterns to the file
		for _, pattern := range ignorePatterns {
			if _, err := tmpIgnore.WriteString(pattern + "\n"); err != nil {
				tmpIgnore.Close()
				return fmt.Errorf("failed to write ignore patterns: %w", err)
			}
		}
		tmpIgnore.Close()
	}

	// Show exclusion info
	if !config.NoExclusion {
		fmt.Fprintf(os.Stderr, "[*] Using default exclusions (%d extensions, %d folders)\n",
			len(defaultExcludedExtensions), len(defaultExcludedFolders))
	} else {
		fmt.Fprintln(os.Stderr, "[*] WARNING: Scanning all files (no exclusions enabled)")
	}
	if len(config.AdditionalExts) > 0 || len(config.AdditionalFolders) > 0 {
		fmt.Fprintf(os.Stderr, "[*] Additional exclusions: %d extensions, %d folders\n",
			len(config.AdditionalExts), len(config.AdditionalFolders))
	}

	// Report all excluded files
	reportExclusions(scanPath, config)

	// Run noseyparker scan
	fmt.Fprintf(os.Stderr, "[*] Scanning %s...\n", scanPath)
	if err := runNoseyparkerScan(config, scanPath, datastorePath, datastore, ignoreFile); err != nil {
		return err
	}

	// Check for findings
	hasFindings, err := checkForFindings(config, datastorePath)
	if err != nil {
		// summarize might not exist in older versions, continue anyway
		fmt.Fprintln(os.Stderr, "[*] Note: Could not get summary (may be using older noseyparker version)")
		hasFindings = true // Assume there might be findings
	}

	if !hasFindings {
		fmt.Fprintln(os.Stderr, "[*] No secrets discovered in this share.")
		return nil
	}

	// Run noseyparker report to stdout (and optionally to file)
	if err := runNoseyparkerReport(config, datastorePath, datastore); err != nil {
		return err
	}

	if config.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "[+] Report saved to %s\n", config.OutputFile)
	}

	return nil
}

func runNoseyparkerScan(config Config, scanPath, datastorePath, datastore, ignoreFile string) error {
	var cmd *exec.Cmd

	if config.UseDocker {
		// Build Docker command with volume mounts
		args := []string{"run", "--rm"}

		// Mount the scan path
		args = append(args, "-v", fmt.Sprintf("%s:/scan:ro", scanPath))

		// Mount the datastore directory
		args = append(args, "-v", fmt.Sprintf("%s:/datastore", datastorePath))

		// Mount the ignore file if it exists
		if ignoreFile != "" {
			args = append(args, "-v", fmt.Sprintf("%s:/ignore:ro", ignoreFile))
		}

		args = append(args, dockerImage, "scan", "--datastore", "/datastore/datastore", "--progress", "always")
		if ignoreFile != "" {
			args = append(args, "--ignore", "/ignore")
		}
		args = append(args, "/scan")

		cmd = exec.Command("docker", args...)
	} else {
		// Native command
		args := []string{"scan", "--datastore", datastore, "--progress", "always"}
		if ignoreFile != "" {
			args = append(args, "--ignore", ignoreFile)
		}
		args = append(args, scanPath)
		cmd = exec.Command("noseyparker", args...)
	}

	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkForFindings(config Config, datastorePath string) (bool, error) {
	var cmd *exec.Cmd

	if config.UseDocker {
		args := []string{"run", "--rm",
			"-v", fmt.Sprintf("%s:/datastore", datastorePath),
			dockerImage, "summarize", "--datastore", "/datastore/datastore",
		}
		cmd = exec.Command("docker", args...)
	} else {
		datastore := filepath.Join(datastorePath, "datastore")
		cmd = exec.Command("noseyparker", "summarize", "--datastore", datastore)
	}

	output, err := cmd.Output()
	if err != nil {
		return false, err
	}

	// Check if there are any findings by looking for non-zero numbers in the Findings column
	// The table format has "Findings" as a column header
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Skip header and separator lines
		if strings.Contains(line, "Rule") || strings.Contains(line, "───") || strings.TrimSpace(line) == "" {
			continue
		}
		// If we have any data row, there are findings
		if strings.TrimSpace(line) != "" {
			return true, nil
		}
	}

	return false, nil
}

func runNoseyparkerReport(config Config, datastorePath, datastore string) error {
	var cmd *exec.Cmd

	if config.UseDocker {
		args := []string{"run", "--rm",
			"-v", fmt.Sprintf("%s:/datastore", datastorePath),
			dockerImage, "report", "--datastore", "/datastore/datastore",
		}
		cmd = exec.Command("docker", args...)
	} else {
		cmd = exec.Command("noseyparker", "report", "--datastore", datastore)
	}

	cmd.Stderr = os.Stderr

	// Set up output: tee to file if -o is specified
	if config.OutputFile != "" {
		outFile, err := os.Create(config.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer outFile.Close()
		cmd.Stdout = io.MultiWriter(os.Stdout, outFile)
	} else {
		cmd.Stdout = os.Stdout
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("noseyparker report failed: %w", err)
	}

	return nil
}

func cleanup(config Config) {
	fmt.Fprintln(os.Stderr, "[*] Cleaning up...")

	if runtime.GOOS == "windows" {
		unmountSMBWindows(config)
	} else {
		// Linux and macOS both use umount
		unmountSMBLinux(config)
	}
}

func unmountSMBLinux(config Config) {
	if config.MountPath == "" {
		return
	}

	// Unmount
	cmd := exec.Command("umount", config.MountPath)
	cmd.Run() // Ignore errors during cleanup

	// Remove the temporary directory
	os.RemoveAll(config.MountPath)
}

func unmountSMBWindows(config Config) {
	uncPath := fmt.Sprintf("\\\\%s\\%s", config.Host, config.Share)
	cmd := exec.Command("net", "use", uncPath, "/delete", "/y")
	cmd.Run() // Ignore errors during cleanup
}
