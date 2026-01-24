package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2"
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
	ExcludedShares     []string
	SaveOutput         bool
	OutputFile         string
	OutputFormats      []string // Output formats: txt, json, jsonl, sarif
	Verbose            bool
	UseDocker          bool
	TargetsFile        string
	DomainController   string
	UseLDAPS           bool   // Use LDAPS (port 636) instead of LDAP (port 389)
	ChannelBinding     bool   // Enable LDAP channel binding (requires TLS)
	DNSServer          string // Custom DNS server IP for lookups
	NoNoseyparker      bool   // Discovery-only mode: output shares without scanning
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

// Default shares to exclude during discovery (regex patterns)
var defaultExcludedShares = []string{
	`^IPC\$$`, `^print\$$`, `^ADMIN\$$`,
}

func main() {
	config := parseArgs()

	// Check if noseyparker is available (skip in discovery-only mode)
	if !config.NoNoseyparker {
		if _, err := exec.LookPath("noseyparker"); err != nil {
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
	}

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
		fmt.Fprintln(os.Stderr, "Error: Cannot use --domain-controller with --target-file. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}
	if hasExplicitDC && hasPartialHostShare {
		fmt.Fprintln(os.Stderr, "Error: Cannot use --domain-controller with -h/-s. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}
	if hasTargetFile && hasPartialHostShare {
		fmt.Fprintln(os.Stderr, "Error: Cannot use --target-file with -h/-s. Choose one input method.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate discovery mode requirements
	if hasDiscovery {
		if config.Username == "" || config.Password == "" || config.Domain == "" {
			fmt.Fprintln(os.Stderr, "Error: Discovery mode requires -u <username>, -p <password>, and -d <domain>.")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Validate that at least one input method is provided
	if !hasDiscovery && !hasTargetFile && !hasHostShare {
		fmt.Fprintln(os.Stderr, "Error: Provide -d <domain> with credentials for auto-discovery,")
		fmt.Fprintln(os.Stderr, "       --domain-controller <dc> for explicit DC,")
		fmt.Fprintln(os.Stderr, "       --target-file <file>, OR both -h <host> and -s <share>.")
		flag.Usage()
		os.Exit(1)
	}

	// Validate --no-noseyparker only works with discovery mode
	if config.NoNoseyparker && !hasDiscovery {
		fmt.Fprintln(os.Stderr, "Error: --no-noseyparker/-nn requires discovery mode (provide -d <domain> with credentials).")
		flag.Usage()
		os.Exit(1)
	}

	// Warn if -of is used with -nn (it will be ignored)
	if config.NoNoseyparker && len(config.OutputFormats) > 0 {
		fmt.Fprintln(os.Stderr, "[!] Warning: --output-format/-of is ignored in discovery-only mode (-nn)")
	}

	// Validate/create output directory for batch mode
	if isBatchMode && config.SaveOutput {
		info, err := os.Stat(config.OutputFile)
		if err != nil {
			// Directory doesn't exist, create it
			if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to create output directory: %s\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "[*] Created output directory: %s\n", config.OutputFile)
		} else if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: Output path must be a directory in batch mode: %s\n", config.OutputFile)
			os.Exit(1)
		}
	}

	// Build target list
	var targets []Target
	if hasDiscovery {
		var err error
		targets, err = discoverTargets(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during discovery: %v\n", err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			fmt.Fprintln(os.Stderr, "[*] No accessible shares discovered")
			os.Exit(0)
		}

		// Discovery-only mode: output shares and exit
		if config.NoNoseyparker {
			outputDiscoveredShares(config, targets)
			os.Exit(0)
		}
	} else if hasTargetFile {
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
		if isBatchMode {
			fmt.Fprintf(os.Stderr, "\n[*] === Target %d/%d: //%s/%s ===\n", i+1, len(targets), target.Host, target.Share)
		}

		// Create a copy of config for this target
		targetConfig := config
		targetConfig.Host = target.Host
		targetConfig.Share = target.Share

		// Set output file for batch mode
		if isBatchMode && config.SaveOutput {
			targetConfig.OutputFile = filepath.Join(config.OutputFile,
				fmt.Sprintf("%s__%s.txt", sanitizeFilename(target.Host), sanitizeFilename(target.Share)))
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
	if isBatchMode {
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
	if err := mountSMB(config); err != nil {
		cleanup(config)
		return fmt.Errorf("mount failed: %w", err)
	}
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
	s = strings.ReplaceAll(s, " ", "_")
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
	fmt.Fprintf(os.Stderr, "Scanned:       %d\n", successful)
	fmt.Fprintf(os.Stderr, "Failed:        %d\n", failed)

	if len(failedTargets) > 0 {
		fmt.Fprintln(os.Stderr, "\nFailed targets:")
		for _, r := range failedTargets {
			fmt.Fprintf(os.Stderr, "  - //%s/%s : %v\n", r.Host, r.Share, r.Error)
		}
	}
}

// outputDiscoveredShares outputs discovered shares in UNC format
func outputDiscoveredShares(config Config, targets []Target) {
	// Build output lines in UNC format
	var lines []string
	for _, t := range targets {
		lines = append(lines, fmt.Sprintf("\\\\%s\\%s", t.Host, t.Share))
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
						fmt.Fprintf(os.Stderr, "Error: Failed to create output directory: %s\n", err)
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
			fmt.Fprintf(os.Stderr, "Error: Failed to write output file: %s\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[+] Discovered shares written to %s\n", outputPath)
	} else {
		// Output to stdout
		fmt.Print(output)
	}
}

// domainToBaseDN converts a domain name to LDAP base DN
// e.g., "corp.local" -> "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	return strings.Join(dnParts, ",")
}

// discoverTargets orchestrates host and share discovery with parallel workers
func discoverTargets(config Config) ([]Target, error) {
	// Step 1: Get list of domain controllers to try
	var domainControllers []string

	if config.DomainController != "" {
		// User explicitly specified a DC
		domainControllers = []string{config.DomainController}
		fmt.Fprintf(os.Stderr, "[*] Using specified domain controller: %s\n", config.DomainController)
	} else {
		// Auto-discover DCs via DNS SRV lookup
		fmt.Fprintf(os.Stderr, "[*] Discovering domain controllers for %s...\n", config.Domain)
		dcs, err := discoverDomainControllers(config.Domain, config.DNSServer)
		if err != nil {
			return nil, fmt.Errorf("could not auto-discover domain controller for %s: %w\n\nProvide a domain controller explicitly with -dc <hostname>\nor try a different DNS server with -dns <ip>", config.Domain, err)
		}
		domainControllers = dcs
		fmt.Fprintf(os.Stderr, "[+] Discovered %d domain controller(s): %s\n", len(dcs), strings.Join(dcs, ", "))
	}

	// Step 2: Discover computers from AD
	fmt.Fprintf(os.Stderr, "[*] Querying AD for computer objects...\n")
	computers, err := discoverComputers(config, domainControllers)
	if err != nil {
		return nil, fmt.Errorf("failed to discover computers: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[+] Found %d computers in AD\n", len(computers))

	if len(computers) == 0 {
		return nil, nil
	}

	// Step 2: Discover shares on each computer (parallel with 10 workers)
	fmt.Fprintln(os.Stderr, "[*] Identifying shares on discovered hosts (this could take a while)...")

	type hostShares struct {
		host   string
		shares []string
		err    error
	}

	jobs := make(chan string, len(computers))
	results := make(chan hostShares, len(computers))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				shares, err := discoverSharesOnHost(host, config)
				results <- hostShares{host: host, shares: shares, err: err}
			}
		}()
	}

	// Send jobs
	for _, computer := range computers {
		jobs <- computer
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var targets []Target
	var hostsWithShares, totalShares, failedHosts int
	for result := range results {
		if result.err != nil {
			failedHosts++
			if config.Verbose {
				fmt.Fprintf(os.Stderr, "[!] %s: %v\n", result.host, result.err)
			}
			continue
		}
		if len(result.shares) > 0 {
			hostsWithShares++
			for _, share := range result.shares {
				totalShares++
				targets = append(targets, Target{Host: result.host, Share: share})
				fmt.Fprintf(os.Stderr, "[+] Found \\\\%s\\%s\n", result.host, share)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "[+] Found %d accessible shares on %d hosts\n", totalShares, hostsWithShares)
	if failedHosts > 0 && !config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] %d hosts unreachable (use -v for details)\n", failedHosts)
	}
	return targets, nil
}

// discoverDomainControllers performs DNS SRV lookup to find domain controllers for a domain
func discoverDomainControllers(domain, dnsServer string) ([]string, error) {
	resolver := getResolver(dnsServer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try the DC-specific SRV record first: _ldap._tcp.dc._msdcs.<domain>
	_, srvs, err := resolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil || len(srvs) == 0 {
		// Fallback to generic LDAP SRV record: _ldap._tcp.<domain>
		_, srvs, err = resolver.LookupSRV(ctx, "ldap", "tcp", domain)
	}

	if err != nil {
		return nil, fmt.Errorf("DNS SRV lookup failed: %w", err)
	}

	if len(srvs) == 0 {
		return nil, fmt.Errorf("no SRV records found")
	}

	// Extract hostnames, sorted by priority (lower = higher priority) and weight
	// Go's LookupSRV already returns results sorted by priority
	var dcs []string
	for _, srv := range srvs {
		// Remove trailing dot from DNS name
		dc := strings.TrimSuffix(srv.Target, ".")
		if dc != "" {
			dcs = append(dcs, dc)
		}
	}

	return dcs, nil
}

// connectToLDAP establishes an LDAP connection to the specified domain controller
func connectToLDAP(dc string, config Config) (*ldap.Conn, error) {
	var l *ldap.Conn
	var err error

	// Resolve DC hostname using custom DNS server if configured
	dcAddr := dc
	if net.ParseIP(dc) == nil {
		// It's a hostname, resolve it
		resolver := getResolver(config.DNSServer)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ips, resolveErr := resolver.LookupHost(ctx, dc)
		if resolveErr != nil {
			return nil, fmt.Errorf("DNS resolution failed for %s: %w", dc, resolveErr)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for %s", dc)
		}
		dcAddr = ips[0]
	}

	if config.UseLDAPS {
		// TLS config - accept self-signed certs (pentesting tool)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         dc, // Use original hostname for TLS SNI
		}

		// Connect to LDAPS (port 636) using resolved IP
		ldapsURL := fmt.Sprintf("ldaps://%s:636", dcAddr)
		l, err = ldap.DialURL(ldapsURL, ldap.DialWithTLSConfig(tlsConfig))
		if err != nil {
			return nil, fmt.Errorf("failed to connect via LDAPS: %w", err)
		}

		if config.ChannelBinding {
			// Use NTLM authentication over LDAPS
			err = l.NTLMBind(config.Domain, config.Username, config.Password)
			if err != nil {
				l.Close()
				return nil, fmt.Errorf("NTLM bind over LDAPS failed: %w", err)
			}
		} else {
			// Simple bind over LDAPS
			bindUser := fmt.Sprintf("%s@%s", config.Username, config.Domain)
			err = l.Bind(bindUser, config.Password)
			if err != nil {
				l.Close()
				return nil, fmt.Errorf("LDAP bind failed: %w", err)
			}
		}
	} else {
		// Plain LDAP (port 389) using resolved IP
		l, err = ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcAddr))
		if err != nil {
			return nil, fmt.Errorf("failed to connect to DC: %w", err)
		}

		// Bind with credentials (UPN format: user@domain works best with FQDN domains)
		bindUser := fmt.Sprintf("%s@%s", config.Username, config.Domain)
		err = l.Bind(bindUser, config.Password)
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("LDAP bind failed: %w", err)
		}
	}

	return l, nil
}

// discoverComputers queries AD via LDAP for all computer objects
// It tries each domain controller in the list until one succeeds
func discoverComputers(config Config, domainControllers []string) ([]string, error) {
	var l *ldap.Conn
	var err error
	var connectedDC string

	// Try each DC until one works
	for _, dc := range domainControllers {
		l, err = connectToLDAP(dc, config)
		if err == nil {
			connectedDC = dc
			break
		}
		fmt.Fprintf(os.Stderr, "[!] Failed to connect to %s: %v\n", dc, err)
	}

	if l == nil {
		return nil, fmt.Errorf("failed to connect to any domain controller")
	}
	defer l.Close()

	// Print connection info
	if config.UseLDAPS {
		if config.ChannelBinding {
			fmt.Fprintf(os.Stderr, "[+] LDAPS connection with NTLM authentication established to %s\n", connectedDC)
		} else {
			fmt.Fprintf(os.Stderr, "[+] LDAPS connection established to %s\n", connectedDC)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[+] LDAP connection established to %s\n", connectedDC)
	}

	// Search for computer objects using paged search to handle large domains
	// AD has a default limit of 1000 results per query
	baseDN := domainToBaseDN(config.Domain)

	// Calculate timestamp for 4 months ago in Windows FILETIME format
	// FILETIME is 100-nanosecond intervals since January 1, 1601
	// Unix epoch (Jan 1, 1970) = 116444736000000000 in FILETIME
	const unixEpochDiff = 116444736000000000
	fourMonthsAgo := time.Now().AddDate(0, -4, 0)
	fileTime := (fourMonthsAgo.Unix() * 10000000) + unixEpochDiff

	// Build LDAP filter:
	// - objectClass=computer: only computer accounts
	// - !(userAccountControl:1.2.840.113556.1.4.803:=2): exclude disabled accounts (bit 2 = ACCOUNTDISABLE)
	// - lastLogonTimestamp>=X: only machines that logged in within last 4 months
	ldapFilter := fmt.Sprintf("(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=%d))", fileTime)

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapFilter,
		[]string{"dNSHostName"},
		nil,
	)

	// Use paged search with 500 entries per page to avoid size limit errors
	sr, err := l.SearchWithPaging(searchRequest, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range sr.Entries {
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		if dnsHostName != "" {
			computers = append(computers, dnsHostName)
		}
	}

	return computers, nil
}

// discoverSharesOnHost enumerates SMB shares on a host and returns those with read access
func discoverSharesOnHost(host string, config Config) ([]string, error) {
	// Resolve hostname to IP using custom resolver if configured
	resolver := getResolver(config.DNSServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found")
	}

	// Connect to SMB
	conn, err := net.DialTimeout("tcp", ips[0]+":445", 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Create SMB dialer
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     config.Username,
			Password: config.Password,
			Domain:   config.Domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("SMB dial failed: %w", err)
	}
	defer s.Logoff()

	// List shares
	shareNames, err := s.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("failed to list shares: %w", err)
	}

	// Check read access for each share (skip excluded shares)
	var accessibleShares []string
	for _, shareName := range shareNames {
		if isShareExcluded(shareName, config.ExcludedShares) {
			continue
		}
		if checkShareAccess(s, shareName) {
			accessibleShares = append(accessibleShares, shareName)
		}
	}

	return accessibleShares, nil
}

// isShareExcluded checks if a share name should be excluded (supports regex patterns)
func isShareExcluded(shareName string, excludedShares []string) bool {
	for _, pattern := range excludedShares {
		re, err := regexp.Compile("(?i)" + pattern) // case-insensitive
		if err != nil {
			// If invalid regex, fall back to literal match
			if strings.EqualFold(shareName, pattern) {
				return true
			}
			continue
		}
		if re.MatchString(shareName) {
			return true
		}
	}
	return false
}

// checkShareAccess verifies read access to a share by attempting to list its root directory
func checkShareAccess(session *smb2.Session, shareName string) bool {
	share, err := session.Mount(shareName)
	if err != nil {
		return false
	}
	defer share.Umount()

	// Try to read root directory
	_, err = share.ReadDir(".")
	return err == nil
}

func parseArgs() Config {
	var config Config
	var additionalExts string
	var additionalFolders string
	var excludedShares string
	var outputFormats string

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

	// Output options (note: -o is handled manually after flag.Parse for optional argument support)
	flag.StringVar(&outputFormats, "output-format", "", "Output formats to save (comma-separated: txt,json,jsonl,sarif)")
	flag.StringVar(&outputFormats, "of", "", "Output formats to save (shorthand)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output (show excluded files)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output (shorthand)")

	// Discovery options (LDAPS and channel binding)
	flag.BoolVar(&config.UseLDAPS, "ldaps", false, "Use LDAPS (port 636) instead of LDAP (port 389)")
	flag.BoolVar(&config.ChannelBinding, "channel-binding", false, "Enable LDAP channel binding (requires --ldaps)")
	flag.StringVar(&config.DNSServer, "dns-server", "", "Custom DNS server IP for hostname resolution")
	flag.StringVar(&config.DNSServer, "dns", "", "Custom DNS server IP (shorthand)")
	flag.BoolVar(&config.NoNoseyparker, "no-noseyparker", false, "Discovery only: output shares in UNC format without scanning")
	flag.BoolVar(&config.NoNoseyparker, "nn", false, "Discovery only: output shares in UNC format without scanning (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "A tool to mount SMB shares and scan for secrets using Noseyparker")
		fmt.Fprintln(os.Stderr, "\nTarget Selection (choose one):")
		fmt.Fprintln(os.Stderr, "  -d <domain> -u -p         Auto-discover DC and scan all accessible AD shares")
		fmt.Fprintln(os.Stderr, "  --domain-controller, -dc  Explicitly specify domain controller (optional)")
		fmt.Fprintln(os.Stderr, "  --target-file, -tf        File with targets (CSV: host,share or UNC: \\\\host\\share)")
		fmt.Fprintln(os.Stderr, "  -host, -h                 Target IP address or hostname  }  Required together")
		fmt.Fprintln(os.Stderr, "  -share, -s                SMB share name                  }  if not using discovery/-tf")
		fmt.Fprintln(os.Stderr, "\nAuthentication:")
		fmt.Fprintln(os.Stderr, "  -username, -u       Username for authentication (required for discovery)")
		fmt.Fprintln(os.Stderr, "  -password, -p       Password for authentication (required for discovery)")
		fmt.Fprintln(os.Stderr, "  -domain, -d         Domain for authentication (required for discovery, e.g., corp.local)")
		fmt.Fprintln(os.Stderr, "\nDiscovery Options:")
		fmt.Fprintln(os.Stderr, "  --ldaps             Use LDAPS (port 636) instead of LDAP (port 389)")
		fmt.Fprintln(os.Stderr, "  --channel-binding   Enable LDAP channel binding (requires --ldaps)")
		fmt.Fprintln(os.Stderr, "  --dns-server, -dns  Custom DNS server IP for DC discovery and hostname resolution")
		fmt.Fprintln(os.Stderr, "  --no-noseyparker, -nn  Discovery only: output shares in UNC format, skip scanning")
		fmt.Fprintln(os.Stderr, "\nFiltering (supports regex patterns):")
		fmt.Fprintln(os.Stderr, "  --show-default-exclusions             Show all default exclusions and exit")
		fmt.Fprintln(os.Stderr, "  --no-default-exclusions       Disable all default exclusions (scan everything)")
		fmt.Fprintln(os.Stderr, "  --exclude-extensions, -xe     Additional file extensions to exclude (comma-separated)")
		fmt.Fprintln(os.Stderr, "  --exclude-directories, -xd    Additional directories to exclude (comma-separated)")
		fmt.Fprintln(os.Stderr, "  --exclude-shares, -xs         Share names to exclude during discovery (comma-separated)")
		fmt.Fprintln(os.Stderr, "\nOutput:")
		fmt.Fprintln(os.Stderr, "  -o <path>           Single target: output file (default: <host>_<share>.txt)")
		fmt.Fprintln(os.Stderr, "                      Batch mode: output directory (must exist)")
		fmt.Fprintln(os.Stderr, "  --output-format, -of  Output formats to save (comma-separated: txt,json,jsonl,sarif)")
		fmt.Fprintln(os.Stderr, "                        Default: txt. Requires -o flag.")
		fmt.Fprintln(os.Stderr, "  -v                  Verbose output (show excluded files)")
		fmt.Fprintln(os.Stderr, "\nBuilt-in Exclusions (enabled by default):")
		fmt.Fprintln(os.Stderr, "  Shares:")
		fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(defaultExcludedShares, ", "))
		fmt.Fprintln(os.Stderr, "  File Extensions:")
		fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(defaultExcludedExtensions, ", "))
		fmt.Fprintln(os.Stderr, "  Directories:")
		fmt.Fprintf(os.Stderr, "    %s\n", strings.Join(defaultExcludedFolders, ", "))
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  # Auto-discover DC and scan all accessible shares in domain")
		fmt.Fprintf(os.Stderr, "  %s -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Same as above, with explicit DC (skips auto-discovery)")
		fmt.Fprintf(os.Stderr, "  %s -dc dc01.corp.local -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Auto-discovery with custom DNS server")
		fmt.Fprintf(os.Stderr, "  %s -u admin -p secret123 -d corp.local -dns 10.0.0.1\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Discovery with output to directory")
		fmt.Fprintf(os.Stderr, "  %s -u admin -p secret123 -d corp.local -o ./results/\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Discovery only (no scanning), output UNC paths to stdout")
		fmt.Fprintf(os.Stderr, "  %s -u admin -p secret123 -d corp.local -nn\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Single target scan")
		fmt.Fprintf(os.Stderr, "  %s -h 192.168.1.100 -s public\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  # Batch scan from target file")
		fmt.Fprintf(os.Stderr, "  %s -tf targets.txt -u admin -p secret123 -d corp.local\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Target file format (one per line):")
		fmt.Fprintln(os.Stderr, "  192.168.1.10,share1       # CSV format")
		fmt.Fprintln(os.Stderr, "  \\\\fileserver\\backup$      # UNC path")
	}

	flag.Parse()

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

	// Validate channel binding requires LDAPS
	if config.ChannelBinding && !config.UseLDAPS {
		fmt.Fprintln(os.Stderr, "Error: --channel-binding requires --ldaps")
		os.Exit(1)
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
	validFormats := map[string]bool{"txt": true, "json": true, "jsonl": true, "sarif": true}
	if outputFormats != "" {
		for _, format := range strings.Split(outputFormats, ",") {
			format = strings.TrimSpace(strings.ToLower(format))
			if !validFormats[format] {
				fmt.Fprintf(os.Stderr, "Error: Invalid output format '%s'. Valid formats: txt, json, jsonl, sarif\n", format)
				os.Exit(1)
			}
			config.OutputFormats = append(config.OutputFormats, format)
		}
	}

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
						fmt.Fprintf(os.Stderr, "Error: Failed to create output directory: %s\n", err)
						os.Exit(1)
					}
					fmt.Fprintf(os.Stderr, "[*] Created output directory: %s\n", config.OutputFile)
				}
				// Append default filename to directory
				config.OutputFile = filepath.Join(config.OutputFile, generateOutputFilename(config.Host, config.Share))
			}
		}
	}

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
	// Suppress output (including podman's "Emulate Docker CLI" message)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// stderrFilter filters out podman's "Emulate Docker CLI" message from stderr
type stderrFilter struct {
	w io.Writer
}

func (f *stderrFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "Emulate Docker CLI") {
		return len(p), nil
	}
	return f.w.Write(p)
}

// getResolver returns a custom DNS resolver if DNSServer is configured, otherwise nil (use default)
func getResolver(dnsServer string) *net.Resolver {
	if dnsServer == "" {
		return net.DefaultResolver
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}
}

func resolveHostToIP(host, dnsServer string) string {
	// If it's already an IP address, return as-is
	if net.ParseIP(host) != nil {
		return host
	}

	// Try to resolve hostname to IP using custom resolver if configured
	resolver := getResolver(dnsServer)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
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
	resolvedIP := resolveHostToIP(config.Host, config.DNSServer)
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
			fmt.Fprintf(os.Stderr, "[+] Mounted to %s using SMB %s\n", config.MountPath, version)
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
	for _, pattern := range extensions {
		re, err := regexp.Compile("(?i)^" + pattern + "$") // case-insensitive, full match
		if err != nil {
			// If invalid regex, fall back to literal match
			if strings.EqualFold(ext, pattern) {
				return true, fmt.Sprintf("**/*.%s", pattern)
			}
			continue
		}
		if re.MatchString(ext) {
			return true, fmt.Sprintf("**/*.%s", pattern)
		}
	}
	return false, ""
}

func containsExcludedFolder(path string, folders []string) (bool, string) {
	pathParts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range pathParts {
		for _, pattern := range folders {
			re, err := regexp.Compile("(?i)^" + pattern + "$") // case-insensitive, full match
			if err != nil {
				// If invalid regex, fall back to literal match
				if strings.EqualFold(part, pattern) {
					return true, fmt.Sprintf("**/%s/**", pattern)
				}
				continue
			}
			if re.MatchString(part) {
				return true, fmt.Sprintf("**/%s/**", pattern)
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
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "[*] Using default exclusions (%d extensions, %d folders)\n",
				len(defaultExcludedExtensions), len(defaultExcludedFolders))
		}
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

	// Run noseyparker report to stdout (and optionally to file(s))
	if err := runNoseyparkerReport(config, datastorePath, datastore); err != nil {
		return err
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

	if config.Verbose {
		cmd.Stderr = &stderrFilter{os.Stderr}
	}
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

// getOutputFilePath returns the output file path for a given format.
// It replaces or appends the appropriate extension based on the format.
func getOutputFilePath(basePath, format string) string {
	// Remove any existing extension from the base path
	ext := filepath.Ext(basePath)
	baseWithoutExt := strings.TrimSuffix(basePath, ext)

	// Map format to file extension
	extMap := map[string]string{
		"txt":   ".txt",
		"json":  ".json",
		"jsonl": ".jsonl",
		"sarif": ".sarif",
	}

	return baseWithoutExt + extMap[format]
}

// runNoseyparkerReportToFile runs noseyparker report with a specific format and writes to a file.
func runNoseyparkerReportToFile(config Config, datastorePath, datastore, format, outputPath string) error {
	var cmd *exec.Cmd

	if config.UseDocker {
		args := []string{"run", "--rm",
			"-v", fmt.Sprintf("%s:/datastore", datastorePath),
			dockerImage, "report", "--datastore", "/datastore/datastore",
		}
		if format != "txt" {
			args = append(args, "--format", format)
		}
		cmd = exec.Command("docker", args...)
	} else {
		args := []string{"report", "--datastore", datastore}
		if format != "txt" {
			args = append(args, "--format", format)
		}
		cmd = exec.Command("noseyparker", args...)
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer outFile.Close()

	cmd.Stdout = outFile
	cmd.Stderr = &stderrFilter{os.Stderr}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("noseyparker report (%s) failed: %w", format, err)
	}

	return nil
}

func runNoseyparkerReport(config Config, datastorePath, datastore string) error {
	// Always output txt format to stdout
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

	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderrFilter{os.Stderr}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("noseyparker report failed: %w", err)
	}

	// If output file is specified, generate files for each requested format
	if config.SaveOutput && config.OutputFile != "" {
		// Default to txt if no formats specified
		formats := config.OutputFormats
		if len(formats) == 0 {
			formats = []string{"txt"}
		}

		for _, format := range formats {
			outputPath := getOutputFilePath(config.OutputFile, format)
			if err := runNoseyparkerReportToFile(config, datastorePath, datastore, format, outputPath); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "[+] Report saved to %s\n", outputPath)
		}
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
