package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2"
	titusscanner "github.com/praetorian-inc/titus/pkg/scanner"
	titussarif "github.com/praetorian-inc/titus/pkg/sarif"
	titusrule "github.com/praetorian-inc/titus/pkg/rule"
	titustypes "github.com/praetorian-inc/titus/pkg/types"
)

// titusCore is the shared Titus scanner instance, initialized once in main().
var titusCore *titusscanner.Core

// titusAllRules caches the full rule set loaded at startup, reused for SARIF output.
var titusAllRules []*titustypes.Rule

// timestampMode prepends [YYYY-MM-DD HH:MM:SS] to every stderr log line.
var timestampMode bool

// logMu serialises timestamp prefix + message so concurrent goroutines
// don't interleave mid-line.
var logMu sync.Mutex

// logAtLineStart tracks whether the next write is at the beginning of a line.
var logAtLineStart = true

// logf writes a formatted message to stderr, optionally prefixed with a timestamp
// at the start of each new line.
func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logMu.Lock()
	defer logMu.Unlock()
	for len(msg) > 0 {
		if logAtLineStart && timestampMode {
			fmt.Fprintf(os.Stderr, "[%s] ", time.Now().Format("2006-01-02 15:04:05"))
		}
		idx := strings.IndexByte(msg, '\n')
		if idx == -1 {
			fmt.Fprint(os.Stderr, msg)
			logAtLineStart = false
			break
		}
		fmt.Fprint(os.Stderr, msg[:idx+1])
		logAtLineStart = true
		msg = msg[idx+1:]
	}
}

// logln writes a line to stderr, optionally prefixed with a timestamp.
func logln(msg string) {
	logf("%s\n", msg)
}

// shareStatus tracks live scan metrics for a single share.
type shareStatus struct {
	tag       string
	state     string // "connecting" or "scanning"
	fileCount *int64
	dirCount  *int64
	startTime time.Time
}

// shareTracker maintains the set of currently-scanning shares and prints
// their status when requested (Enter keypress).
type shareTracker struct {
	mu        sync.Mutex
	shares    map[string]*shareStatus // keyed by tag
	order     []string                // insertion order for stable output
	stopCh    chan struct{}
	total     int64 // total number of targets (set once at start)
	completed int64 // atomically incremented as shares finish
}

func newShareTracker(total int) *shareTracker {
	return &shareTracker{
		shares: make(map[string]*shareStatus),
		stopCh: make(chan struct{}),
		total:  int64(total),
	}
}

func (st *shareTracker) registerConnecting(tag string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.shares[tag] = &shareStatus{
		tag:       tag,
		state:     "connecting",
		startTime: time.Now(),
	}
	st.order = append(st.order, tag)
}

func (st *shareTracker) register(tag string, fileCount, dirCount *int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.shares[tag]; ok {
		// Transition from connecting to scanning
		s.state = "scanning"
		s.fileCount = fileCount
		s.dirCount = dirCount
	} else {
		st.shares[tag] = &shareStatus{
			tag:       tag,
			state:     "scanning",
			fileCount: fileCount,
			dirCount:  dirCount,
			startTime: time.Now(),
		}
		st.order = append(st.order, tag)
	}
}

func (st *shareTracker) deregister(tag string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.shares, tag)
	for i, t := range st.order {
		if t == tag {
			st.order = append(st.order[:i], st.order[i+1:]...)
			break
		}
	}
	atomic.AddInt64(&st.completed, 1)
}

func (st *shareTracker) printStatus() {
	st.mu.Lock()
	defer st.mu.Unlock()
	total := atomic.LoadInt64(&st.total)
	done := atomic.LoadInt64(&st.completed)
	active := int64(len(st.shares))
	queued := total - done - active
	if queued < 0 {
		queued = 0
	}
	if len(st.shares) == 0 {
		if queued > 0 {
			logf("[status] %d/%d complete, %d queued (waiting for worker slot)\n", done, total, queued)
		} else {
			logf("[status] %d/%d complete\n", done, total)
		}
		return
	}
	logf("[status] %d/%d complete, %d active, %d queued:\n", done, total, active, queued)
	for _, tag := range st.order {
		s, ok := st.shares[tag]
		if !ok {
			continue
		}
		elapsed := time.Since(s.startTime).Round(time.Second)
		if s.state == "connecting" {
			fmt.Fprintf(os.Stderr, "  %s  connecting (%s elapsed)\n", s.tag, elapsed)
		} else {
			fc := atomic.LoadInt64(s.fileCount)
			dc := atomic.LoadInt64(s.dirCount)
			fmt.Fprintf(os.Stderr, "  %s  %d files, %d dirs, %s elapsed\n", s.tag, fc, dc, elapsed)
		}
	}
}

// startStdinListener reads lines from stdin in a goroutine and calls
// printStatus on each Enter keypress. Returns a stop function.
func (st *shareTracker) startStdinListener() {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			// scanner.Scan blocks until a line is available or EOF
			if !scanner.Scan() {
				return
			}
			select {
			case <-st.stopCh:
				return
			default:
				st.printStatus()
			}
		}
	}()
}

func (st *shareTracker) stop() {
	close(st.stopCh)
}

// outputFileTracker collects paths of files created by smbellum for zip packaging.
type outputFileTracker struct {
	mu    sync.Mutex
	paths []string
}

func (t *outputFileTracker) add(path string) {
	t.mu.Lock()
	t.paths = append(t.paths, path)
	t.mu.Unlock()
}

func (t *outputFileTracker) list() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.paths))
	copy(out, t.paths)
	return out
}

// createdFiles tracks all output files smbellum writes, for --zip packaging.
var createdFiles = &outputFileTracker{}

type Config struct {
	Host               string
	Share              string
	Username           string
	Password           string
	Domain             string
	NoExclusion        bool
	AdditionalExts     []string
	AdditionalFolders  []string
	ExcludedShares     []string
	SaveOutput         bool
	OutputFile         string
	OutputFormats      []string // Output formats: txt, json, jsonl, sarif, tabularium
	Verbose            bool
	TargetsFile        string
	DomainController   string
	UseLDAPS           bool             // Use LDAPS (port 636) instead of LDAP (port 389)
	ChannelBinding     bool             // Enable LDAP channel binding (requires TLS)
	DNSServer          string           // Custom DNS server IP for lookups
	DiscoveryOnly      bool             // Discovery-only mode: output shares without scanning
	DiscoveryResult    *DiscoveryResult // AD discovery metadata for tabularium output
	ShareWorkers       int              // Number of parallel share workers (default 60)
	FileWorkers        int              // Number of parallel file scanning goroutines per share (default NumCPU)
	NoDFS              bool             // Disable DFS namespace awareness
	DFSPath            string           // DFS namespace path for this target (set during dedup)
	MaxScanSize        int64            // Maximum file size to scan in bytes (default 5MB, 0 = no limit)
	MaxDepth           int              // Maximum directory recursion depth (0 = unlimited)
	MaxShareTime       int              // Maximum time per share in minutes (0 = indefinite, default 45)
	MaxFilesPerDir     int              // Maximum files to scan per directory (0 = unlimited)
	QuickMode          bool             // Quick mode: only scan high-value file types
	Keywords           []string         // Additional filename substrings to always include in scanning
	InterestingExcl    bool             // Write interesting exclusions (keyword/quick match but skipped) to CSV (on when -o is set)
	ZipOutput          bool             // Zip txt/json output files into a single archive, then delete originals
	TargetNum          int              // Current target number (1-based, for progress display)
	TotalTargets       int              // Total number of targets (for progress display)
	// Pre-computed exclusions (built once, shared across all targets)
	ExcludedExts       map[string]bool  // Extension exclusion set
	ExcludedDirs       dirExclusions    // Directory exclusion (exact + regex)
	// Live status tracking (shared across all share goroutines)
	Tracker            *shareTracker
}

// Target represents a single host/share combination to scan
type Target struct {
	Host    string
	Share   string
	DFSPath string // Canonical DFS namespace path (e.g., \\corp.local\dfs\link), empty if not a DFS target
}

// ComputerInfo holds AD computer metadata for tabularium output
type ComputerInfo struct {
	DNSHostName       string
	SID               string
	DistinguishedName string
}

// DomainInfo holds AD domain metadata for tabularium output
type DomainInfo struct {
	Name              string
	SID               string
	DistinguishedName string
}

// DiscoveryResult holds the results of AD discovery for tabularium output
type DiscoveryResult struct {
	Domain    DomainInfo
	Computers map[string]ComputerInfo // keyed by DNSHostName
}

// Tabularium output structures
type TabulariumOutput struct {
	Context TabulariumContext `json:"context"`
	Items   []interface{}       `json:"items"`
}

type TabulariumContext struct {
	Source string                 `json:"source"`
	Target map[string]interface{} `json:"target"`
}

type TabulariumADDomain struct {
	Type              string `json:"_type"`
	Key               string `json:"key"`
	Label             string `json:"label"`
	Class             string `json:"class"`
	Domain            string `json:"domain"`
	ObjectID          string `json:"objectid"`
	SID               string `json:"sid"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
}

type TabulariumADComputer struct {
	Type              string `json:"_type"`
	Key               string `json:"key"`
	Label             string `json:"label"`
	Class             string `json:"class"`
	Domain            string `json:"domain"`
	ObjectID          string `json:"objectid"`
	SID               string `json:"sid"`
	DistinguishedName string `json:"distinguishedname"`
	DNSHostName       string `json:"dnshostname"`
}

type TabulariumRisk struct {
	Type     string                 `json:"_type"`
	Key      string                 `json:"key"`
	DNS      string                 `json:"dns"`
	Name     string                 `json:"name"`
	Status   string                 `json:"status"`
	Source   string                 `json:"source"`
	Priority int                    `json:"priority"`
	Created  string                 `json:"created"`
	Updated  string                 `json:"updated"`
	Visited  string                 `json:"visited"`
	Target   map[string]interface{} `json:"_target"`
}

type TabulariumFile struct {
	Type  string `json:"_type"`
	Key   string `json:"key"`
	Name  string `json:"name"`
	Bytes string `json:"bytes"`
}

// ScanResult holds the outcome of scanning a single target
type ScanResult struct {
	Host        string
	Share       string
	Error       error
	HasFindings bool   // Whether Titus found any secrets
	OutputPath  string // Path to the output file (for tabularium aggregation)
	// Expanded summary fields
	TimedOut       bool
	FileCount      int64
	DirCount       int64
	SkippedFiles   int64
	MatchCount     int
	SeverityCounts [4]int         // [Critical, High, Medium, Low]
	RuleCounts     map[string]int // rule ID → count
}

// ScanStats holds per-share scan statistics returned by runTitusScanSMB.
type ScanStats struct {
	HasFindings    bool
	TimedOut       bool
	FileCount      int64
	DirCount       int64
	SkippedFiles   int64
	MatchCount     int
	SeverityCounts [4]int         // [Critical, High, Medium, Low]
	RuleCounts     map[string]int // rule ID → count
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

// Default Titus rules to exclude from scanning
var defaultExcludedRules = []string{
	"np.linkedin.3", // LinkedIn Access Token
	"np.google.5",   // Google API Key
}

// Severity represents the impact level of a Titus finding.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "Critical"
	case SeverityHigh:
		return "High"
	case SeverityMedium:
		return "Medium"
	case SeverityLow:
		return "Low"
	default:
		return "Unknown"
	}
}

// ruleSeverityMap maps each Titus rule ID to a severity level.
// Unknown rules default to Medium.
var ruleSeverityMap = map[string]Severity{
	// Critical — direct access creds, private keys, connection strings
	"np.aws.2":      SeverityCritical, // AWS Secret Access Key
	"np.aws.4":      SeverityCritical, // AWS Session Token
	"np.aws.5":      SeverityCritical, // Amazon MWS Auth Token
	"np.aws.6":      SeverityCritical, // Amazon API Credentials
	"np.azure.1":    SeverityCritical, // Azure Connection String
	"np.azure.2":    SeverityCritical, // Azure App Configuration Connection String
	"np.azure.3":    SeverityCritical, // Azure Personal Access Token
	"np.azure.4":    SeverityCritical, // Azure DevOps Personal Access Token
	"np.hashicorp.1": SeverityCritical, // Hashicorp Vault Service Token (< v1.10)
	"np.hashicorp.2": SeverityCritical, // Hashicorp Vault Batch Token (< v1.10)
	"np.hashicorp.3": SeverityCritical, // Hashicorp Vault Recovery Token (< v1.10)
	"np.hashicorp.4": SeverityCritical, // Hashicorp Vault Service Token (>= v1.10)
	"np.hashicorp.5": SeverityCritical, // Hashicorp Vault Batch Token (>= v1.10)
	"np.hashicorp.6": SeverityCritical, // Hashicorp Vault Recovery Token (>= v1.10)
	"np.hashicorp.7": SeverityCritical, // Hashicorp Vault Unseal Key
	"np.pem.1":      SeverityCritical, // PEM-Encoded Private Key
	"np.pem.2":      SeverityCritical, // Base64-PEM-Encoded Private Key
	"np.wireguard.1": SeverityCritical, // WireGuard Private Key
	"np.wireguard.2": SeverityCritical, // WireGuard Preshared Key
	"np.kubernetes.1": SeverityCritical, // Kubernetes Bootstrap Token
	"np.kubernetes.2": SeverityCritical, // Kubernetes Bootstrap Token
	"np.mongodb.1":  SeverityCritical, // Credentials in MongoDB Connection String
	"np.postgres.1": SeverityCritical, // Credentials in PostgreSQL Connection URI
	"np.odbc.1":     SeverityCritical, // Credentials in ODBC Connection String
	"np.redis.1":    SeverityCritical, // Redis URI Connection String
	"np.redis.2":    SeverityCritical, // Python Redis Client Debug Output
	"np.netrc.1":    SeverityCritical, // netrc Credentials
	"np.psexec.1":   SeverityCritical, // Credentials in PsExec Command
	"np.vmware.1":   SeverityCritical, // Credentials in Connect-VIServer Command
	"np.jenkins.2":  SeverityCritical, // Jenkins Setup Admin Password
	"np.generic.1":  SeverityCritical, // Generic Secret
	"np.generic.3":  SeverityCritical, // Generic Username and Password
	"np.generic.4":  SeverityCritical, // Generic Username and Password
	"np.generic.5":  SeverityCritical, // Generic Password
	"np.generic.6":  SeverityCritical, // Generic Password
	"np.generic.7":  SeverityCritical, // Credentials in .NET System.Net.NetworkCredential
	"np.generic.8":  SeverityCritical, // Credentials in .NET System.DirectoryServices.DirectoryEntry
	"np.generic.9":  SeverityCritical, // Sensitive value in .NET configuration
	"np.generic.10": SeverityCritical, // Connection string in .NET configuration
	"np.generic.11": SeverityCritical, // Generic Password
	"np.generic.12": SeverityCritical, // Generic Password
	"np.generic.13": SeverityCritical, // Generic Credentials
	"np.generic.14": SeverityCritical, // Generic Credentials
	"np.generic.15": SeverityCritical, // Generic Secret
	"np.generic.16": SeverityCritical, // Generic Secret
	"np.http.1":     SeverityCritical, // HTTP Basic Authentication
	"np.age.2":      SeverityCritical, // Age Identity (X22519 secret key)
	"np.jwt.2":      SeverityCritical, // JSON Web Token Secret
	"np.jwt.3":      SeverityCritical, // JSON Web Token Secret
	"np.okta.1":     SeverityCritical, // Okta API Token
	"np.django.1":   SeverityCritical, // Django Secret Key
	"np.gradle.1":   SeverityCritical, // Hardcoded Gradle Credentials
	"np.phpmailer.1": SeverityCritical, // PHPMailer Credentials
	"np.auth0.1":    SeverityCritical, // Auth0 Application Credentials
	"np.gitalk.1":   SeverityCritical, // Gitalk OAuth Credentials
	"np.google.6":   SeverityCritical, // Google OAuth Credentials
	"np.reactapp.1": SeverityCritical, // React App Username
	"np.reactapp.2": SeverityCritical, // React App Password

	// High — service tokens, CI/CD tokens, major platform API keys
	"np.github.1":       SeverityHigh, // GitHub Personal Access Token
	"np.github.2":       SeverityHigh, // GitHub OAuth Access Token
	"np.github.3":       SeverityHigh, // GitHub App Token
	"np.github.4":       SeverityHigh, // GitHub Refresh Token
	"np.github.6":       SeverityHigh, // GitHub Secret Key
	"np.github.7":       SeverityHigh, // GitHub Personal Access Token
	"np.gitlab.1":       SeverityHigh, // GitLab Runner Registration Token
	"np.gitlab.2":       SeverityHigh, // GitLab Personal Access Token
	"np.gitlab.3":       SeverityHigh, // GitLab Pipeline Trigger Token
	"np.bitbucket.1":    SeverityHigh, // Bitbucket App Password
	"np.slack.2":        SeverityHigh, // Slack Bot Token
	"np.slack.4":        SeverityHigh, // Slack User Token
	"np.slack.5":        SeverityHigh, // Slack App Token
	"np.slack.6":        SeverityHigh, // Slack Legacy Bot Token
	"np.stripe.1":       SeverityHigh, // Stripe API Key
	"np.openai.1":       SeverityHigh, // OpenAI API Key
	"np.anthropic.1":    SeverityHigh, // Anthropic API Key
	"np.dockerhub.1":    SeverityHigh, // Docker Hub Personal Access Token
	"np.heroku.1":       SeverityHigh, // Heroku API Key
	"np.artifactory.1":  SeverityHigh, // Artifactory API Key
	"np.appsync.1":      SeverityHigh, // AWS AppSync API Key
	"np.databricks.1":   SeverityHigh, // Databricks Personal Access Token
	"np.digitalocean.1": SeverityHigh, // DigitalOcean Application Access Token
	"np.digitalocean.2": SeverityHigh, // DigitalOcean Personal Access Token
	"np.digitalocean.3": SeverityHigh, // DigitalOcean Refresh Token
	"np.salesforce.1":   SeverityHigh, // Salesforce Access Token
	"np.atlassian.1":    SeverityHigh, // Atlassian Cloud API Token
	"np.teamcity.1":     SeverityHigh, // TeamCity API Token
	"np.sonarqube.1":    SeverityHigh, // SonarQube Token
	"np.jenkins.1":      SeverityHigh, // Jenkins Token or Crumb
	"np.doppler.1":      SeverityHigh, // Doppler CLI Token
	"np.doppler.2":      SeverityHigh, // Doppler Personal Token
	"np.doppler.3":      SeverityHigh, // Doppler Service Token
	"np.doppler.4":      SeverityHigh, // Doppler Service Account Token
	"np.doppler.5":      SeverityHigh, // Doppler SCIM Token
	"np.doppler.6":      SeverityHigh, // Doppler Audit Token
	"np.twilio.1":       SeverityHigh, // Twilio API Key
	"np.sendgrid.1":     SeverityHigh, // SendGrid API Key
	"np.google.2":       SeverityHigh, // Google OAuth Client Secret (prefixed)
	"np.google.3":       SeverityHigh, // Google OAuth Client Secret
	"np.google.4":       SeverityHigh, // Google OAuth Access Token
	"np.google.5":       SeverityHigh, // Google API Key
	"np.facebook.1":     SeverityHigh, // Facebook Secret Key
	"np.facebook.2":     SeverityHigh, // Facebook Access Token
	"np.dropbox.1":      SeverityHigh, // Dropbox Access Token
	"np.npm.1":          SeverityHigh, // NPM Access Token (fine-grained)
	"np.pypi.1":         SeverityHigh, // PyPI Upload Token
	"np.cratesio.1":     SeverityHigh, // crates.io API Key
	"np.jwt.1":          SeverityHigh, // JSON Web Token (base64url-encoded)
	"np.linkedin.2":     SeverityHigh, // LinkedIn Secret Key
	"np.linkedin.3":     SeverityHigh, // LinkedIn Access Token
	"np.dtrack.1":       SeverityHigh, // Dependency-Track API Key
	"np.dynatrace.1":    SeverityHigh, // Dynatrace Token
	"np.newrelic.1":     SeverityHigh, // New Relic License Key
	"np.newrelic.2":     SeverityHigh, // New Relic License Key (non-suffixed)
	"np.newrelic.3":     SeverityHigh, // New Relic API Service Key
	"np.newrelic.4":     SeverityHigh, // New Relic Admin API Key
	"np.twitter.2":      SeverityHigh, // Twitter Secret Key
	"np.generic.2":      SeverityHigh, // Generic API Key
	"np.http.2":         SeverityHigh, // HTTP Bearer Token
	"np.truenas.1":      SeverityHigh, // TrueNAS API Key (WebSocket)
	"np.truenas.2":      SeverityHigh, // TrueNAS API Key (REST API)
	"np.square.1":       SeverityHigh, // Square Access Token
	"np.square.2":       SeverityHigh, // Square OAuth Secret
	"np.stackhawk.1":    SeverityHigh, // StackHawk API Key

	// Medium — webhooks, monitoring tokens, lower-blast-radius tokens
	"np.slack.3":       SeverityMedium, // Slack Webhook
	"np.msteams.1":     SeverityMedium, // Microsoft Teams Webhook
	"np.grafana.1":     SeverityMedium, // Grafana API Token
	"np.grafana.2":     SeverityMedium, // Grafana Cloud API Token
	"np.grafana.3":     SeverityMedium, // Grafana Service Account Token
	"np.mailchimp.1":   SeverityMedium, // MailChimp API Key
	"np.mailgun.1":     SeverityMedium, // Mailgun API Key
	"np.telegram.1":    SeverityMedium, // Telegram Bot Token
	"np.twitch.1":      SeverityMedium, // Twitch Stream Key
	"np.shopify.2":     SeverityMedium, // Shopify App Secret
	"np.shopify.3":     SeverityMedium, // Shopify Access Token (Public App)
	"np.shopify.4":     SeverityMedium, // Shopify Access Token (Custom App)
	"np.shopify.5":     SeverityMedium, // Shopify Access Token (Legacy Private App)
	"np.codeclimate.1": SeverityMedium, // CodeClimate
	"np.adobe.1":       SeverityMedium, // Adobe OAuth Client Secret
	"np.blynk.1":       SeverityMedium, // Blynk Device Access Token
	"np.blynk.2":       SeverityMedium, // Blynk Organization Access Token
	"np.blynk.3":       SeverityMedium, // Blynk Organization Access Token
	"np.blynk.8":       SeverityMedium, // Blynk Organization Client Credentials
	"np.blynk.9":       SeverityMedium, // Blynk Organization Client Credentials
	"np.postmark.1":    SeverityMedium, // Postmark API Token
	"np.thingsboard.1": SeverityMedium, // ThingsBoard Access Token
	"np.thingsboard.2": SeverityMedium, // ThingsBoard Provision Device Key
	"np.thingsboard.3": SeverityMedium, // ThingsBoard Provision Device Secret
	"np.newrelic.5":    SeverityMedium, // New Relic Insights Insert Key
	"np.newrelic.6":    SeverityMedium, // New Relic Insights Query Key
	"np.newrelic.7":    SeverityMedium, // New Relic REST API Key
	"np.newrelic.8":    SeverityMedium, // New Relic Pixie API Key
	"np.newrelic.9":    SeverityMedium, // New Relic Pixie Deploy Key
	"np.adafruit.1":    SeverityMedium, // Adafruit IO Key
	"np.firecrawl.1":   SeverityMedium, // Firecrawl API Key
	"np.groq.1":        SeverityMedium, // Groq API Key
	"np.jina.1":        SeverityMedium, // Jina Search Foundation API Key
	"np.kagi.1":        SeverityMedium, // Kagi API Key
	"np.tavily.1":      SeverityMedium, // Tavily API Key

	// Low — public-facing tokens, read-only keys, low-impact tokens
	"np.figma.1":       SeverityLow, // Figma Personal Access Token
	"np.nuget.1":       SeverityLow, // NuGet API Key
	"np.rubygems.1":    SeverityLow, // RubyGems API Key
	"np.sourcegraph.1": SeverityLow, // Sourcegraph Access Token
	"np.postman.1":     SeverityLow, // Postman API Key
	"np.nasa.1":        SeverityLow, // NASA API Key
	"np.mapbox.2":      SeverityLow, // Mapbox Secret Access Token
	"np.mapbox.3":      SeverityLow, // Mapbox Temporary Access Token
	"np.sauce.1":       SeverityLow, // Sauce Token
	"np.particleio.1":  SeverityLow, // particle.io Access Token
	"np.particleio.2":  SeverityLow, // particle.io Access Token
	"np.huggingface.1": SeverityLow, // HuggingFace User Access Token
}

func ruleSeverity(ruleID string) Severity {
	if s, ok := ruleSeverityMap[ruleID]; ok {
		return s
	}
	return SeverityMedium // safe default for unmapped rules
}

// Quick mode allowlists — files likely to contain secrets.

var quickModeExactFilenames = map[string]bool{
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	"ntds.dit": true, "sam": true, "system": true, "security": true,
	".htpasswd": true, ".netrc": true, ".pgpass": true, ".my.cnf": true, "pgpass.conf": true,
	"credentials": true, "credentials.json": true, "credentials.xml": true,
	"shadow": true, "passwd": true,
	"unattend.xml": true, "sysprep.xml": true, "autounattend.xml": true,
	"web.config": true, "applicationhost.config": true,
	"wp-config.php": true, "localsettings.php": true, "database.yml": true,
	".npmrc": true, ".pypirc": true, ".git-credentials": true,
	".boto": true, ".s3cfg": true,
	".bashrc": true, ".bash_profile": true, ".zshrc": true, ".profile": true,
	".htaccess": true,
	"config.php": true, "settings.py": true,
}

var quickModeContainsFilenames = []string{
	"dockerfile", "docker-compose", ".dockerenv",
	"jenkinsfile", ".gitlab-ci",
	"terraform.tfvars", ".tfstate",
	"appsettings", "connection", "datasource",
	".env",
	"credentials", "password", "secret",
}

var quickModeExtensions = map[string]bool{
	"pem": true, "key": true, "pfx": true, "p12": true, "pkcs12": true,
	"ppk": true, "jks": true, "keystore": true, "kdbx": true, "kdb": true,
	"env": true, "conf": true, "cfg": true, "ini": true,
	"yaml": true, "yml": true, "toml": true, "properties": true,
	"ps1": true, "psm1": true, "bat": true, "cmd": true, "sh": true, "bash": true,
	"config": true, "ovpn": true, "txt": true,
	"log": true, "sql": true, "rdp": true,
	"bak": true, "old": true, "orig": true,
}

func isQuickModeTarget(path string) bool {
	name := strings.ToLower(filepath.Base(path))
	ext := strings.TrimPrefix(filepath.Ext(name), ".")

	if quickModeExtensions[ext] {
		return true
	}
	if quickModeExactFilenames[name] {
		return true
	}
	for _, pattern := range quickModeContainsFilenames {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

func main() {
	config := parseArgs()

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
		if config.Verbose {
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

	// Validate tabularium format only works in discovery mode
	hasTabularium := false
	for _, f := range config.OutputFormats {
		if f == "tabularium" {
			hasTabularium = true
			break
		}
	}
	if hasTabularium && !hasDiscovery {
		logln("Error: --output-format tabularium requires discovery mode (provide -d <domain> with credentials).")
		flag.Usage()
		os.Exit(1)
	}
	// Strip tabularium from formats if -do is used (discovery-only mode)
	if config.DiscoveryOnly && hasTabularium {
		var filtered []string
		for _, f := range config.OutputFormats {
			if f != "tabularium" {
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
		// Fetch SIDs if tabularium output is requested
		fetchSIDs := hasTabularium && !config.DiscoveryOnly
		var discoveryResult *DiscoveryResult
		targets, discoveryResult, err = discoverTargets(config, fetchSIDs)
		if err != nil {
			logf("Error during discovery: %v\n", err)
			os.Exit(1)
		}
		// Store discovery result for tabularium output
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
	defer tracker.stop()

	results := make([]ScanResult, len(targets))
	sem := make(chan struct{}, config.ShareWorkers)
	var wg sync.WaitGroup
	scanStartAll := time.Now()

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
			if err != nil {
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

	// Generate tabularium output if requested
	if hasTabularium && config.DiscoveryResult != nil {
		if err := generateTabulariumOutput(config, results); err != nil {
			logf("[-] Failed to generate tabularium output: %v\n", err)
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
	logf("%s Connecting...\n", tag)

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
	}()

	if config.TotalTargets > 0 {
		logf("%s Connected via SMB, target %d/%d\n", tag, config.TargetNum, config.TotalTargets)
	} else {
		logf("%s Connected via SMB\n", tag)
	}

	// Apply per-share time limit if configured
	scanCtx := ctx
	if config.MaxShareTime > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, time.Duration(config.MaxShareTime)*time.Minute)
		defer cancel()
		logf("%s Time limit: %d minutes per share\n", tag, config.MaxShareTime)
	}

	logf("%s Running Titus scan...\n", tag)
	scanStart := time.Now()
	stats, err := runTitusScanSMB(scanCtx, config, share)
	scanDuration := time.Since(scanStart)
	if err != nil {
		return stats, "", fmt.Errorf("scan failed: %w", err)
	}

	logf("%s Scan complete (%s)\n", tag, scanDuration.Round(time.Millisecond))
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

// generateTabulariumOutput creates a tabularium-compatible JSON file for Guard platform ingestion
func generateTabulariumOutput(config Config, results []ScanResult) error {
	discovery := config.DiscoveryResult
	if discovery == nil {
		return fmt.Errorf("no discovery result available")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	domainLower := strings.ToLower(config.Domain)

	// Build domain object for context and items
	domainObj := map[string]interface{}{
		"_type":             "addomain",
		"key":               fmt.Sprintf("#addomain#%s#%s", domainLower, discovery.Domain.SID),
		"label":             "ADDomain",
		"class":             "domain",
		"domain":            domainLower,
		"objectid":          discovery.Domain.SID,
		"sid":               discovery.Domain.SID,
		"domainsid":         discovery.Domain.SID,
		"distinguishedname": discovery.Domain.DistinguishedName,
	}

	// Build context
	output := TabulariumOutput{
		Context: TabulariumContext{
			Source: "smbellum",
			Target: domainObj,
		},
		Items: []interface{}{},
	}

	// Add domain object to items
	output.Items = append(output.Items, domainObj)

	// Aggregate findings per host
	// Map from hostname to list of results with findings
	hostFindings := make(map[string][]ScanResult)
	for _, r := range results {
		if r.HasFindings {
			hostFindings[r.Host] = append(hostFindings[r.Host], r)
		}
	}

	// For each host with findings, create computer object, risk, and proof file
	for host, hostResults := range hostFindings {
		// Get computer info from discovery result
		computerInfo, ok := discovery.Computers[host]
		if !ok {
			// Computer not found in discovery (shouldn't happen), skip
			logf("[!] Warning: Computer %s not found in discovery result, skipping tabularium entry\n", host)
			continue
		}

		// Create computer object
		computerObj := TabulariumADComputer{
			Type:              "adcomputer",
			Key:               fmt.Sprintf("#adcomputer#%s#%s", domainLower, computerInfo.SID),
			Label:             "ADComputer",
			Class:             "computer",
			Domain:            domainLower,
			ObjectID:          computerInfo.SID,
			SID:               computerInfo.SID,
			DistinguishedName: computerInfo.DistinguishedName,
			DNSHostName:       strings.ToLower(computerInfo.DNSHostName),
		}
		output.Items = append(output.Items, computerObj)

		// Aggregate proof content from all output files for this host
		var proofContent strings.Builder
		proofContent.WriteString(fmt.Sprintf("Host: %s\n", host))
		proofContent.WriteString(fmt.Sprintf("Shares with findings: %d\n", len(hostResults)))
		proofContent.WriteString("=" + strings.Repeat("=", 50) + "\n\n")

		for _, r := range hostResults {
			proofContent.WriteString(fmt.Sprintf("Share: %s\n", r.Share))
			proofContent.WriteString("-" + strings.Repeat("-", 30) + "\n")

			// Read the output file if it exists, redacting secret values
			if r.OutputPath != "" {
				content, err := os.ReadFile(r.OutputPath)
				if err == nil {
					proofContent.WriteString(redactProofContent(string(content)))
				} else {
					proofContent.WriteString(fmt.Sprintf("[Could not read output file: %v]\n", err))
				}
			} else {
				proofContent.WriteString("[No output file saved]\n")
			}
			proofContent.WriteString("\n")
		}

		// Create risk object - use host (not domain) for unique risk per host
		hostLower := strings.ToLower(host)
		riskKey := fmt.Sprintf("#risk#%s#smb-exposed-secrets", hostLower)
		riskTarget := map[string]interface{}{
			"_type":       "adcomputer",
			"key":         computerObj.Key,
			"label":       "ADComputer",
			"class":       "computer",
			"domain":      domainLower,
			"objectid":    computerInfo.SID,
			"dnshostname": strings.ToLower(computerInfo.DNSHostName),
		}

		risk := TabulariumRisk{
			Type:     "risk",
			Key:      riskKey,
			DNS:      hostLower,
			Name:     "smb-exposed-secrets",
			Status:   "TM", // Triage Medium
			Source:   "smbellum:TITUS",
			Priority: 20, // Medium
			Created:  now,
			Updated:  now,
			Visited:  now,
			Target:   riskTarget,
		}
		output.Items = append(output.Items, risk)

		// Create proof file - name must match risk dns/name for evidence linkage
		proofName := fmt.Sprintf("proofs/%s/smb-exposed-secrets", hostLower)
		proofFile := TabulariumFile{
			Type:  "file",
			Key:   fmt.Sprintf("#file#%s", proofName),
			Name:  proofName,
			Bytes: "base64:" + base64.StdEncoding.EncodeToString([]byte(proofContent.String())),
		}
		output.Items = append(output.Items, proofFile)
	}

	// Serialize to JSON
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize tabularium output: %w", err)
	}

	// Determine output path
	filename := fmt.Sprintf("%s.tabularium", sanitizeFilename(config.Domain))
	outputPath := filename
	if config.OutputFile != "" {
		// Check if OutputFile is a directory
		if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
			outputPath = filepath.Join(config.OutputFile, filename)
		} else if strings.HasSuffix(config.OutputFile, "/") || strings.HasSuffix(config.OutputFile, string(os.PathSeparator)) {
			// Intended to be a directory
			if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
			outputPath = filepath.Join(config.OutputFile, filename)
		}
	}

	// Write the file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write tabularium output: %w", err)
	}

	logf("[+] Tabularium output written to %s\n", outputPath)
	return nil
}

// zipOutputFiles collects the tracked txt/json output files into a single zip
// archive, then removes the originals. The zip is named to match the tabularium
// convention: {sanitized_domain_or_host__share}.zip and placed in the same
// directory as the output files.
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

	// Determine zip filename using tabularium naming convention
	var zipBase string
	if config.Domain != "" {
		zipBase = sanitizeFilename(config.Domain)
	} else {
		zipBase = sanitizeFilename(config.Host) + "__" + sanitizeFilename(config.Share)
	}

	// Determine output directory (same as where tabularium would be placed)
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

// sidToString converts a binary SID to its string representation
// SID format: S-R-I-S-S-S...
// Where R=revision, I=identifier authority, S=sub-authorities
func sidToString(sidBytes []byte) string {
	if len(sidBytes) < 8 {
		return ""
	}

	revision := sidBytes[0]
	subAuthCount := int(sidBytes[1])

	// Identifier authority is 6 bytes big-endian
	var identAuth uint64
	for i := 2; i < 8; i++ {
		identAuth = (identAuth << 8) | uint64(sidBytes[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, identAuth)

	// Sub-authorities are 4 bytes little-endian each
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(sidBytes); i++ {
		subAuth := binary.LittleEndian.Uint32(sidBytes[8+i*4:])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// discoverTargets orchestrates host and share discovery with parallel workers
// If fetchSIDs is true, also fetches SIDs for tabularium output
func discoverTargets(config Config, fetchSIDs bool) ([]Target, *DiscoveryResult, error) {
	// Step 1: Get list of domain controllers to try
	var domainControllers []string

	if config.DomainController != "" {
		// User explicitly specified a DC
		domainControllers = []string{config.DomainController}
		logf("[*] Using specified domain controller: %s\n", config.DomainController)
	} else {
		// Auto-discover DCs via DNS SRV lookup
		logf("[*] Discovering domain controllers for %s...\n", config.Domain)
		dcs, err := discoverDomainControllers(config.Domain, config.DNSServer)
		if err != nil {
			return nil, nil, fmt.Errorf("could not auto-discover domain controller for %s: %w\n\nProvide a domain controller explicitly with -dc <hostname>\nor try a different DNS server with -dns <ip>", config.Domain, err)
		}
		domainControllers = dcs
		logf("[+] Discovered %d domain controller(s): %s\n", len(dcs), strings.Join(dcs, ", "))
	}

	// Step 2: Discover computers from AD
	logf("[*] Querying AD for computer objects...\n")
	computers, discoveryResult, err := discoverComputers(config, domainControllers, fetchSIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover computers: %w", err)
	}
	logf("[+] Found %d computers in AD\n", len(computers))

	if len(computers) == 0 {
		return nil, discoveryResult, nil
	}

	// Step 2: Discover shares on each computer (parallel workers)
	logln("[*] Identifying shares on discovered hosts (this could take a while)...")

	// Pre-compile share exclusion patterns once
	compiledExclusions := compileExcludedShares(config.ExcludedShares)

	type hostShares struct {
		host   string
		shares []string
		err    error
	}

	jobs := make(chan string, len(computers))
	results := make(chan hostShares, len(computers))

	// Start workers (use ShareWorkers for discovery too, minimum 20)
	discoveryWorkers := max(config.ShareWorkers, 20)
	var wg sync.WaitGroup
	for i := 0; i < discoveryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				shares, err := discoverSharesOnHost(host, config, compiledExclusions)
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
				logf("[!] %s: %v\n", result.host, result.err)
			}
			continue
		}
		if len(result.shares) > 0 {
			hostsWithShares++
			for _, share := range result.shares {
				totalShares++
				targets = append(targets, Target{Host: result.host, Share: share})
				logf("[+] Found \\\\%s\\%s\n", result.host, share)
			}
		}
	}

	logf("[+] Found %d accessible shares on %d hosts\n", totalShares, hostsWithShares)
	if failedHosts > 0 && !config.Verbose {
		logf("[*] %d hosts unreachable (use -v for details)\n", failedHosts)
	}

	// DFS namespace awareness: discover DFS links and deduplicate targets
	if !config.NoDFS && len(targets) > 0 {
		logln("[*] Querying AD for DFS namespaces...")
		dfsLinks, dfsErr := discoverDFSNamespaces(config, domainControllers)
		if dfsErr != nil {
			// DFS discovery failure is non-fatal — continue without dedup
			logf("[!] DFS namespace discovery failed (continuing without DFS dedup): %v\n", dfsErr)
		} else if len(dfsLinks) > 0 {
			logf("[+] Found DFS links covering %d physical share(s)\n", len(dfsLinks))
			var removed int
			targets, removed = deduplicateTargetsWithDFS(targets, dfsLinks, config.Domain)
			if removed > 0 {
				logf("[+] DFS dedup: removed %d duplicate target(s), %d target(s) remaining\n", removed, len(targets))
			}
		} else {
			logln("[*] No DFS namespaces found")
		}

		// Deduplicate DFSR-replicated shares (SYSVOL, NETLOGON) across domain controllers.
		// These use DFSR replication (msDFSR-* AD objects) rather than standard DFS namespaces,
		// so discoverDFSNamespaces does not detect them. Every DC serves identical content.
		// Skip if DFS discovery failed — LDAP was unreachable, so the DC list may be incomplete.
		if dfsErr == nil {
			var replicatedRemoved int
			targets, replicatedRemoved = deduplicateReplicatedShares(targets, config.Domain)
			if replicatedRemoved > 0 {
				logf("[+] DFSR dedup: removed %d duplicate replicated share(s), %d target(s) remaining\n", replicatedRemoved, len(targets))
			}
		}
	}

	return targets, discoveryResult, nil
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

// connectToLDAP establishes an LDAP connection to the specified domain controller.
// It returns the connection, a description of the method used, and any error.
//
// Auto-negotiation (default when neither --ldaps nor --channel-binding is set):
//   1. LDAPS + channel binding (NTLM bind on port 636)
//   2. LDAPS + simple bind (port 636)
//   3. Plain LDAP (port 389)
//
// When --ldaps is set, only LDAPS methods are tried (skips plain LDAP).
// When --channel-binding is set, only LDAPS + NTLM is tried.
func connectToLDAP(dc string, config Config) (*ldap.Conn, string, error) {
	// Resolve DC hostname using custom DNS server if configured
	dcAddr := dc
	if net.ParseIP(dc) == nil {
		// It's a hostname, resolve it
		resolver := getResolver(config.DNSServer)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ips, resolveErr := resolver.LookupHost(ctx, dc)
		if resolveErr != nil {
			return nil, "", fmt.Errorf("DNS resolution failed for %s: %w", dc, resolveErr)
		}
		if len(ips) == 0 {
			return nil, "", fmt.Errorf("no IP addresses found for %s", dc)
		}
		dcAddr = ips[0]
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         dc, // Use original hostname for TLS SNI
	}
	bindUser := fmt.Sprintf("%s@%s", config.Username, config.Domain)

	// Determine which methods to attempt based on flags
	autoNegotiate := !config.UseLDAPS && !config.ChannelBinding

	// Attempt 1: LDAPS + channel binding (NTLM)
	if config.ChannelBinding || config.UseLDAPS || autoNegotiate {
		l, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", dcAddr), ldap.DialWithTLSConfig(tlsConfig))
		if err == nil {
			if bindErr := l.NTLMBind(config.Domain, config.Username, config.Password); bindErr == nil {
				return l, "LDAPS with channel binding (NTLM)", nil
			}
			l.Close()
		}
		// If channel-binding was explicitly requested, don't fall back
		if config.ChannelBinding && !config.UseLDAPS {
			return nil, "", fmt.Errorf("LDAPS with channel binding failed for %s: %w", dc, err)
		}
	}

	// Attempt 2: LDAPS + simple bind
	if config.UseLDAPS || autoNegotiate {
		l, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", dcAddr), ldap.DialWithTLSConfig(tlsConfig))
		if err == nil {
			if bindErr := l.Bind(bindUser, config.Password); bindErr == nil {
				return l, "LDAPS", nil
			}
			l.Close()
		}
		// If --ldaps was explicitly requested, don't fall back to plain LDAP
		if config.UseLDAPS {
			return nil, "", fmt.Errorf("LDAPS connection failed for %s: %w", dc, err)
		}
	}

	// Attempt 3: Plain LDAP (port 389)
	if autoNegotiate {
		l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcAddr))
		if err == nil {
			if bindErr := l.Bind(bindUser, config.Password); bindErr == nil {
				return l, "LDAP", nil
			}
			l.Close()
			return nil, "", fmt.Errorf("LDAP bind failed for %s: %w", dc, err)
		}
		return nil, "", fmt.Errorf("failed to connect to DC %s: %w", dc, err)
	}

	return nil, "", fmt.Errorf("all LDAP connection methods failed for %s", dc)
}

// discoverComputers queries AD via LDAP for all computer objects
// It tries each domain controller in the list until one succeeds
// Returns computer hostnames and optionally DiscoveryResult with SIDs for tabularium output
func discoverComputers(config Config, domainControllers []string, fetchSIDs bool) ([]string, *DiscoveryResult, error) {
	var l *ldap.Conn
	var err error
	var connectedDC string
	var connMethod string

	// Try each DC until one works
	for _, dc := range domainControllers {
		l, connMethod, err = connectToLDAP(dc, config)
		if err == nil {
			connectedDC = dc
			break
		}
		logf("[!] Failed to connect to %s: %v\n", dc, err)
	}

	if l == nil {
		return nil, nil, fmt.Errorf("failed to connect to any domain controller")
	}
	defer l.Close()

	logf("[+] %s connection established to %s\n", connMethod, connectedDC)

	baseDN := domainToBaseDN(config.Domain)

	// Initialize discovery result if fetching SIDs
	var discoveryResult *DiscoveryResult
	if fetchSIDs {
		discoveryResult = &DiscoveryResult{
			Computers: make(map[string]ComputerInfo),
		}

		// Fetch domain SID
		domainSearchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=domain)",
			[]string{"objectSid", "distinguishedName"},
			nil,
		)
		domainResult, err := l.Search(domainSearchRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch domain SID: %w", err)
		}
		if len(domainResult.Entries) > 0 {
			entry := domainResult.Entries[0]
			sidBytes := entry.GetRawAttributeValue("objectSid")
			discoveryResult.Domain = DomainInfo{
				Name:              strings.ToLower(config.Domain),
				SID:               sidToString(sidBytes),
				DistinguishedName: entry.GetAttributeValue("distinguishedName"),
			}
			logf("[+] Domain SID: %s\n", discoveryResult.Domain.SID)
		}
	}

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

	// Fetch additional attributes if we need SIDs
	attributes := []string{"dNSHostName"}
	if fetchSIDs {
		attributes = append(attributes, "objectSid", "distinguishedName")
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapFilter,
		attributes,
		nil,
	)

	// Use paged search with 500 entries per page to avoid size limit errors
	sr, err := l.SearchWithPaging(searchRequest, 500)
	if err != nil {
		return nil, nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range sr.Entries {
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		if dnsHostName != "" {
			computers = append(computers, dnsHostName)

			// Store computer info if fetching SIDs
			if fetchSIDs && discoveryResult != nil {
				sidBytes := entry.GetRawAttributeValue("objectSid")
				discoveryResult.Computers[dnsHostName] = ComputerInfo{
					DNSHostName:       dnsHostName,
					SID:               sidToString(sidBytes),
					DistinguishedName: entry.GetAttributeValue("distinguishedName"),
				}
			}
		}
	}

	return computers, discoveryResult, nil
}

// discoverSharesOnHost enumerates SMB shares on a host and returns those with read access
func discoverSharesOnHost(host string, config Config, compiledExclusions []*regexp.Regexp) ([]string, error) {
	// Resolve hostname to IP using custom resolver if configured
	resolver := getResolver(config.DNSServer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found")
	}

	// Connect to SMB
	conn, err := net.DialTimeout("tcp", ips[0]+":445", 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	// Cap entire SMB session (auth + list shares + access checks) so slow/hung
	// hosts don't block discovery workers indefinitely.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

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
		if isSigningError(err) {
			return nil, fmt.Errorf("authentication failed (server requires signing): %w", err)
		}
		return nil, fmt.Errorf("SMB dial failed: %w", err)
	}
	defer s.Logoff()

	// List shares
	shareNames, err := s.ListSharenames()
	if err != nil {
		if isSigningError(err) {
			return nil, fmt.Errorf("authentication failed (server requires signing): %w", err)
		}
		return nil, fmt.Errorf("failed to list shares: %w", err)
	}

	// Check read access for each share (skip excluded shares)
	var accessibleShares []string
	for _, shareName := range shareNames {
		if isShareExcluded(shareName, compiledExclusions) {
			continue
		}
		if checkShareAccess(s, shareName) {
			accessibleShares = append(accessibleShares, shareName)
		}
	}

	return accessibleShares, nil
}

// DFSLink represents a single DFS namespace link and its physical target(s).
type DFSLink struct {
	Namespace string // e.g., "corp.local" or custom namespace name
	LinkPath  string // e.g., "finance" (the link name within the namespace)
	DFSPath   string // Full DFS path: \\domain\namespace\link
	Targets   []DFSTarget
}

// DFSTarget represents one physical target of a DFS link.
type DFSTarget struct {
	Host  string // e.g., "fileserver.corp.local"
	Share string // e.g., "finance$"
	Path  string // Subfolder path within the share (usually empty)
}

// discoverDFSNamespaces queries AD for domain-based DFS namespace configurations.
// Returns a map from normalized "host\share" → []DFSLink for deduplication.
// A physical share may back multiple DFS links, so each key maps to a slice.
func discoverDFSNamespaces(config Config, domainControllers []string) (map[string][]DFSLink, error) {
	var l *ldap.Conn
	var err error

	// Try each DC until one works
	for _, dc := range domainControllers {
		l, _, err = connectToLDAP(dc, config)
		if err == nil {
			break
		}
	}
	if l == nil {
		return nil, fmt.Errorf("failed to connect to any domain controller for DFS discovery")
	}
	defer l.Close()

	baseDN := domainToBaseDN(config.Domain)
	dfsConfigDN := fmt.Sprintf("CN=Dfs-Configuration,CN=System,%s", baseDN)

	// Search for DFS namespace link objects (fTDfs class represents DFS links)
	// Domain-based DFS namespaces store links under:
	//   CN=<link>,CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...
	searchRequest := ldap.NewSearchRequest(
		dfsConfigDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDFS-Linkv2)",
		[]string{"msDFS-LinkPathv2", "msDFS-TargetListv2", "distinguishedName", "cn"},
		nil,
	)

	// Try v2 DFS objects first (Windows Server 2008+ domain-based DFS)
	sr, v2Err := l.SearchWithPaging(searchRequest, 500)
	var v2Results map[string][]DFSLink
	if v2Err == nil && len(sr.Entries) > 0 {
		v2Results = parseDFSv2Entries(sr.Entries, config.Domain)
		if config.Verbose {
			logf("[*] DFS: found %d v2 link entries\n", len(sr.Entries))
		}
	}

	// Also try legacy DFS objects (Windows 2000/2003 style fTDfs)
	// Many environments use legacy objects even on modern DCs
	legacyRequest := ldap.NewSearchRequest(
		dfsConfigDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=fTDfs)",
		[]string{"remoteServerName", "distinguishedName", "cn"},
		nil,
	)
	legacySR, legacyErr := l.SearchWithPaging(legacyRequest, 500)
	var legacyResults map[string][]DFSLink
	if legacyErr == nil && len(legacySR.Entries) > 0 {
		legacyResults = parseLegacyDFSEntries(legacySR.Entries, config.Domain)
		if config.Verbose {
			logf("[*] DFS: found %d legacy (fTDfs) entries\n", len(legacySR.Entries))
		}
	}

	// If both failed, report the errors
	if v2Err != nil && legacyErr != nil {
		return nil, fmt.Errorf("DFS LDAP query failed (v2: %v, legacy: %w)", v2Err, legacyErr)
	}

	// Merge results — legacy entries may cover namespaces that v2 missed
	merged := make(map[string][]DFSLink)
	for k, v := range v2Results {
		merged[k] = v
	}
	for k, v := range legacyResults {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}

	return merged, nil
}

// parseDFSv2Entries parses msDFS-Linkv2 LDAP entries into a target lookup map.
func parseDFSv2Entries(entries []*ldap.Entry, domain string) map[string][]DFSLink {
	result := make(map[string][]DFSLink)
	domainLower := strings.ToLower(domain)

	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		linkPath := entry.GetAttributeValue("msDFS-LinkPathv2")
		targetListRaw := entry.GetRawAttributeValues("msDFS-TargetListv2")

		if linkPath == "" || len(targetListRaw) == 0 {
			continue
		}

		// Clean the link path (remove leading backslash if present)
		linkPath = strings.TrimPrefix(linkPath, "\\")

		// Extract namespace name from DN: CN=<link>,CN=<namespace>,CN=Dfs-Configuration,...
		namespace := extractNamespaceFromDN(dn)
		if namespace == "" {
			continue
		}

		dfsPath := fmt.Sprintf(`\\%s\%s\%s`, domainLower, namespace, linkPath)

		// Parse all target list blobs to extract physical server/share targets
		var targets []DFSTarget
		for _, raw := range targetListRaw {
			targets = append(targets, parseDFSTargetListBytes(raw)...)
		}

		link := DFSLink{
			Namespace: namespace,
			LinkPath:  linkPath,
			DFSPath:   dfsPath,
			Targets:   targets,
		}

		// Map each physical target to this DFS link (accumulate — a share may back multiple links)
		for _, t := range targets {
			key := strings.ToLower(t.Host + `\` + t.Share)
			if t.Path != "" {
				key += `\` + strings.ToLower(t.Path)
			}
			result[key] = append(result[key], link)
		}
	}

	return result
}

// parseLegacyDFSEntries parses legacy fTDfs LDAP entries (Windows 2000/2003 DFS).
func parseLegacyDFSEntries(entries []*ldap.Entry, domain string) map[string][]DFSLink {
	result := make(map[string][]DFSLink)
	domainLower := strings.ToLower(domain)

	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		remoteServers := entry.GetAttributeValues("remoteServerName")

		if len(remoteServers) == 0 {
			continue
		}

		namespace := extractNamespaceFromDN(dn)
		linkName := entry.GetAttributeValue("cn")
		if namespace == "" || linkName == "" {
			continue
		}

		dfsPath := fmt.Sprintf(`\\%s\%s\%s`, domainLower, namespace, linkName)

		var targets []DFSTarget
		for _, rs := range remoteServers {
			t := parseRemoteServerName(rs)
			if t.Host != "" {
				targets = append(targets, t)
			}
		}

		link := DFSLink{
			Namespace: namespace,
			LinkPath:  linkName,
			DFSPath:   dfsPath,
			Targets:   targets,
		}

		for _, t := range targets {
			key := strings.ToLower(t.Host + `\` + t.Share)
			result[key] = append(result[key], link)
		}
	}

	return result
}

// extractNamespaceFromDN extracts the DFS namespace name from a distinguished name.
// DN format: CN=<link>,CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...
func extractNamespaceFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		if strings.EqualFold(strings.TrimSpace(part), "CN=Dfs-Configuration") && i >= 2 {
			// The namespace is the CN immediately before Dfs-Configuration
			nsPart := strings.TrimSpace(parts[i-1])
			if strings.HasPrefix(strings.ToUpper(nsPart), "CN=") {
				return nsPart[3:]
			}
		}
	}
	return ""
}

// parseDFSTargetListBytes extracts server/share targets from a raw msDFS-TargetListv2 blob.
// The blob is a binary structure (MS-DFSNM wire format) that may contain UNC paths in
// either ASCII or UTF-16LE encoding. We extract UNC paths by scanning for \\ patterns.
func parseDFSTargetListBytes(raw []byte) []DFSTarget {
	var targets []DFSTarget

	// Try to decode as UTF-16LE first (common in AD binary attributes).
	// If that yields valid UNC paths, use them. Otherwise fall back to raw bytes as ASCII.
	text := decodeUTF16LEIfPresent(raw)

	remaining := text
	for {
		idx := strings.Index(remaining, `\\`)
		if idx == -1 {
			break
		}
		remaining = remaining[idx:]

		// Extract the UNC path (up to whitespace, null, or control char)
		endIdx := len(remaining)
		for i, c := range remaining[2:] {
			if c == 0 || c == '\t' || c == '\n' || c == '\r' || c == ' ' {
				endIdx = i + 2
				break
			}
		}

		uncPath := remaining[:endIdx]
		remaining = remaining[endIdx:]

		t := parseUNCToTarget(uncPath)
		if t.Host != "" && t.Share != "" {
			targets = append(targets, t)
		}
	}

	return targets
}

// decodeUTF16LEIfPresent checks if the byte slice appears to be UTF-16LE encoded
// (contains null bytes interleaved with ASCII) and decodes it. Otherwise returns
// the bytes as a plain string.
func decodeUTF16LEIfPresent(data []byte) string {
	if len(data) < 4 {
		return string(data)
	}

	// Heuristic: if the second byte is 0x00 and the first is printable ASCII,
	// it's likely UTF-16LE
	if data[1] == 0 && data[0] >= 0x20 && data[0] < 0x7f {
		var sb strings.Builder
		for i := 0; i+1 < len(data); i += 2 {
			ch := uint16(data[i]) | uint16(data[i+1])<<8
			if ch == 0 {
				sb.WriteByte(0) // preserve null terminators for boundary detection
			} else if ch < 128 {
				sb.WriteByte(byte(ch))
			} else {
				sb.WriteRune(rune(ch))
			}
		}
		return sb.String()
	}

	return string(data)
}

// parseUNCToTarget converts a UNC path like \\server\share\path to a DFSTarget.
func parseUNCToTarget(unc string) DFSTarget {
	// Remove leading backslashes
	trimmed := strings.TrimLeft(unc, `\`)
	parts := strings.SplitN(trimmed, `\`, 3)

	var t DFSTarget
	if len(parts) >= 1 {
		t.Host = parts[0]
	}
	if len(parts) >= 2 {
		t.Share = parts[1]
	}
	if len(parts) >= 3 {
		t.Path = parts[2]
	}
	return t
}

// parseRemoteServerName parses a legacy DFS remoteServerName value.
// Format is typically: *\server\share or \\server\share
func parseRemoteServerName(rs string) DFSTarget {
	return parseUNCToTarget(strings.TrimLeft(rs, "*"))
}

// deduplicateTargetsWithDFS removes targets that are physical backends of DFS links.
// For each such target, the DFS namespace path is preferred. Targets not covered by DFS are kept as-is.
// Returns the deduplicated target list and the count of removed duplicates.
func deduplicateTargetsWithDFS(targets []Target, dfsLinks map[string][]DFSLink, domain string) ([]Target, int) {
	if len(dfsLinks) == 0 {
		return targets, 0
	}

	domainLower := strings.ToLower(domain)

	// Track which DFS namespaces we need to add as scan targets
	namespacesToAdd := make(map[string]bool) // keyed by lowercase namespace name
	// Track which targets to keep (those not covered by DFS)
	var kept []Target
	removed := 0

	for _, t := range targets {
		key := strings.ToLower(t.Host + `\` + t.Share)
		if links, isDFSTarget := dfsLinks[key]; isDFSTarget {
			// This physical share is a DFS link target — skip it, add namespace(s) instead
			for _, link := range links {
				namespacesToAdd[strings.ToLower(link.Namespace)] = true
			}
			removed++
		} else {
			// Check if this target IS a DFS namespace root (the namespace share on the domain FQDN)
			// e.g., \\corp.local\namespace — only match exact domain FQDN, not arbitrary hosts
			isNamespaceRoot := false
			for _, links := range dfsLinks {
				for _, link := range links {
					if strings.EqualFold(t.Share, link.Namespace) && strings.EqualFold(t.Host, domainLower) {
						isNamespaceRoot = true
						break
					}
				}
				if isNamespaceRoot {
					break
				}
			}
			if isNamespaceRoot {
				// It's a DFS namespace root share on a DC — keep it as the canonical scan target
				t.DFSPath = fmt.Sprintf(`\\%s\%s`, domainLower, t.Share)
			}
			kept = append(kept, t)
		}
	}

	// Add DFS namespace root targets for links whose physical backends were removed.
	// We mount \\domain\namespace (the namespace root share) and let cifs follow DFS referrals.
	for nsName := range namespacesToAdd {
		// Check if we already have a target for this namespace root
		alreadyHave := false
		for _, t := range kept {
			if strings.EqualFold(t.Share, nsName) && strings.EqualFold(t.Host, domainLower) {
				alreadyHave = true
				break
			}
		}
		if !alreadyHave {
			// Add the DFS namespace root as a scan target — mount \\domain\namespace
			kept = append(kept, Target{
				Host:    domainLower,
				Share:   nsName,
				DFSPath: fmt.Sprintf(`\\%s\%s`, domainLower, nsName),
			})
		}
	}

	return kept, removed
}

// deduplicateReplicatedShares removes redundant SYSVOL and NETLOGON targets.
// These shares use DFSR replication and serve identical content on every DC, so scanning one is sufficient.
// Any host exposing these shares is a DC by definition — we don't rely on the DNS SRV DC list
// because SRV records often only contain a subset of DCs in large environments.
func deduplicateReplicatedShares(targets []Target, domain string) ([]Target, int) {
	// Well-known DFSR-replicated shares present on every DC
	replicatedShares := map[string]bool{
		"sysvol":   true,
		"netlogon": true,
	}

	// Track which replicated shares we've already kept (keyed by lowercase share name)
	seen := make(map[string]bool)
	var kept []Target
	removed := 0

	for _, t := range targets {
		shareLower := strings.ToLower(t.Share)

		if replicatedShares[shareLower] {
			if seen[shareLower] {
				removed++
				continue
			}
			seen[shareLower] = true
			// Tag the kept target with a DFS path for cleaner output
			if t.DFSPath == "" {
				t.DFSPath = fmt.Sprintf(`\\%s\%s`, strings.ToLower(domain), shareLower)
			}
		}
		kept = append(kept, t)
	}

	return kept, removed
}

// compileExcludedShares pre-compiles exclusion patterns into regexps.
// Invalid patterns are compiled as case-insensitive literal matches.
func compileExcludedShares(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			// If invalid regex, fall back to literal match
			re = regexp.MustCompile("(?i)^" + regexp.QuoteMeta(pattern) + "$")
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// isSigningError returns true if the error indicates an SMB signing negotiation failure,
// which typically means authentication was rejected or downgraded to guest on a host that
// requires signing.
func isSigningError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "signing required") ||
		strings.Contains(msg, "doesn't support signing")
}

// isShareExcluded checks if a share name should be excluded using pre-compiled patterns
func isShareExcluded(shareName string, compiledExclusions []*regexp.Regexp) bool {
	for _, re := range compiledExclusions {
		if re.MatchString(shareName) {
			return true
		}
	}
	return false
}

// checkShareAccess verifies read access to a share by stat-ing its root directory
func checkShareAccess(session *smb2.Session, shareName string) bool {
	share, err := session.Mount(shareName)
	if err != nil {
		return false
	}
	defer share.Umount()

	// Stat checks directory open permission. Cheaper than ReadDir (which fetches
	// all entries) but may succeed on shares where listing is denied. The scan
	// phase will catch those failures.
	_, err = share.Stat(".")
	return err == nil
}

func parseArgs() Config {
	var config Config
	var additionalExts string
	var additionalFolders string
	var keywords string
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
	flag.StringVar(&keywords, "keywords", "", "Filename substrings to always include in scanning (comma-separated)")
	flag.StringVar(&keywords, "kw", "", "Filename substrings to always include (shorthand)")

	// Output options (note: -o is handled manually after flag.Parse for optional argument support)
	flag.StringVar(&outputFormats, "output-format", "", "Output formats to save (comma-separated: txt,json,jsonl,sarif,tabularium)")
	flag.StringVar(&outputFormats, "of", "", "Output formats to save (shorthand)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output (show excluded files)")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output (shorthand)")
	var wantTimestamps bool
	flag.BoolVar(&wantTimestamps, "timestamp", false, "Prepend timestamp to every log line")
	flag.BoolVar(&wantTimestamps, "ts", false, "Prepend timestamp to every log line (shorthand)")

	// Discovery options (LDAPS and channel binding)
	flag.BoolVar(&config.UseLDAPS, "ldaps", false, "Force LDAPS (port 636); by default all methods are auto-negotiated")
	flag.BoolVar(&config.ChannelBinding, "channel-binding", false, "Force LDAPS with channel binding (NTLM); by default auto-negotiated")
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
	flag.BoolVar(&config.QuickMode, "quick", false, "Quick mode: only scan high-value file types")
	flag.BoolVar(&config.QuickMode, "q", false, "Quick mode (shorthand)")
	flag.BoolVar(&config.ZipOutput, "zip", false, "Zip txt/json output files into a single archive and delete originals")
	flag.BoolVar(&config.ZipOutput, "z", false, "Zip txt/json output files (shorthand)")

	// Concurrency options
	flag.IntVar(&config.ShareWorkers, "share-workers", 60, "Number of parallel share workers")
	flag.IntVar(&config.ShareWorkers, "jt", 60, "Number of parallel share workers (shorthand)")
	flag.IntVar(&config.FileWorkers, "file-workers", 0, "Number of parallel file scanning goroutines per share (default: NumCPU)")
	flag.IntVar(&config.FileWorkers, "jf", 0, "Number of parallel file scanning goroutines per share (shorthand)")

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
		logln("  --channel-binding   Force LDAPS with channel binding only (no fallback)")
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
		logln("  --output-format, -of  Output formats to save (comma-separated: txt,json,jsonl,sarif,tabularium)")
		logln("                        Default: txt. Requires -o flag.")
		logln("  --zip, -z           Zip all txt/json output files and delete originals. Requires -o flag.")
		logln("  -v                  Verbose output (show excluded files)")
		logln("\nScanning:")
		logln("  --quick, -q              Quick mode: high-value files only, depth 5, 15 min/share")
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
	validFormats := map[string]bool{"txt": true, "json": true, "jsonl": true, "sarif": true, "tabularium": true}
	if outputFormats != "" {
		for _, format := range strings.Split(outputFormats, ",") {
			format = strings.TrimSpace(strings.ToLower(format))
			if !validFormats[format] {
				logf("Error: Invalid output format '%s'. Valid formats: txt, json, jsonl, sarif\n", format)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs[0]
	}

	// If resolution fails, return original host
	return host
}

// smbConnect establishes an SMB session and mounts the target share.
// The caller must call share.Umount() and session.Logoff() when done.
func smbConnect(ctx context.Context, config Config) (net.Conn, *smb2.Session, *smb2.Share, error) {
	ip := resolveHostToIP(config.Host, config.DNSServer)

	conn, err := net.DialTimeout("tcp", ip+":445", 3*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("SMB connection to %s (%s) failed: %w", config.Host, ip, err)
	}

	// Cap SMB negotiation + auth + mount to 30s total
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     config.Username,
			Password: config.Password,
			Domain:   config.Domain,
		},
	}

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("SMB auth to %s failed: %w", config.Host, err)
	}

	share, err := session.Mount(config.Share)
	if err != nil {
		session.Logoff()
		return nil, nil, nil, fmt.Errorf("mount %s\\%s failed: %w", config.Host, config.Share, err)
	}

	// Clear deadline so scanning isn't capped
	conn.SetDeadline(time.Time{})

	return conn, session, share, nil
}

// smbWalkDir recursively walks a share, calling fn for each file entry.
// Directories are filtered by shouldExcludeDir before recursion.
// dirCount is atomically incremented for each directory entered.
func smbWalkDir(ctx context.Context, share *smb2.Share, root string,
	excludedDirs dirExclusions, maxDepth int, maxFilesPerDir int, dirCount *int64, fn func(path string, size int64) error) error {

	return smbWalkDirRecursive(ctx, share, root, excludedDirs, maxDepth, maxFilesPerDir, 0, dirCount, fn)
}

func smbWalkDirRecursive(ctx context.Context, share *smb2.Share, dir string,
	excludedDirs dirExclusions, maxDepth int, maxFilesPerDir int, currentDepth int, dirCount *int64, fn func(path string, size int64) error) error {

	if ctx.Err() != nil {
		return ctx.Err()
	}

	atomic.AddInt64(dirCount, 1)

	entries, err := share.ReadDir(dir)
	if err != nil {
		return nil // skip unreadable directories
	}

	fileCount := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := entry.Name()
		fullPath := dir + "/" + name // go-smb2 uses forward slashes

		if entry.IsDir() {
			if shouldExcludeDir(name, excludedDirs) {
				continue
			}
			if maxDepth > 0 && currentDepth >= maxDepth {
				continue
			}
			if err := smbWalkDirRecursive(ctx, share, fullPath, excludedDirs, maxDepth, maxFilesPerDir, currentDepth+1, dirCount, fn); err != nil {
				return err
			}
		} else {
			if maxFilesPerDir > 0 && fileCount >= maxFilesPerDir {
				continue
			}
			if err := fn(fullPath, entry.Size()); err != nil {
				return err
			}
			fileCount++
		}
	}
	return nil
}

// fileMatch pairs a Titus match with its source file path.
type fileMatch struct {
	match    *titustypes.Match
	filePath string
	severity Severity
}

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
	return exts
}

// dirExclusions holds both O(1) exact-match names and compiled regex patterns for directories to skip.
type dirExclusions struct {
	exact    map[string]bool
	patterns []*regexp.Regexp
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

// fileJob represents a file path and its size for scanning workers.
type fileJob struct {
	path        string
	size        int64
	interesting bool // matched keyword or quick mode allowlist
}

// interestingExclusion records a file that matched keyword/quick mode but was skipped.
type interestingExclusion struct {
	uncPath string
	size    int64
	reason  string // "binary" or "oversize"
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
func scanFileSMB(config Config, share *smb2.Share, path string, size int64, interesting bool,
	headerBuf []byte, skippedFiles *int64) ([]fileMatch, *interestingExclusion) {

	const largeFileThreshold = 50 * 1024 * 1024
	const chunkSize = 50 * 1024 * 1024
	const chunkOverlap = 4 * 1024

	displayPath := toUNCPathSMB(path, config)

	// Size gate
	if config.MaxScanSize > 0 && size > config.MaxScanSize {
		if config.Verbose {
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

	// Read header for binary detection (reuse caller-provided buffer)
	n, _ := f.Read(headerBuf)
	if n > 0 && isBinary(headerBuf[:n]) {
		if config.Verbose {
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
			if config.Verbose {
				logf("[*] Read error (skipping): %s: %v\n", displayPath, readErr)
			}
			return nil, nil
		}
		content = content[:n]

		result, scanErr := titusCore.Scan(bytesToString(content), displayPath)
		if scanErr != nil {
			if config.Verbose {
				logf("[*] Scan error (skipping): %s: %v\n", displayPath, scanErr)
			}
			return nil, nil
		}
		for _, m := range result.Matches {
			matches = append(matches, fileMatch{match: m, filePath: displayPath, severity: ruleSeverity(m.RuleID)})
		}
	} else {
		// Large file: chunked reading via smb2 file handle
		if config.Verbose {
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
						matches = append(matches, fileMatch{match: m, filePath: displayPath, severity: ruleSeverity(m.RuleID)})
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
		if config.Verbose {
			logf("%s Using default exclusions (%d extensions, %d folders)\n",
				tag, len(defaultExcludedExtensions), len(defaultExcludedFolders))
		}
	} else {
		logf("%s WARNING: Scanning all files (no exclusions enabled)\n", tag)
	}
	if len(config.AdditionalExts) > 0 || len(config.AdditionalFolders) > 0 {
		logf("%s Additional exclusions: %d extensions, %d folders\n",
			tag, len(config.AdditionalExts), len(config.AdditionalFolders))
	}

	var (
		allMatches          []fileMatch
		allInterestingExcl  []interestingExclusion
		mu                  sync.Mutex
		fileCount           int64
		dirCount            int64
		skippedFiles        int64
	)

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
				matches, excl := scanFileSMB(config, share, job.path, job.size, job.interesting, headerBuf, &skippedFiles)
				atomic.AddInt64(&fileCount, 1)
				if len(matches) > 0 || excl != nil {
					mu.Lock()
					allMatches = append(allMatches, matches...)
					if excl != nil {
						allInterestingExcl = append(allInterestingExcl, *excl)
					}
					mu.Unlock()
				}
			}
		}()
	}

	// Producer: walk share and send eligible files to workers
	err := smbWalkDir(ctx, share, ".", excludedDirs, config.MaxDepth, config.MaxFilesPerDir, &dirCount, func(path string, size int64) error {
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
				if !isQuickModeTarget(path) {
					atomic.AddInt64(&skippedFiles, 1)
					return nil
				}
			} else if shouldExcludeExt(path, excludedExts) {
				if config.Verbose {
					logf("[*] Skipping excluded: %s\n", toUNCPathSMB(path, config))
				}
				atomic.AddInt64(&skippedFiles, 1)
				return nil
			}
		}
		// Mark as interesting if keyword matched or (quick mode and passed allowlist)
		interesting := keywordMatch || config.QuickMode
		select {
		case jobs <- fileJob{path: path, size: size, interesting: interesting}:
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
	} else {
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

	// Write interesting exclusions CSV if enabled and there are entries
	if config.InterestingExcl && len(allInterestingExcl) > 0 {
		if err := writeInterestingExclusions(config, allInterestingExcl); err != nil {
			logf("%s Warning: failed to write interesting exclusions: %v\n", tag, err)
		}
	}

	if len(allMatches) == 0 {
		logf("%s No secrets discovered in this share.\n", tag)
		return stats, nil
	}

	if err := outputTitusResults(config, allMatches); err != nil {
		return stats, err
	}
	return stats, nil
}

// getOutputFilePath returns the output file path for a given format.
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

// writeInterestingExclusions writes a CSV of files that matched keywords/quick mode but were
// skipped due to binary detection or file size limits.
func writeInterestingExclusions(config Config, exclusions []interestingExclusion) error {
	// Determine filename base
	var nameBase string
	if config.Domain != "" {
		nameBase = sanitizeFilename(config.Domain)
	} else {
		nameBase = sanitizeFilename(config.Host) + "__" + sanitizeFilename(config.Share)
	}
	filename := fmt.Sprintf("%s_interesting_exclusions.csv", nameBase)

	// Determine output path
	outputPath := filename
	if config.OutputFile != "" {
		if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
			outputPath = filepath.Join(config.OutputFile, filename)
		} else if strings.HasSuffix(config.OutputFile, "/") || strings.HasSuffix(config.OutputFile, string(os.PathSeparator)) {
			outputPath = filepath.Join(config.OutputFile, filename)
		}
	}

	var buf strings.Builder
	buf.WriteString("unc_path,file_size,exclude_reason\n")
	for _, e := range exclusions {
		buf.WriteString(fmt.Sprintf("%s,%d,%s\n", e.uncPath, e.size, e.reason))
	}

	if err := os.WriteFile(outputPath, []byte(buf.String()), 0644); err != nil {
		return err
	}
	createdFiles.add(outputPath)
	logf("[+] Interesting exclusions written to %s (%d entries)\n", outputPath, len(exclusions))
	return nil
}

// outputTitusResults writes scan results to stdout and, if configured, to output files.
func outputTitusResults(config Config, matches []fileMatch) error {
	// Always output human-readable text to stdout
	outputTitusText(os.Stdout, matches)

	if config.SaveOutput && config.OutputFile != "" {
		var formats []string
		for _, f := range config.OutputFormats {
			if f != "tabularium" {
				formats = append(formats, f)
			}
		}
		if len(formats) == 0 {
			formats = []string{"txt"}
		}

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
			FilePath string           `json:"file_path"`
			Severity string           `json:"severity"`
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
			FilePath string           `json:"file_path"`
			Severity string           `json:"severity"`
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

