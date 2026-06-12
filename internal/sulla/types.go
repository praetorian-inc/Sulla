package sulla

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	titusscanner "github.com/praetorian-inc/titus/pkg/scanner"
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

type Config struct {
	Host              string
	Share             string
	Username          string
	Password          string
	Domain            string
	NoExclusion       bool
	AdditionalExts    []string
	AdditionalFolders []string
	ExcludedShares    []string
	SaveOutput        bool
	OutputFile        string
	OutputFormats     []string // Output formats: txt, json, jsonl, sarif, capability-sdk
	Verbose           bool
	Debug             bool // --debug: show per-file diagnostics (skipped files, errors, chunking)
	TargetsFile       string
	DomainController  string
	UseLDAPS          bool             // Use LDAPS (port 636) instead of LDAP (port 389)
	ChannelBinding    bool             // Require NTLMv2+CBT on LDAPS; disables simple-bind fallback
	DNSServer         string           // Custom DNS server IP for lookups
	DiscoveryOnly     bool             // Discovery-only mode: output shares without scanning
	DiscoveryResult   *DiscoveryResult // AD discovery metadata for capability-sdk output
	ShareWorkers      int              // Number of parallel share workers (default 60)
	FileWorkers       int              // Number of parallel file scanning goroutines per share (default NumCPU)
	NoDFS             bool             // Disable DFS namespace awareness
	DFSPath           string           // DFS namespace path for this target (set during dedup)
	MaxScanSize       int64            // Maximum file size to scan in bytes (default 5MB, 0 = no limit)
	MaxDepth          int              // Maximum directory recursion depth (0 = unlimited)
	MaxShareTime      int              // Maximum time per share in minutes (0 = indefinite, default 45)
	MaxFilesPerDir    int              // Maximum files to scan per directory (0 = unlimited)
	QuickMode         bool             // Quick mode: only scan high-value file types
	Keywords          []string         // Additional filename substrings to always include in scanning
	InterestingExcl   bool             // Write interesting exclusions (keyword/quick match but skipped) to CSV (on when -o is set)
	ZipOutput         bool             // Zip txt/json output files into a single archive, then delete originals
	ExtractBinary     bool             // --extract: enable text extraction from binary files (docx, xlsx, pdf, etc.)
	TargetNum         int              // Current target number (1-based, for progress display)
	TotalTargets      int              // Total number of targets (for progress display)
	// Pre-computed exclusions (built once, shared across all targets)
	ExcludedExts map[string]bool // Extension exclusion set
	ExcludedDirs dirExclusions   // Directory exclusion (exact + regex)
	// Live status tracking (shared across all share goroutines)
	Tracker *shareTracker
}

// Target represents a single host/share combination to scan
type Target struct {
	Host    string
	Share   string
	DFSPath string // Canonical DFS namespace path (e.g., \\corp.local\dfs\link), empty if not a DFS target
}

// ComputerInfo holds AD computer metadata for capability-sdk output
type ComputerInfo struct {
	DNSHostName       string
	SID               string
	DistinguishedName string
}

// DomainInfo holds AD domain metadata for capability-sdk output
type DomainInfo struct {
	Name              string
	SID               string
	DistinguishedName string
}

// DiscoveryResult holds the results of AD discovery for capability-sdk output
type DiscoveryResult struct {
	Domain    DomainInfo
	Computers map[string]ComputerInfo // keyed by DNSHostName
}

// ScanResult holds the outcome of scanning a single target
type ScanResult struct {
	Host        string
	Share       string
	Error       error
	HasFindings bool   // Whether Titus found any secrets
	OutputPath  string // Path to the output file (for capability-sdk proof aggregation)
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
	"zip", "tar", "gz", "tar.gz", "bz2", "xz", "7z", "rar", "iso", "dmg",
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
	"np.aws.2":        SeverityCritical, // AWS Secret Access Key
	"np.aws.4":        SeverityCritical, // AWS Session Token
	"np.aws.5":        SeverityCritical, // Amazon MWS Auth Token
	"np.aws.6":        SeverityCritical, // Amazon API Credentials
	"np.azure.1":      SeverityCritical, // Azure Connection String
	"np.azure.2":      SeverityCritical, // Azure App Configuration Connection String
	"np.azure.3":      SeverityCritical, // Azure Personal Access Token
	"np.azure.4":      SeverityCritical, // Azure DevOps Personal Access Token
	"np.hashicorp.1":  SeverityCritical, // Hashicorp Vault Service Token (< v1.10)
	"np.hashicorp.2":  SeverityCritical, // Hashicorp Vault Batch Token (< v1.10)
	"np.hashicorp.3":  SeverityCritical, // Hashicorp Vault Recovery Token (< v1.10)
	"np.hashicorp.4":  SeverityCritical, // Hashicorp Vault Service Token (>= v1.10)
	"np.hashicorp.5":  SeverityCritical, // Hashicorp Vault Batch Token (>= v1.10)
	"np.hashicorp.6":  SeverityCritical, // Hashicorp Vault Recovery Token (>= v1.10)
	"np.hashicorp.7":  SeverityCritical, // Hashicorp Vault Unseal Key
	"np.pem.1":        SeverityCritical, // PEM-Encoded Private Key
	"np.pem.2":        SeverityCritical, // Base64-PEM-Encoded Private Key
	"np.wireguard.1":  SeverityCritical, // WireGuard Private Key
	"np.wireguard.2":  SeverityCritical, // WireGuard Preshared Key
	"np.kubernetes.1": SeverityCritical, // Kubernetes Bootstrap Token
	"np.kubernetes.2": SeverityCritical, // Kubernetes Bootstrap Token
	"np.mongodb.1":    SeverityCritical, // Credentials in MongoDB Connection String
	"np.postgres.1":   SeverityCritical, // Credentials in PostgreSQL Connection URI
	"np.odbc.1":       SeverityCritical, // Credentials in ODBC Connection String
	"np.redis.1":      SeverityCritical, // Redis URI Connection String
	"np.redis.2":      SeverityCritical, // Python Redis Client Debug Output
	"np.netrc.1":      SeverityCritical, // netrc Credentials
	"np.psexec.1":     SeverityCritical, // Credentials in PsExec Command
	"np.vmware.1":     SeverityCritical, // Credentials in Connect-VIServer Command
	"np.jenkins.2":    SeverityCritical, // Jenkins Setup Admin Password
	"np.generic.1":    SeverityCritical, // Generic Secret
	"np.generic.3":    SeverityCritical, // Generic Username and Password
	"np.generic.4":    SeverityCritical, // Generic Username and Password
	"np.generic.5":    SeverityCritical, // Generic Password
	"np.generic.6":    SeverityCritical, // Generic Password
	"np.generic.7":    SeverityCritical, // Credentials in .NET System.Net.NetworkCredential
	"np.generic.8":    SeverityCritical, // Credentials in .NET System.DirectoryServices.DirectoryEntry
	"np.generic.9":    SeverityCritical, // Sensitive value in .NET configuration
	"np.generic.10":   SeverityCritical, // Connection string in .NET configuration
	"np.generic.11":   SeverityCritical, // Generic Password
	"np.generic.12":   SeverityCritical, // Generic Password
	"np.generic.13":   SeverityCritical, // Generic Credentials
	"np.generic.14":   SeverityCritical, // Generic Credentials
	"np.generic.15":   SeverityCritical, // Generic Secret
	"np.generic.16":   SeverityCritical, // Generic Secret
	"np.http.1":       SeverityCritical, // HTTP Basic Authentication
	"np.age.2":        SeverityCritical, // Age Identity (X22519 secret key)
	"np.jwt.2":        SeverityCritical, // JSON Web Token Secret
	"np.jwt.3":        SeverityCritical, // JSON Web Token Secret
	"np.okta.1":       SeverityCritical, // Okta API Token
	"np.django.1":     SeverityCritical, // Django Secret Key
	"np.gradle.1":     SeverityCritical, // Hardcoded Gradle Credentials
	"np.phpmailer.1":  SeverityCritical, // PHPMailer Credentials
	"np.auth0.1":      SeverityCritical, // Auth0 Application Credentials
	"np.gitalk.1":     SeverityCritical, // Gitalk OAuth Credentials
	"np.google.6":     SeverityCritical, // Google OAuth Credentials
	"np.reactapp.1":   SeverityCritical, // React App Username
	"np.reactapp.2":   SeverityCritical, // React App Password

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
	".htaccess":  true,
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

// fileMatch pairs a Titus match with its source file path.
type fileMatch struct {
	match    *titustypes.Match
	filePath string
	severity Severity
}

// dirExclusions holds both O(1) exact-match names and compiled regex patterns for directories to skip.
type dirExclusions struct {
	exact    map[string]bool
	patterns []*regexp.Regexp
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
