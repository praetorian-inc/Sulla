# SMBellum

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/a2efc303-7afa-41d6-b2e0-ad622298d436" />
</p>

***

A command-line tool to scan SMB shares for sensitive data using [Titus](https://github.com/praetorian-inc/titus).

You can:
* Automatically discover and scan SMB shares on AD-joined hosts
* Scan a single target share without performing discovery
* Use regex filters to exclude share names, directories, or file types
* Save output in txt, json, jsonl, or sarif format

![demo](https://github.com/user-attachments/assets/1297a612-7724-4cfa-917d-4c0c09900407)


## Requirements

- Titus is built into the SMBellum binary — no external dependencies required

## Installation

Download the appropriate SMBellum binary for your platform from [Releases](https://github.com/praetorian-inc/SMBellum/releases):
```bash
# Linux x86_64
wget -O smbellum https://github.com/praetorian-inc/SMBellum/releases/latest/download/smbellum-linux-amd64

# Linux ARM64
wget -O smbellum https://github.com/praetorian-inc/SMBellum/releases/latest/download/smbellum-linux-arm64
```

### Docker

Alternatively, run SMBellum via Docker without installing dependencies:

```bash
docker pull ghcr.io/praetorian-inc/smbellum:latest
```

Docker usage:

```bash
docker run --rm --privileged --network=host \
  -v $(pwd):/smbellum_output -w /smbellum_output \
  ghcr.io/praetorian-inc/smbellum:latest \
  -u admin -p secret123 -d corp.local -o results -of txt,json
```

For convenience, create an alias:

```bash
alias smbellum='docker run --rm --privileged --network=host -v $(pwd):/smbellum_output -w /smbellum_output ghcr.io/praetorian-inc/smbellum:latest'

# Then use normally
smbellum -u admin -p secret123 -d corp.local
```

> **Note:** Podman users (e.g., Kali) may need to run docker with `sudo`

## Usage

### Domain-Wide Share Discovery

Automatically discover and scan all accessible SMB shares across an Active Directory domain:

```bash
# Auto-discover DC and scan all accessible shares (recommended)
smbellum -u admin -p secret123 -d corp.local

# Explicitly specify DC (skips auto-discovery)
smbellum -dc dc01.corp.local -u admin -p secret123 -d corp.local

# Use custom DNS server for DC discovery and hostname resolution
smbellum -u admin -p secret123 -d corp.local -dns 10.0.0.1

# Save results to a directory in txt and json format
smbellum -u admin -p secret123 -d corp.local -o results/ -of txt,json
```

> SMBellum discovers domain controllers via DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`). If the first DC is unreachable, it automatically tries others.

### Discovery-Only Mode

Discover accessible shares without running Titus scans. Outputs UNC paths that can be reviewed, filtered, and later used with `--target-file`:

```bash
# Discover reachable shares without secret scanning
smbellum -u admin -p secret123 -d corp.local -do -o

# Later, use discovered shares as target file input:
smbellum -tf corp_local_discovered_smb_shares.txt -u admin -p secret123 -d corp.local
```

Useful when:
- You need to review the full share list before scanning
- You want to manually drop specific shares without using exclusion flags

### Batch Scanning from Target File

Scan a predefined list of shares:

```bash
# Scan targets from file
smbellum -tf targets.txt -u admin -p secret123 -d corp.local
```

Target file format (one per line):
```
fileserver.domain.tld,backup     # CSV format
\\fileserver.domain.tld\backup$  # UNC path
```

### Single Target Scanning

Scan a specific share:

```bash
# Basic scan, anonymous
smbellum -h 192.168.1.100 -s public

# With domain credentials + saving output
smbellum -h fileserver.corp.local -s SYSVOL -u admin -p secret123 -d corp.local
```

## Options

### Target Selection

| Flag | Description |
|------|-------------|
| `-d` without `-h`/`-s`/`-tf` | Auto-discover domain controller, auto-discover all readable shares, and scan |
| `--domain-controller`, `-dc` | Explicitly specify domain controller (optional) |
| `--target-file`, `-tf` | File containing SMB shares to scan (CSV or UNC paths) |
| `--host`, `-h` | Target IP address or hostname |
| `--share`, `-s` | SMB share name (required with `--host`) |

### Authentication

| Flag | Description |
|------|-------------|
| `--username`, `-u` | Username for authentication |
| `--password`, `-p` | Password for authentication |
| `--domain`, `-d` | Fully qualified domain for authentication |

### Discovery Options

| Flag | Description |
|------|-------------|
| `--ldaps` | Use LDAPS (port 636) instead of LDAP (port 389) |
| `--channel-binding` | Require NTLMv2 with RFC 5929 channel binding on LDAPS; refuse fallback to simple bind (prevents cleartext credential exposure on CBT-enforced DCs) |
| `--dns-server`, `-dns` | Custom DNS server IP for hostname resolution |
| `--discovery-only`, `-do` | Discovery only: output shares in UNC format without scanning |
| `--no-dfs` | Disable DFS namespace awareness (skip DFS deduplication) |

### LDAP Authentication Behavior

SMBellum auto-negotiates the strongest LDAP auth available per DC:

1. **LDAPS with NTLMv2 + channel binding** — RFC 5929 `tls-server-end-point`
   CBT is embedded as the NTLMv2 `MsvAvChannelBindings` AV pair, so the bind
   succeeds against Server 2022/2025 DCs with "LDAP server channel binding
   token requirements = Always".
2. **LDAPS + simple bind** — fallback when NTLMv2 fails. Credentials transit
   as cleartext inside the TLS tunnel; use only when the TLS channel is trusted.
3. **Plain LDAP + simple bind (port 389)** — last resort for legacy DCs without
   LDAPS. Credentials are cleartext on the wire.

Use `--channel-binding` to require attempt 1 and refuse fallback — this
guarantees the operator's password never transits as cleartext, even inside
TLS, at the cost of failing against non-CBT DCs.

LDAPS certificate validation is disabled by default (matches impacket, NetExec,
BloodHound.py) because internal CA / self-signed certs are the norm in AD
environments.

### Note on NTLMSSP implementation

Channel binding required patching `github.com/Azure/go-ntlmssp` (already a
transitive dep via go-ldap) to inject the `MsvAvChannelBindings` AV pair. The
patched copy lives in-tree at `third_party/go-ntlmssp/` and is wired via a
`replace` directive in `go.mod`. Upstream remains MIT-licensed; see
`third_party/go-ntlmssp/NOTICE.md` for details on modifications.

### Filtering

| Flag | Description |
|------|-------------|
| `--show-default-exclusions` | Show all default exclusions and exit |
| `--no-default-exclusions` | Disable all default exclusions (scan everything) |
| `--exclude-extensions`, `-xe` | Additional file extensions to exclude (comma-separated, supports regex) |
| `--exclude-directories`, `-xd` | Additional directories to exclude (comma-separated, supports regex) |
| `--exclude-shares`, `-xs` | Share names to exclude during discovery (comma-separated, supports regex) |
| `--keywords`, `-kw` | Filename substrings to always include in scanning, overriding exclusions (comma-separated) |

Custom exclusions are always additive to the defaults. Use `--no-default-exclusions` to start from a clean slate.

### Output

| Flag | Description |
|------|-------------|
| `--output [path]`, `-o [path]` | Save report output. Single target: filename (default: `{host}__{share}.txt`). Batch mode: directory |
| `--output-format`, `-of` | Output formats to save (comma-separated: `txt`, `json`, `jsonl`, `sarif`, `tabularium`). Default: `txt` |
| `--zip`, `-z` | Zip txt/json output files into a single archive and delete originals (requires `-o`) |
| `--verbose`, `-v` | Show per-share progress (connections, scan lifecycle) |
| `--debug`, `-de` | Show per-file diagnostics (skipped files, errors, chunking) |
| `--timestamp`, `-ts` | Prepend a timestamp to every log line |
| `--version` | Print version and exit |

### Scanning

| Flag | Description |
|------|-------------|
| `--extract`, `-x` | Extract and scan text from binary files (docx, xlsx, pptx, pdf, archives, etc.) |
| `--quick`, `-q` | Quick mode: high-value file types only, depth 5, 15 min/share |
| `--max-scan-size`, `-ms` | Max file size to scan in MB (default: 5, 0 = no limit) |
| `--max-depth`, `-md` | Max directory recursion depth (default: 0 = unlimited) |
| `--max-share-time`, `-mst` | Max time per share in minutes (default: 45, 0 = indefinite) |
| `--max-files-per-dir`, `-mf` | Max files to scan per directory (default: 0 = unlimited) |

### Concurrency

| Flag | Description |
|------|-------------|
| `--share-workers`, `-jt` | Parallel share workers (default: 60) |
| `--file-workers`, `-jf` | Parallel file scanners per share (default: NumCPU) |

## Default Exclusions

SMBellum skips scanning files, folders, and shares that are unlikely to contain secrets.

**Shares:**
- `IPC$`, `print$`, `ADMIN$`

**File Extensions:**
- exe, dll, so, zip, tar, gz, jpg, png, mp3, mp4, pdf, docx, xlsx, pptx, and more

**Directories:**
- Program Files, Windows, System32, node_modules, .git, \_\_pycache\_\_, vendor, and more

Use `--show-default-exclusions` to see the complete list, or `--no-default-exclusions` to scan everything.

## Output Formats

| Format | Description |
|--------|-------------|
| `txt` | Human-readable text format (default) |
| `json` | JSON format for programmatic processing |
| `jsonl` | JSON Lines format (one finding per line) |
| `sarif` | SARIF format for integration with security tools |
| `tabularium` | [Tabularium](https://github.com/praetorian-inc/tabularium) format (discovery mode only). The tabularium evidence blob redacts match values from its embedded proof content |

> **Note:** Redaction applies only to the `tabularium` format. The `txt`, `json`, `jsonl`, and `sarif` outputs contain raw match content and should be handled as sensitive.


## Notes

- Discovery mode filters out disabled AD accounts and machines inactive for >4 months, a la [Snaffler](https://github.com/SnaffCon/Snaffler)
- Only shares with read access are reported during discovery
- Secret scanning is powered by [Titus](https://github.com/praetorian-inc/titus), a Go port of NoseyParker — no external binary required
