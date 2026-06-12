# Sulla

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/51cd1920-7ca6-46c5-94ad-ed36a9a40c96" />
</p>

***

A command-line tool to scan SMB shares for sensitive data using [Titus](https://github.com/praetorian-inc/titus).<img width="1286" height="985" alt="demo" src="https://github.com/user-attachments/assets/c58a0e1a-7462-49cd-99c9-62addd22544a" />


You can:
* Automatically discover and scan SMB shares on AD-joined hosts
* Scan a single target share without performing discovery
* Use regex filters to exclude share names, directories, or file types

* Save output in txt, json, jsonl, or sarif format

![demo](https://github.com/user-attachments/assets/cc37df6c-52f5-4f70-8321-061acba18c5e)

## Installation

Download the appropriate Sulla binary for your platform from [Releases](https://github.com/praetorian-inc/Sulla/releases):
```bash
# Linux x86_64
wget -O sulla https://github.com/praetorian-inc/Sulla/releases/latest/download/sulla-linux-amd64

# Linux ARM64
wget -O sulla https://github.com/praetorian-inc/Sulla/releases/latest/download/sulla-linux-arm64
```

### Docker

Alternatively, run Sulla via Docker without installing dependencies:

```bash
docker pull ghcr.io/praetorian-inc/sulla:latest
```

Docker usage:

```bash
docker run --rm --privileged --network=host \
  -v $(pwd):/sulla_output -w /sulla_output \
  ghcr.io/praetorian-inc/sulla:latest \
  -u admin -p secret123 -d corp.local -o results -of txt,json
```

## Usage

### Domain-Wide Share Discovery

Automatically discover and scan all accessible SMB shares across an Active Directory domain:

```bash
# Auto-discover all accessible shares and write results to txt and json files
sulla -u admin -p secret123 -d corp.local -o results/ -of txt,json
```

> Sulla discovers domain controllers via DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`). If the first DC is unreachable, it automatically tries others.

### Discovery-Only Mode

Discover accessible shares without running Titus scans. Outputs UNC paths that can be reviewed, filtered, and later used with `--target-file`:

```bash
# Discover reachable shares without secret scanning
sulla -u admin -p secret123 -d corp.local -do -o
```

Useful when:
- You need to review the full share list before scanning
- You want to manually drop specific shares without using exclusion flags

### Batch Scanning from Target File

Scan a predefined list of shares:

```bash
# Scan targets from file
sulla -tf corp_local_discovered_smb_shares.txt -u admin -p secret123 -d corp.local -o results/
```

Target file format (one per line):
```
fileserver.domain.tld,backup     # CSV format, or
\\fileserver.domain.tld\backup$  # UNC path
```

### Single Target Scanning

Scan a specific share:

```bash
# Basic scan, anonymous
sulla -h 192.168.1.100 -s public

# With domain credentials + saving output
sulla -h fileserver.corp.local -s SYSVOL -u admin -p secret123 -d corp.local -o results/
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
| `--ldaps` | Use LDAPS instead of LDAP |
| `--channel-binding` | Require NTLMv2 with RFC 5929 channel binding on LDAPS |
| `--dns-server`, `-dns` | Custom DNS server IP for hostname resolution |
| `--discovery-only`, `-do` | Discovery only: output shares in UNC format without scanning |
| `--no-dfs` | Disable DFS namespace awareness (skip DFS deduplication) |

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
| `--output-format`, `-of` | Output formats to save (comma-separated: `txt`, `json`, `jsonl`, `sarif`, `capability-sdk`). Default: `txt` |
| `--zip`, `-z` | Zip txt/json output files into a single archive and delete originals (requires `-o`) |
| `--verbose`, `-v` | Show per-share progress (connections, scan lifecycle) |
| `--debug`, `-de` | Show per-file diagnostics (skipped files, errors, chunking) |
| `--timestamp`, `-ts` | Prepend a timestamp to every log line |
| `--version` | Print version and exit |

### Scanning

**Quick mode is on by default.** Sulla only scans high-value file types (allowlisted extensions and filenames), with depth 5, 15 min/share, and 200 files/dir.

**Full mode is set with --full.** All files will be scanned for secrets, sans those in Sulla's default exclusions list. These default exclusions can be disabled with `--no-default-exclusions`. Full scans will run for much longer than Quick scans and are not recommended when scanning multiple shares.

| Flag | Description |
|------|-------------|
| `--extract`, `-x` | Extract and scan text from binary files (docx, xlsx, pptx, pdf, archives, etc.) |
| `--full`, `-f` | Full scan: disable the default quick-mode allowlist and tighter limits |
| `--max-scan-size`, `-ms` | Max file size to scan in MB (default: 5, 0 = no limit) |
| `--max-depth`, `-md` | Max directory recursion depth (default: 5 in quick mode, 0 = unlimited with `--full`) |
| `--max-share-time`, `-mst` | Max time per share in minutes (default: 15 in quick mode, 45 with `--full`; 0 = indefinite) |
| `--max-files-per-dir`, `-mf` | Max files to scan per directory (default: 200 in quick mode, 0 = unlimited with `--full`) |

### Concurrency

| Flag | Description |
|------|-------------|
| `--share-workers`, `-jt` | Parallel share workers (default: 60) |
| `--file-workers`, `-jf` | Parallel file scanners per share (default: NumCPU) |

## Default Exclusions

Sulla skips scanning files, folders, and shares that are unlikely to contain secrets.

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
| `capability-sdk` | JSON file matching the [capability-sdk](https://github.com/praetorian-inc/capability-sdk) `capmodel` wire format (discovery mode only). Written as `<domain>.tabularium`. The evidence blob redacts match values from its embedded proof content. `tabularium` is accepted as a deprecated alias for one release |

> **Note:** Redaction applies only to the `capability-sdk` format. The `txt`, `json`, `jsonl`, and `sarif` outputs contain raw match content and should be handled as sensitive.


## Notes

- Discovery mode filters out disabled AD accounts and machines inactive for >4 months, a la [Snaffler](https://github.com/SnaffCon/Snaffler)
- Only shares with read access are reported during discovery
- Secret scanning is powered by [Titus](https://github.com/praetorian-inc/titus), a Go port of NoseyParker
