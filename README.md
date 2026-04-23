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

![demo](https://github.com/user-attachments/assets/bfab2548-e54d-4a48-aa6c-bc299baf983c)

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

## Usage

### Domain-Wide Share Discovery

Automatically discover and scan all accessible SMB shares across an Active Directory domain:

```bash
# Auto-discover all accessible shares in quick mode and write to txt/json
smbellum -u admin -p secret123 -d corp.local -o results/ -of txt,json --quick
```

> SMBellum discovers domain controllers via DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`). If the first DC is unreachable, it automatically tries others.

### Discovery-Only Mode

Discover accessible shares without running Titus scans. Outputs UNC paths that can be reviewed, filtered, and later used with `--target-file`:

```bash
# Discover reachable shares without secret scanning
smbellum -u admin -p secret123 -d corp.local -do -o
```

Useful when:
- You need to review the full share list before scanning
- You want to manually drop specific shares without using exclusion flags

### Batch Scanning from Target File

Scan a predefined list of shares:

```bash
# Scan targets from file
smbellum -tf corp_local_discovered_smb_shares.txt -u admin -p secret123 -d corp.local -o results/ --quick
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
smbellum -h fileserver.corp.local -s SYSVOL -u admin -p secret123 -d corp.local -o results/
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
| `--channel-binding` | Require NTLMv2 with RFC 5929 channel binding on LDAPS) |
| `--dns-server`, `-dns` | Custom DNS server IP for hostname resolution |
| `--discovery-only`, `-do` | Discovery only: output shares in UNC format without scanning |

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
| `--verbose`, `-v` | Verbose output (show excluded files, unreachable hosts) |

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
- Secret scanning is powered by [Titus](https://github.com/praetorian-inc/titus), a Go port of NoseyParker
