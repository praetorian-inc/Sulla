# SMBellum

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/a2efc303-7afa-41d6-b2e0-ad622298d436" />
</p>

***

A command-line tool to scan SMB shares for sensitive data using [Noseyparker](https://github.com/praetorian-inc/noseyparker).

You can:
* Automatically discover and scan SMB shares on AD-joined hosts
* Scan a single target share without performing discovery
* Use regex filters to exclude share names, directories, or file types
* Save output in txt, json, jsonl, or sarif format

![demo](https://github.com/user-attachments/assets/1297a612-7724-4cfa-917d-4c0c09900407)


## Requirements

- [Noseyparker](https://github.com/praetorian-inc/noseyparker) must be installed (or available via Docker)
- `cifs-utils`, typically installed on Linux by default

## Installation
Ensure `cifs-utils` is installed:

```bash
# Using apt
sudo apt install cifs-utils -y
```

Install Noseyparker if not already installed. To install via Docker:

```bash
docker pull ghcr.io/praetorian-inc/noseyparker:latest
```

Next, download the appropriate SMBellum binary for your platform from [Releases](https://github.com/praetorian-inc/SMBellum/releases):
```bash
# Linux x86_64
wget -O smbellum https://github.com/praetorian-inc/SMBellum/releases/latest/download/smbellum-linux-amd64

# Linux ARM64
wget -O smbellum https://github.com/praetorian-inc/SMBellum/releases/latest/download/smbellum-linux-arm64
```

## Usage

### Domain-Wide Share Discovery

Automatically discover and scan all accessible SMB shares across an Active Directory domain:

```bash
# Discover and scan all accessible shares in domain
smbellum -dc dc01.corp.local -u admin -p secret123 -d corp.local

# Save results to a directory in txt and json format
smbellum -dc dc01.corp.local -u admin -p secret123 -d corp.local -o results/ -of txt,json
```

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

### Target Selection (mutually exclusive)

| Flag | Description |
|------|-------------|
| `--domain-controller`, `-dc` | Domain controller for AD share discovery |
| `--target-file`, `-tf` | File containing targets (CSV or UNC paths) |
| `--host`, `-h` | Target IP address or hostname |
| `--share`, `-s` | SMB share name (required with `-h`) |

### Authentication

| Flag | Description |
|------|-------------|
| `--username`, `-u` | Username for authentication (required for `-dc`) |
| `--password`, `-p` | Password for authentication (required for `-dc`) |
| `--domain`, `-d` | Domain for authentication (required for `-dc`, e.g., corp.local) |

### Discovery Options

| Flag | Description |
|------|-------------|
| `--ldaps` | Use LDAPS (port 636) instead of LDAP (port 389) |
| `--channel-binding` | Enable LDAP channel binding (requires `--ldaps`) |
| `--dns-server`, `-dns` | Custom DNS server IP for hostname resolution |

### Filtering

| Flag | Description |
|------|-------------|
| `--show-default-exclusions` | Show all default exclusions and exit |
| `--no-default-exclusions` | Disable all default exclusions (scan everything) |
| `--exclude-extensions`, `-xe` | Additional file extensions to exclude (comma-separated, supports regex) |
| `--exclude-directories`, `-xd` | Additional directories to exclude (comma-separated, supports regex) |
| `--exclude-shares`, `-xs` | Share names to exclude during discovery (comma-separated, supports regex) |

### Output

| Flag | Description |
|------|-------------|
| `--output [path]`, `-o [path]` | Save report output. Single target: filename (default: `{host}_{share}.txt`). Batch mode: directory (must exist) |
| `--output-format`, `-of` | Output formats to save (comma-separated: `txt`, `json`, `jsonl`, `sarif`). Default: `txt` |
| `--verbose`, `-v` | Verbose output (show excluded files, unreachable hosts) |

## Default Exclusions

SMBellum skips scanning files, folders, and shares that are unlikely to contain secrets.

**Shares:**
- `IPC$`, `print$`, `ADMIN$`

**File Extensions:**
- exe, dll, so, zip, tar, gz, jpg, png, mp3, mp4, pdf, docx, xlsx, pptx, and more

**Directories:**
- Program Files, Windows, System32, node_modules, .git, __pycache__, vendor, and more

Use `--show-default-exclusions` to see the complete list, or `--no-default-exclusions` to scan everything.

## Output Formats

| Format | Description |
|--------|-------------|
| `txt` | Human-readable text format (default) |
| `json` | JSON format for programmatic processing |
| `jsonl` | JSON Lines format (one finding per line) |
| `sarif` | SARIF format for integration with security tools |


## Notes

- Mounting SMB shares may require `sudo` privileges
- Shares are mounted read-only for safety
- Automatically cleans up mounts on completion or interruption (Ctrl+C)
- Discovery mode filters out disabled AD accounts and machines inactive for >4 months, ala [Snaffler](https://github.com/SnaffCon/Snaffler)
- Discovery uses 10 parallel workers for efficient share enumeration
- If noseyparker is not in PATH, SMBellum will automatically use Docker if available
