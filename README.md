# Sulla

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/21ffdb8d-a18d-42a6-9c5e-f4f4c0978b41" />
</p>

A command-line tool to scan SMB shares for sensitive data using [Titus](https://github.com/praetorian-inc/titus).

You can:
* Automatically discover and scan SMB shares on AD-joined hosts
* Scan a single target share without performing discovery
* Use regex filters to exclude share names, directories, or file types

* Save output in txt, json, jsonl, or sarif format

![demo](https://github.com/user-attachments/assets/70323c53-5d09-4ae0-981a-41ecf3eb5e38)

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

### Pivoting through a SOCKS5 proxy

Go binaries make network syscalls directly and bypass libc, so `proxychains` (which hooks libc via `LD_PRELOAD`) has no effect on Sulla. Use the native `--socks5` flag to pivot through a SOCKS5 proxy such as `ssh -D`, [chisel](https://github.com/jpillora/chisel), or [Ligolo-ng](https://github.com/nicocha30/ligolo-ng):

```bash
# Bring up a SOCKS5 proxy into the target network (example: SSH dynamic forward)
ssh -D 1080 -N pivot-host

# Scan a single share through the proxy
sulla --socks5 127.0.0.1:1080 -h fileserver.corp.local -s Data -u admin -p secret -d corp.local

# Domain-wide discovery through the proxy, resolving names via an internal DNS server
sulla --socks5 127.0.0.1:1080 -dns 10.0.0.10 -u admin -p secret -d corp.local -do

# Domain-wide discovery naming the DC explicitly (no DNS server needed)
sulla --socks5 127.0.0.1:1080 -dc dc01.corp.local -u admin -p secret -d corp.local -do

# Authenticated proxy
sulla --socks5 user:pass@127.0.0.1:1080 -dns 10.0.0.10 -u admin -p secret -d corp.local -do
```

Behavior when a proxy is set:

- **All traffic is proxied** — SMB (445), LDAP/LDAPS (389/636), and DNS.
- **DNS resolution.** By default, hostnames are resolved by the proxy at the pivot host (like proxychains `proxy_dns`). This works only if the pivot host can resolve the target names. When it can't — a common case — add `-dns <internal-ip>` and Sulla tunnels DNS **over TCP through the proxy** to that server, so internal names (including hosts discovered from AD) resolve correctly.
- **Domain discovery needs `-dns` or `-dc`.** SRV-based DC auto-discovery requires DNS, which can't traverse SOCKS over UDP. Either pass `-dns <internal-ip>` (auto-discovery then works end to end through a bare `ssh -D` tunnel), or name a controller explicitly with `-dc <host>`. Without either, Sulla exits with an error.

> Docker users: point Sulla at a proxy on the host with `--socks5 host.docker.internal:1080`.

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
| `--dns-server`, `-dns` | Custom DNS server IP for hostname resolution. With `--socks5`, queries are tunneled over TCP through the proxy |
| `--socks5`, `--socks` | Route all traffic (SMB, LDAP, DNS) through a SOCKS5 proxy: `[user:pass@]host:port`. See [Pivoting through a SOCKS5 proxy](#pivoting-through-a-socks5-proxy) |
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

### Custom Rules

Bring your own [Titus](https://github.com/praetorian-inc/titus) detection rules for secrets specific to your environment.

| Flag | Description |
|------|-------------|
| `--custom-rules`, `-cr` | Custom rule files or directories, added to the built-in rules (comma-separated). Each path is a `.yml`/`.yaml` file or a directory that is walked recursively |
| `--custom-rules-only`, `-cro` | Scan with **only** the custom rules, ignoring the built-in ruleset (requires `--custom-rules`) |

Rules use the NoseyParker/Titus YAML format, **one rule per file**. A minimal rule:

```yaml
rules:
- name: Acme Internal Token
  id: acme.token.1
  pattern: 'ACME-[A-Z0-9]{10}'
```

```bash
# Add a single custom rule on top of the built-in ruleset
sulla -h fileserver.corp.local -s Data --custom-rules ./acme-token.yml

# Load every rule in a directory
sulla -u admin -p secret -d corp.local -cr ./my-rules/

# Scan using only your custom rules
sulla -h fileserver.corp.local -s Data -cr ./my-rules/ --custom-rules-only
```

By default custom rules are **additive** to the built-in ruleset. Use `--custom-rules-only` to scan with just your own rules.

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
