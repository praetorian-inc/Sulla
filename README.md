# SMBellum

<p align="center">
  <img width="600" alt="image" src="https://github.com/user-attachments/assets/a2efc303-7afa-41d6-b2e0-ad622298d436" />
</p>

***

A command-line tool to mount SMB shares and scan them for secrets using [Noseyparker](https://github.com/praetorian-inc/noseyparker).

## Requirements

- [Noseyparker](https://github.com/praetorian-inc/noseyparker) must be installed

## Quick Installation

Install Noseyparker if not already installed. To install via Docker:

```bash
docker pull ghcr.io/praetorian-inc/noseyparker:latest
```

Next, download the appropriate SMBellum binary for your platform from [Releases](https://github.com/praetorian-inc/SMBellum/releases). 

## Usage

```bash
# Scan using domain credentials
SMBellum -h host.corp.tld -s SecretShare -u username -p password -d corp.tld

# Add custom filetypes/folders to exclude from scanning (see default exclusions below)
SMBellum -h 192.168.1.100 -s docs -exclude log,tmp -exclude-folder cache,backup

# Save report output to a file
SMBellum -h host.corp.tld -s HRData -u username -p password -d corp.tld -o
    [+] Report saved to host_corp_tld_HRData.txt

# Or:
SMBellum -h host.corp.tld -s HRData -u username -p password -d corp.tld -o custom_filename.txt
    [+] Report saved to custom_filename.txt
```

## Options

| Flag | Description |
|------|-------------|
| `-host`, `-h` | Target IP address or hostname (required) |
| `-share`, `-s` | SMB share name (required) |
| `-username`, `-u` | Username for authentication |
| `-password`, `-p` | Password for authentication |
| `-domain`, `-d` | Domain for authentication |
| `-no-exclusion` | Disable all default exclusions |
| `-exclude` | Additional file extensions to exclude (comma-separated) |
| `-exclude-folder` | Additional folder names to exclude (comma-separated) |
| `-o [filename]` | Save report output to provided file name. If no filename provided, will default to `{host}_{share}.txt` |
| `-v` | Verbose output |

## Default Exclusions

By default, SMBellum skips scanning files and folders that are unlikely to contain secrets:

**File Extensions:** exe, dll, so, zip, tar, gz, jpg, png, mp3, mp4, pdf, docx, xlsx, pptx, and more

**Folders:** Program Files, Windows, System32, node_modules, .git, __pycache__, vendor, and more

Use `-no-exclusion` to scan everything, or add custom exclusions with `-exclude` and `-exclude-folder`.

## Notes

- Mounting SMB shares may require `sudo` privileges
- Shares are mounted read-only for safety
- Automatically cleans up mounts on completion or interruption (Ctrl+C)
- Running SMBellum from Windows is pending native Windows support for Noseyparker [issue](https://github.com/praetorian-inc/noseyparker/issues/121)
