# SMBellum

A command-line tool to mount SMB shares and scan them for secrets using [Noseyparker](https://github.com/praetorian-inc/noseyparker).

## Requirements

- [Noseyparker](https://github.com/praetorian-inc/noseyparker) must be installed and available in your PATH

## Installation

Download the appropriate binary for your platform from the releases. 

Alternatively, build from source:

```bash
# Build for all platforms
make all

# Build for a specific platform
make linux
make windows
make mac
```

## Usage

```bash
# Scan using domain credentials
SMBellum -h dc01.corp.tld -s SYSVOL -u username -p password -d corp.tld

# Add custom filetypes/folders to exclude from scanning (see default exclusions below)
SMBellum -h 192.168.1.100 -s docs -exclude log,tmp -exclude-folder cache,backup
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
| `-o` | Save report output to given file name |
| `-v` | Verbose output |

## Default Exclusions

By default, SMBellum skips scanning files and folders that are unlikely to contain secrets:

**File Extensions:** exe, dll, so, zip, tar, gz, jpg, png, mp3, mp4, pdf, docx, xlsx, pptx, and more

**Folders:** Program Files, Windows, System32, node_modules, .git, __pycache__, vendor, and more

Use `-no-exclusion` to scan everything, or add custom exclusions with `-exclude` and `-exclude-folder`.

## Notes

- On Linux, mounting SMB shares may require `sudo` privileges
- Shares are mounted read-only for safety
- Automatically cleans up mounts on completion or interruption (Ctrl+C)
