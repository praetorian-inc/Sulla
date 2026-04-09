# SMBellum File Filtering

SMBellum applies six filtering layers when deciding which files to scan. Each layer is evaluated in order — if a file is rejected at any layer, later layers never run.

Custom exclusions are always additive to the defaults. Use `--no-default-exclusions` to start from a clean slate.

## Layer 1: Directory Exclusion

**Where:** `smbWalkDirRecursive` — during SMB directory traversal

Entire directories are skipped by name before any files inside them are seen. Matching is case-sensitive against the directory name (not the full path).

Default excluded directories include:
- **Windows:** `Program Files`, `Program Files (x86)`, `Windows`, `System32`, `SysWOW64`, `WinSxS`, `$Recycle.Bin`, `ProgramData`
- **macOS:** `Library`, `Applications`
- **Linux:** `proc`, `sys`, `dev`, `boot`
- **Development:** `node_modules`, `.git`, `__pycache__`, `vendor`

User additions via `--exclude-directories` / `-xd` are appended to this list. Supports regex patterns.

Disabled entirely with `--no-default-exclusions`.

## Layer 2: Max Depth

**Where:** `smbWalkDirRecursive` — during SMB directory traversal

If `--max-depth` / `-md` is set, subdirectories beyond that depth are not entered. Depth 1 means only the root of the share is scanned.

Default: unlimited (0).

## Layer 3: Max Files Per Directory

**Where:** `smbWalkDirRecursive` — during SMB directory traversal

If `--max-files-per-dir` / `-mf` is set, only the first N files in each directory are passed to the scan callback. Remaining files in that directory are silently skipped.

Default: unlimited (0).

---

*Layers 1-3 are structural limits applied during directory traversal. They cannot be overridden by keywords or any other file-level filter.*

---

## Layer 4: File Selection (Keywords / Quick Mode / Extension Exclusion)

**Where:** Walk callback in `runTitusScanSMB`

This is the main content-relevance filter. It determines whether a file is worth scanning based on its name. The logic depends on which mode is active:

### Keywords (highest priority)

If `--keywords` / `-kw` is set, the filename (case-insensitive) is checked for substring matches against the keyword list. **A keyword match overrides all other Layer 4 logic** — the file is scanned regardless of quick mode or extension exclusions.

Example: `-k cohesity,veeam` would scan `cohesity_backup.dat` even though `.dat` is normally excluded.

### Quick Mode (`--quick` / `-q`)

When quick mode is active (and no keyword matched), the file must appear in one of three allowlists:

| Allowlist | Match type | Examples |
|---|---|---|
| Exact filenames | Full filename match | `id_rsa`, `ntds.dit`, `shadow`, `.htpasswd`, `web.config` |
| Substring patterns | Filename contains string | `dockerfile`, `.env`, `terraform.tfvars`, `credentials`, `password`, `secret` |
| Extensions | File extension match | `.pem`, `.key`, `.env`, `.yaml`, `.conf`, `.ps1`, `.sql`, `.bak` |

Files not matching any allowlist are skipped.

### Normal Mode (default)

When neither keywords matched nor quick mode is active, the file's extension is checked against the exclusion set. Files with excluded extensions are skipped; everything else is scanned.

Default excluded extensions include: `exe`, `dll`, `so`, `zip`, `tar`, `gz`, `jpg`, `png`, `mp4`, `pdf`, `ttf`, `dat`, `pak`, and many others (binaries, media, archives, fonts).

User additions via `--exclude-extensions` / `-xe` are appended to this list.

Disabled entirely with `--no-default-exclusions`.

### Layer 4 Decision Flow

```
Keyword match?
  yes → SCAN
  no  → Quick mode?
          yes → In allowlist?
                  yes → SCAN
                  no  → SKIP
          no  → Extension excluded?
                  yes → SKIP
                  no  → SCAN
```

## Layer 5: Max File Size

**Where:** `scanFileSMB` — after file is selected for scanning

If the file exceeds `--max-scan-size` / `-ms` (in MB), it is skipped without being opened.

Default: 5 MB.  Set to 0 for no limit.

## Layer 6: Binary Detection

**Where:** `scanFileSMB` — after opening the file

The first 512 bytes of the file are read and inspected for binary content (null bytes and other non-text indicators). Binary files are skipped since secret-scanning rules target text content.

This check cannot be disabled.
