# Changelog

## Unreleased

### Added
- LDAP authentication now supports RFC 5929 `tls-server-end-point` channel
  binding on the NTLMv2 bind path. SMBellum can now authenticate against
  domain controllers configured with "LDAP server channel binding token
  requirements = Always" (the Server 2025 default). Previous behavior
  silently fell back to LDAPS+simple bind, which transmits the password in
  cleartext inside the TLS tunnel.

### Changed
- **--channel-binding flag semantic (user-visible):** the flag now means
  "require NTLMv2+CBT; refuse fallback to simple bind even on failure".
  Previously it was an alias for the auto-negotiation path. Operators who
  were force-enabling the old (broken) CBT path should drop the flag — CBT
  is now attempted by default. Operators who want strict-no-fallback should
  keep the flag.
- LDAPS+NTLM success message changed from `"LDAPS with channel binding
  (NTLM)"` to `"LDAPS (NTLMv2 + channel binding)"`.

### Fixed
- **Empty tabularium proof content when paired with non-txt formats.** Running
  `-of sarif,tabularium` (or `jsonl,tabularium`, `json,tabularium`) previously
  produced a tabularium file whose embedded proof blob degraded to
  `[Could not read output file: ...]`. The aggregator in
  `generateTabulariumOutput` reads the per-share `.txt` file and pipes it
  through `redactProofContent`, but the write loop only fell back to `txt`
  when the non-tabularium format list was empty. `outputTitusResults` now
  force-includes `txt` whenever `tabularium` is requested.
- **Discovery crash on large AD environments.** Fixed a
  `runtime error: slice bounds out of range [:48] with capacity 0`
  panic originating from a go-smb2 runtime finalizer. The panic was
  reliably reproducible with `--domain-controller` scanning across
  thousands of hosts where a subset enforced SMB signing or reset TCP
  mid-RPC. Root cause was an unchecked short-read in go-smb2's
  `PacketCodec` and `session.recv` paths, exercised by a race between
  `outstandingRequests.shutdown` and a late garbage-collector-driven
  `*File.close` finalizer (typically on the `srvsvc` named pipe opened
  inside `(*Session).ListSharenames`). Fixed in the in-tree fork at
  `third_party/go-smb2` (see `NOTICE.md`).

### Dependencies
- `github.com/Azure/go-ntlmssp` now resolves to an in-tree fork at
  `./third_party/go-ntlmssp` (via go.mod `replace` directive). The fork is
  identical to upstream commit `754e69321358` plus a ~60 LoC patch that
  adds `NewAuthenticateMessageWithCBT` for channel-binding injection. See
  `third_party/go-ntlmssp/NOTICE.md`.
- `github.com/hirochachacha/go-smb2` now resolves to an in-tree fork at
  `./third_party/go-smb2` (via go.mod `replace` directive). The fork is
  identical to upstream tag `v1.1.0` plus ~30 LoC of bounds guards in
  `internal/smb2/packet.go`, `session.go`, and `conn.go` that prevent
  the finalizer-driven panic documented under "Fixed". See
  `third_party/go-smb2/NOTICE.md` for the full set of modifications.
