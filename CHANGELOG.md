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

### Dependencies
- `github.com/Azure/go-ntlmssp` now resolves to an in-tree fork at
  `./third_party/go-ntlmssp` (via go.mod `replace` directive). The fork is
  identical to upstream commit `754e69321358` plus a ~60 LoC patch that
  adds `NewAuthenticateMessageWithCBT` for channel-binding injection. See
  `third_party/go-ntlmssp/NOTICE.md`.
