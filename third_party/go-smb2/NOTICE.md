# Modifications to github.com/hirochachacha/go-smb2

This directory contains a modified copy of
[github.com/hirochachacha/go-smb2](https://github.com/hirochachacha/go-smb2),
originally licensed under BSD-3-Clause (see `LICENSE` in this directory).
The upstream base tag is `v1.1.0`.

## Modifications by Praetorian Security, Inc.

- **`internal/smb2/packet.go`** — Added length guards to `PacketCodec`
  accessors that slice fixed offsets (`SessionId`, `MessageId`, `TreeId`,
  `Command`, `Status`, `Flags`, `NextCommand`, `AsyncId`, `Signature`,
  `Data`). The original code slices `p[40:48]` and similar without
  verifying `len(p) >= 64`, which panics when `p` is a nil/empty slice.
  Guards return zero values (or an empty byte slice) for short packets,
  allowing upstream callers to surface the short response via their
  existing `InvalidResponseError` paths instead of crashing the process.
- **`session.go`** — `(*session).recv` now returns
  `&InvalidResponseError{"short response: N bytes"}` when
  `conn.recv` returns a response shorter than the 64-byte SMB2 packet
  header, before reading any fixed offsets.
- **`conn.go`** — `(*conn).recv` now distinguishes "response channel
  closed without error" from "response channel delivered nil". If the
  channel was closed and no `rr.err` was stored, it returns
  `&InvalidResponseError{"connection closed during recv"}` instead of
  `(nil, nil)`. This closes the shutdown-vs-finalizer-send race that
  allowed a garbage-collected `*File`'s finalizer to trigger the panic
  downstream.

No exported APIs were changed. No behavior changes on the happy path:
the existing tests in the upstream repository continue to pass for all
well-formed server responses. The only observable change is that a
previously process-killing panic on a malformed/empty response now
returns an `InvalidResponseError` that callers already handle.

## Why Forked

Upstream `v1.1.0` is the latest published version; no fix is available
upstream and no newer versions have been released. Smbellum exercises the
panic path reliably when scanning AD-wide share discovery against large
environments (thousands of hosts, many with signing enforcement or flaky
TCP) because `(*Session).ListSharenames` opens an internal `*File` on
the `srvsvc` named pipe whose finalizer runs on Go's shared finalizer
goroutine after the session has been torn down. A panic on that
goroutine cannot be recovered from application code.

## How To Update

1. Fetch a newer upstream tarball.
2. Replace this directory's contents with the new tarball.
3. Reapply the three patches above (or verify upstream now length-guards
   `PacketCodec` accessors and `session.recv`).
4. Run `make test` and `go test ./...` in this directory.
