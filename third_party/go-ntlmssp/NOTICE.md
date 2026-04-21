# Modifications to github.com/Azure/go-ntlmssp

This directory contains a modified copy of github.com/Azure/go-ntlmssp,
originally licensed under MIT (see LICENSE in this directory). The
upstream base commit is `754e69321358`.

## Modifications by Praetorian Security, Inc.

- Added `NewAuthenticateMessageWithCBT` to `authenticate_message.go`.
  This accepts a pre-computed 16-byte channel binding value and injects
  it as the `MsvAvChannelBindings` AV pair (AV ID 0x000A) in the NTLMv2
  AUTHENTICATE_MESSAGE, per MS-NLMP §3.1.5.1.2.
- Added channel-binding AV pair helpers in `channel_binding.go`.
- Added `channel_binding_test.go`.

No existing exported function signatures were changed. `ProcessChallenge`
and `ProcessChallengeWithHash` still return identical bytes for all inputs
they previously accepted — internally they now delegate to a shared
`buildAuthenticateMessage` helper that also powers the new
`NewAuthenticateMessageWithCBT` / `NewAuthenticateMessageWithCBTWithHash`
exports. Callers of `NewNegotiateMessage`, `ProcessChallenge`, or
`ProcessChallengeWithHash` observe no behavior change.
