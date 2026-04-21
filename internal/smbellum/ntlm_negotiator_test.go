package smbellum

import (
	"bytes"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Compile-time assertion that CBTNegotiator satisfies ldap.NTLMNegotiator.
var _ ldap.NTLMNegotiator = (*CBTNegotiator)(nil)

// NT hash of "password" — a well-known test vector used only to exercise the
// AV-pair embedding assertion below. No security relevance.
const testNTHashPassword = "8846f7eaee8fb117ad06bdd830b7586c"

func TestCBTNegotiator_Negotiate_ReturnsNegotiateMessage(t *testing.T) {
	cbt := bytes.Repeat([]byte{0xAB}, 16)
	neg := NewCBTNegotiator("CORP", cbt)

	msg, err := neg.Negotiate("CORP", "OPS")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, []byte("NTLMSSP\x00")) {
		t.Fatalf("not an NTLMSSP message, prefix %q", msg[:8])
	}
	if msg[8] != 0x01 {
		t.Fatalf("expected NEGOTIATE (type 1) at offset 8, got %d", msg[8])
	}
}

func TestCBTNegotiator_ChallengeResponse_EmbedsMsvAvChannelBindings(t *testing.T) {
	cbt := bytes.Repeat([]byte{0xAB}, 16)
	neg := NewCBTNegotiator("CORP", cbt)

	challenge := buildSyntheticNTLMChallenge(t)
	// Non-empty hash matches production — go-ldap bind.go:578-584 always
	// passes a derived hash, never an empty string.
	auth, err := neg.ChallengeResponse(challenge, "user", testNTHashPassword)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := findAVPair(auth, 0x000A)
	if !ok {
		t.Fatal("AUTHENTICATE_MESSAGE missing MsvAvChannelBindings (AV 0x000A)")
	}
	if !bytes.Equal(got, cbt) {
		t.Fatalf("AV pair value mismatch: got %x want %x", got, cbt)
	}
}
