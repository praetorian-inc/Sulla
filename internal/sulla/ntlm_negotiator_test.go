package sulla

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
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

// TestCBTNegotiator_GoldenVector_MatchesImpacketByteForByte locks in the
// end-to-end CBT value flow: a fixed cert DER is hashed through
// computeMsvAvChannelBindings, compared against a hand-rolled impacket PR #1844
// reference computation, and then routed through CBTNegotiator to verify the
// 16-byte value round-trips into AV pair 0x000A of the AUTHENTICATE_MESSAGE.
// If anyone ever tweaks the fork's NTLMSSP math or our CBT math, this test
// catches drift immediately.
func TestCBTNegotiator_GoldenVector_MatchesImpacketByteForByte(t *testing.T) {
	fakeCertDER := bytes.Repeat([]byte{0xCD}, 64)

	// Reference impacket PR #1844 computation inline.
	certHash := sha256.Sum256(fakeCertDER)
	appData := append([]byte("tls-server-end-point:"), certHash[:]...)
	lenPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenPrefix, uint32(len(appData)))
	structBytes := append(make([]byte, 16), append(lenPrefix, appData...)...)
	wantCBT := md5.Sum(structBytes)

	// Production path — the x509.Certificate shim needs only .Raw populated
	// since computeMsvAvChannelBindings only reads cert.Raw.
	fakeCert := &x509.Certificate{Raw: fakeCertDER}
	gotCBT, err := computeMsvAvChannelBindings(fakeCert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCBT, wantCBT[:]) {
		t.Fatalf("computation drift:\n  got:  %x\n  want: %x (impacket reference)",
			gotCBT, wantCBT[:])
	}

	neg := NewCBTNegotiator("Domain", gotCBT)
	if _, err := neg.Negotiate("Domain", "COMPUTER"); err != nil {
		t.Fatal(err)
	}

	challenge := buildSyntheticNTLMChallenge(t)
	auth, err := neg.ChallengeResponse(challenge, "User", testNTHashPassword)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := findAVPair(auth, 0x000A)
	if !ok {
		t.Fatal("AV pair 0x000A missing from AUTHENTICATE_MESSAGE")
	}
	if !bytes.Equal(got, wantCBT[:]) {
		t.Fatalf("AV pair drift:\n  got:  %x\n  want: %x", got, wantCBT[:])
	}
}
