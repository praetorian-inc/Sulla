package sulla

import (
	"fmt"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// CBTNegotiator implements ldap.NTLMNegotiator by routing through our
// patched Azure/go-ntlmssp fork (third_party/go-ntlmssp) to embed the
// MsvAvChannelBindings AV pair in the NTLMv2 AUTHENTICATE_MESSAGE.
//
// Construct with a 16-byte pre-computed channelBinding value from
// computeMsvAvChannelBindings(peerCert).
//
// Note on credentials: go-ldap/ldap/v3@v3.4.12 bind.go:578-584 derives
// ntHash(Password) itself before calling ChallengeResponse, so the
// negotiator never needs to hold the password — go-ldap hands us a
// non-empty hash at call time. Pass-the-hash is fully supported without
// additional glue: the caller sets NTLMBindRequest.Hash and go-ldap passes
// it through verbatim.
type CBTNegotiator struct {
	domain         string
	channelBinding []byte
}

// NewCBTNegotiator constructs a negotiator with a pre-computed 16-byte
// channel binding value. Credentials are plumbed through the go-ldap
// NTLMBindRequest (Domain/Username/Password or Domain/Username/Hash) and
// delivered to ChallengeResponse by go-ldap.
func NewCBTNegotiator(domain string, channelBinding []byte) *CBTNegotiator {
	return &CBTNegotiator{
		domain:         domain,
		channelBinding: channelBinding,
	}
}

// Negotiate returns the NTLMSSP NEGOTIATE_MESSAGE.
func (n *CBTNegotiator) Negotiate(domain, workstation string) ([]byte, error) {
	if domain == "" {
		domain = n.domain
	}
	msg, err := ntlmssp.NewNegotiateMessage(domain, workstation)
	if err != nil {
		return nil, fmt.Errorf("cbt negotiate: %w", err)
	}
	return msg, nil
}

// ChallengeResponse produces the AUTHENTICATE_MESSAGE with AV pair 0x000A
// (MsvAvChannelBindings) set to n.channelBinding.
//
// Hash parameter: go-ldap guarantees a non-empty hex NT hash at this seam
// (bind.go:578-584 computes ntHash(Password) when NTLMBindRequest.Hash is
// blank). We always route through NewAuthenticateMessageWithCBTWithHash.
// domainNeeded=true matches upstream ProcessChallengeWithHash semantics —
// TargetName from the server challenge is preserved.
func (n *CBTNegotiator) ChallengeResponse(challenge []byte, username, hash string) ([]byte, error) {
	if hash == "" {
		return nil, fmt.Errorf("cbt challenge response: empty hash (go-ldap should derive from password before calling)")
	}
	msg, err := ntlmssp.NewAuthenticateMessageWithCBTWithHash(
		challenge, username, hash, true /* domainNeeded */, n.channelBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("cbt challenge response: %w", err)
	}
	return msg, nil
}
