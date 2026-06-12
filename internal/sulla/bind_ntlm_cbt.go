package sulla

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// ntlmChallengeBindRequest is the subset of ldap.NTLMBindRequest fields
// bindNTLMWithCBT needs. Using our own struct keeps the tlsLDAPConn seam
// free of *ldap.NTLMBindRequest so fakes can be trivially constructed.
type ntlmChallengeBindRequest struct {
	Domain     string
	Username   string
	Password   string
	Negotiator ldap.NTLMNegotiator
}

// tlsLDAPConn is the seam between bindNTLMWithCBT and *ldap.Conn, letting
// unit tests inject a fake that captures the bind request without opening
// a real LDAP socket.
type tlsLDAPConn interface {
	TLSConnectionState() (tls.ConnectionState, bool)
	NTLMChallengeBindFunc(req ntlmChallengeBindRequest) error
}

// ntlmChallengeBindAdapter wraps *ldap.Conn to satisfy tlsLDAPConn.
type ntlmChallengeBindAdapter struct{ c *ldap.Conn }

func (a ntlmChallengeBindAdapter) TLSConnectionState() (tls.ConnectionState, bool) {
	return a.c.TLSConnectionState()
}

func (a ntlmChallengeBindAdapter) NTLMChallengeBindFunc(req ntlmChallengeBindRequest) error {
	_, err := a.c.NTLMChallengeBind(&ldap.NTLMBindRequest{
		Domain:     req.Domain,
		Username:   req.Username,
		Password:   req.Password,
		Negotiator: req.Negotiator,
	})
	return err
}

var (
	errNoTLSState  = errors.New("cbt: no TLS state on LDAP connection")
	errNoPeerCerts = errors.New("cbt: no peer certificates in TLS state")
)

// bindNTLMWithCBT performs an NTLMv2 bind with RFC 5929 tls-server-end-point
// channel binding. The 16-byte MsvAvChannelBindings AV pair is computed
// from the server's LDAPS leaf certificate and passed to CBTNegotiator,
// which in turn routes through the patched Azure/go-ntlmssp fork.
func bindNTLMWithCBT(conn tlsLDAPConn, config Config) error {
	state, ok := conn.TLSConnectionState()
	if !ok {
		return errNoTLSState
	}
	if len(state.PeerCertificates) == 0 {
		return errNoPeerCerts
	}
	cbt, err := computeMsvAvChannelBindings(state.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("cbt: %w", err)
	}
	return conn.NTLMChallengeBindFunc(ntlmChallengeBindRequest{
		Domain:     config.Domain,
		Username:   config.Username,
		Password:   config.Password,
		Negotiator: NewCBTNegotiator(config.Domain, cbt),
	})
}
