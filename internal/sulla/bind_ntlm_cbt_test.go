package sulla

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

type fakeTLSConn struct {
	state   tls.ConnectionState
	stateOK bool
	bindErr error
	bindReq *bindRequestCapture
}

type bindRequestCapture struct {
	domain, username, password string
	hasNegotiator              bool
}

func (f *fakeTLSConn) TLSConnectionState() (tls.ConnectionState, bool) {
	return f.state, f.stateOK
}

func (f *fakeTLSConn) NTLMChallengeBindFunc(req ntlmChallengeBindRequest) error {
	f.bindReq = &bindRequestCapture{
		domain:        req.Domain,
		username:      req.Username,
		password:      req.Password,
		hasNegotiator: req.Negotiator != nil,
	}
	return f.bindErr
}

func TestBindNTLMWithCBT_NoTLSState_Errors(t *testing.T) {
	fc := &fakeTLSConn{stateOK: false}
	err := bindNTLMWithCBT(fc, Config{Domain: "CORP", Username: "u", Password: "p"})
	if !errors.Is(err, errNoTLSState) {
		t.Fatalf("expected errNoTLSState, got %v", err)
	}
}

func TestBindNTLMWithCBT_NoPeerCerts_Errors(t *testing.T) {
	fc := &fakeTLSConn{stateOK: true, state: tls.ConnectionState{PeerCertificates: nil}}
	err := bindNTLMWithCBT(fc, Config{Domain: "CORP", Username: "u", Password: "p"})
	if !errors.Is(err, errNoPeerCerts) {
		t.Fatalf("expected errNoPeerCerts, got %v", err)
	}
}

func TestBindNTLMWithCBT_Success_CallsNTLMChallengeBindWithNegotiator(t *testing.T) {
	cert := generateTestCert(t)
	fc := &fakeTLSConn{
		stateOK: true,
		state:   tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
	}
	if err := bindNTLMWithCBT(fc, Config{Domain: "CORP", Username: "u", Password: "p"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fc.bindReq == nil {
		t.Fatal("NTLMChallengeBind was not called")
	}
	if !fc.bindReq.hasNegotiator {
		t.Error("bind request did not carry a negotiator")
	}
	if fc.bindReq.domain != "CORP" || fc.bindReq.username != "u" {
		t.Errorf("credentials not passed through: %+v", fc.bindReq)
	}
}

func TestBindNTLMWithCBT_BindError_Propagates(t *testing.T) {
	cert := generateTestCert(t)
	fc := &fakeTLSConn{
		stateOK: true,
		state:   tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		bindErr: errors.New("bind failed: wrong password"),
	}
	err := bindNTLMWithCBT(fc, Config{Domain: "CORP", Username: "u", Password: "wrong"})
	if err == nil || !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected bind error to propagate, got %v", err)
	}
}
