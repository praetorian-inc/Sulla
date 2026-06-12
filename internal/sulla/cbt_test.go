package sulla

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cbt-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestComputeMsvAvChannelBindings_MatchesImpacketLayout(t *testing.T) {
	cert := generateTestCert(t)

	got, err := computeMsvAvChannelBindings(cert)
	if err != nil {
		t.Fatalf("computeMsvAvChannelBindings: %v", err)
	}
	if len(got) != 16 {
		t.Fatalf("CBT value should be 16 bytes (MD5 digest), got %d", len(got))
	}

	certHash := sha256.Sum256(cert.Raw)
	appDataRaw := append([]byte("tls-server-end-point:"), certHash[:]...)
	lenPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenPrefix, uint32(len(appDataRaw)))

	var structBytes []byte
	structBytes = append(structBytes, make([]byte, 8)...) // initiator
	structBytes = append(structBytes, make([]byte, 8)...) // acceptor
	structBytes = append(structBytes, lenPrefix...)
	structBytes = append(structBytes, appDataRaw...)
	want := md5.Sum(structBytes)

	if !bytes.Equal(got, want[:]) {
		t.Fatalf("CBT bytes do not match impacket layout:\n  got:  %x\n  want: %x", got, want[:])
	}
}

func TestComputeMsvAvChannelBindings_NilCert(t *testing.T) {
	_, err := computeMsvAvChannelBindings(nil)
	if err == nil {
		t.Fatal("expected error on nil certificate")
	}
}
