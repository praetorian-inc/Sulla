package sulla

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// computeMsvAvChannelBindings produces the 16-byte MsvAvChannelBindings AV
// pair value (MS-NLMP §2.2.2.1 AvId 0x000A) for an LDAPS peer certificate,
// byte-for-byte compatible with impacket PR #1844.
//
// The value is MD5(gss_channel_bindings_struct) per MS-NLMP §3.1.5.1.2,
// where the struct is:
//
//	initiator_addrtype(4) + initiator_length(4)  // 8 zero bytes
//	acceptor_addrtype(4)  + acceptor_length(4)   // 8 zero bytes
//	application_length(4) + application_data(variable)
//
// and application_data is "tls-server-end-point:" || SHA-256(cert.DER).
//
// Hash choice: SHA-256 always. Matches Microsoft's AD implementation and
// impacket. RFC 5929 §4.1 would permit cert-signature-matched hashes
// (SHA-384/SHA-512), but Windows DCs hardcode SHA-256 — following the RFC
// letter breaks interop on ECDSA P-384 DCs.
func computeMsvAvChannelBindings(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("computeMsvAvChannelBindings: nil certificate")
	}
	h := sha256.Sum256(cert.Raw)
	appData := make([]byte, 0, len("tls-server-end-point:")+len(h))
	appData = append(appData, []byte("tls-server-end-point:")...)
	appData = append(appData, h[:]...)

	lenPrefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenPrefix, uint32(len(appData)))

	buf := make([]byte, 0, 16+4+len(appData))
	buf = append(buf, make([]byte, 16)...) // initiator(8) + acceptor(8), all zero
	buf = append(buf, lenPrefix...)
	buf = append(buf, appData...)
	sum := md5.Sum(buf)
	return sum[:], nil
}
