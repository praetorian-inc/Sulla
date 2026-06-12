package sulla

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildSyntheticNTLMChallenge mirrors the fork's channel_binding_test.go
// buildTestChallenge — a valid MS-NLMP §2.2.1.2 CHALLENGE_MESSAGE with
// NEGOTIATE_UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN |
// EXTENDED_SESSIONSECURITY | TARGET_INFO | NEGOTIATE_128. The fork's helpers
// are in the ntlmssp package and not exported; this is a parallel copy so
// CBTNegotiator tests can exercise the full NEGOTIATE → AUTHENTICATE round-trip.
func buildSyntheticNTLMChallenge(t *testing.T) []byte {
	t.Helper()
	flags := uint32(0x20888205)
	serverChallenge := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	avPairs := encodeTestAVPairs([]testAVPair{
		{id: 0x0002, value: encodeTestUTF16LE("CORP")},
		{id: 0x0001, value: encodeTestUTF16LE("DC1")},
		{id: 0x0000, value: nil},
	})

	var buf bytes.Buffer
	buf.WriteString("NTLMSSP\x00")
	binary.Write(&buf, binary.LittleEndian, uint32(2))
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0x38))
	binary.Write(&buf, binary.LittleEndian, flags)
	buf.Write(serverChallenge[:])
	buf.Write(make([]byte, 8)) // Reserved
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint32(0x38))
	buf.Write(make([]byte, 8)) // Version
	buf.Write(avPairs)
	return buf.Bytes()
}

type testAVPair struct {
	id    uint16
	value []byte
}

func encodeTestAVPairs(pairs []testAVPair) []byte {
	var out bytes.Buffer
	for _, p := range pairs {
		binary.Write(&out, binary.LittleEndian, p.id)
		binary.Write(&out, binary.LittleEndian, uint16(len(p.value)))
		out.Write(p.value)
	}
	return out.Bytes()
}

func encodeTestUTF16LE(s string) []byte {
	var out bytes.Buffer
	for _, r := range s {
		binary.Write(&out, binary.LittleEndian, uint16(r))
	}
	return out.Bytes()
}

// findAVPair locates AV pair `avId` inside the AUTHENTICATE_MESSAGE's
// NtChallengeResponse payload (MS-NLMP §2.2.1.3). Layout inside
// NtChallengeResponse: 16-byte NTProofStr, then 28-byte temp header
// (respType + reserved + timestamp + clientChallenge + reserved), then
// AV pairs starting at offset 44.
func findAVPair(authMsg []byte, avId uint16) ([]byte, bool) {
	if len(authMsg) < 64 || !bytes.HasPrefix(authMsg, []byte("NTLMSSP\x00")) {
		return nil, false
	}
	ntRespLen := binary.LittleEndian.Uint16(authMsg[20:22])
	ntRespOff := binary.LittleEndian.Uint32(authMsg[24:28])
	if int(ntRespOff)+int(ntRespLen) > len(authMsg) || ntRespLen < 16+28 {
		return nil, false
	}
	avs := authMsg[ntRespOff+16+28 : ntRespOff+uint32(ntRespLen)]
	for len(avs) >= 4 {
		id := binary.LittleEndian.Uint16(avs[0:2])
		ln := binary.LittleEndian.Uint16(avs[2:4])
		if int(4+ln) > len(avs) {
			return nil, false
		}
		if id == 0x0000 {
			return nil, false
		}
		if id == avId {
			v := make([]byte, ln)
			copy(v, avs[4:4+ln])
			return v, true
		}
		avs = avs[4+ln:]
	}
	return nil, false
}
