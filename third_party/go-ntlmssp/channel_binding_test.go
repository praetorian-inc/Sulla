package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestNewAuthenticateMessageWithCBT_EmbedsAVPair0x000A verifies that a
// non-empty channelBinding value appears as AV pair 0x000A in the
// AUTHENTICATE_MESSAGE's TargetInfo.
func TestNewAuthenticateMessageWithCBT_EmbedsAVPair0x000A(t *testing.T) {
	challenge := buildTestChallenge(t)

	cbt := bytes.Repeat([]byte{0xAB}, 16)

	auth, err := NewAuthenticateMessageWithCBT(challenge, "testuser", "P@ssw0rd!", true, cbt)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := findAVPairInAuthMessage(auth, 0x000A)
	if !ok {
		t.Fatal("AUTHENTICATE_MESSAGE missing MsvAvChannelBindings (AV 0x000A)")
	}
	if !bytes.Equal(got, cbt) {
		t.Fatalf("AV pair value mismatch:\n  got:  %s\n  want: %s", hex.EncodeToString(got), hex.EncodeToString(cbt))
	}
}

// TestNewAuthenticateMessageWithCBT_EmptyCBT_OmitsAVPair verifies that
// passing empty channelBinding produces output equivalent to the upstream
// ProcessChallenge path (no AV pair 0x000A).
func TestNewAuthenticateMessageWithCBT_EmptyCBT_OmitsAVPair(t *testing.T) {
	challenge := buildTestChallenge(t)
	auth, err := NewAuthenticateMessageWithCBT(challenge, "testuser", "P@ssw0rd!", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findAVPairInAuthMessage(auth, 0x000A); ok {
		t.Fatal("AV pair 0x000A unexpectedly present when channelBinding is nil")
	}
}

// TestNewAuthenticateMessageWithCBT_ReplacesExistingAVPair verifies that
// an existing MsvAvChannelBindings AV pair in the challenge is replaced
// (not duplicated) by our patch.
func TestNewAuthenticateMessageWithCBT_ReplacesExistingAVPair(t *testing.T) {
	challenge := buildTestChallengeWithExistingCBT(t, bytes.Repeat([]byte{0x11}, 16))
	newCBT := bytes.Repeat([]byte{0xAB}, 16)
	auth, err := NewAuthenticateMessageWithCBT(challenge, "u", "p", true, newCBT)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := findAVPairInAuthMessage(auth, 0x000A)
	if !bytes.Equal(got, newCBT) {
		t.Fatalf("CBT not replaced: got %x want %x", got, newCBT)
	}
	if countAVPairInAuthMessage(auth, 0x000A) != 1 {
		t.Fatal("duplicated AV pair 0x000A")
	}
}

// buildTestChallenge constructs a synthetic CHALLENGE_MESSAGE per MS-NLMP
// §2.2.1.2 layout: Signature + MessageType + TargetNameFields + Flags +
// ServerChallenge + Reserved + TargetInfoFields + Version + Payload.
//
// Flags literal = 0x20888205, the SUM of:
//
//	NEGOTIATE_UNICODE               (1<<0)  = 0x00000001   (REQUIRED by MarshalBinary)
//	REQUEST_TARGET                  (1<<2)  = 0x00000004
//	NTLM                            (1<<9)  = 0x00000200
//	ALWAYS_SIGN                     (1<<15) = 0x00008000
//	EXTENDED_SESSIONSECURITY (NTLM2)(1<<19) = 0x00080000
//	TARGET_INFO                     (1<<23) = 0x00800000
//	NEGOTIATE_128                   (1<<29) = 0x20000000
//
// DO NOT set bit 7 (NEGOTIATE_LM_KEY, 0x80) — authenticate_message.go:95-97
// rejects it with "Only NTLM v2 is supported".
func buildTestChallenge(t *testing.T) []byte {
	t.Helper()
	flags := uint32(0x20888205)
	serverChallenge := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	avPairs := encodeAVPairs([]avPair{
		{id: 0x0002, value: encodeUTF16LE("CORP")},
		{id: 0x0001, value: encodeUTF16LE("DC1")},
		{id: 0x0000, value: nil},
	})

	var buf bytes.Buffer
	buf.WriteString("NTLMSSP\x00")
	binary.Write(&buf, binary.LittleEndian, uint32(2)) // MessageType: CHALLENGE
	// TargetNameFields: len=0, maxlen=0, offset=0x38
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint32(0x38))
	binary.Write(&buf, binary.LittleEndian, flags)
	buf.Write(serverChallenge[:])
	buf.Write(make([]byte, 8)) // Reserved
	// TargetInfoFields: len=len(avPairs), maxlen=same, offset=0x38
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint32(0x38))
	buf.Write(make([]byte, 8)) // Version
	buf.Write(avPairs)         // Payload
	return buf.Bytes()
}

func buildTestChallengeWithExistingCBT(t *testing.T, cbt []byte) []byte {
	t.Helper()
	flags := uint32(0x20888205)
	serverChallenge := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	avPairs := encodeAVPairs([]avPair{
		{id: 0x0002, value: encodeUTF16LE("CORP")},
		{id: 0x0001, value: encodeUTF16LE("DC1")},
		{id: 0x000A, value: cbt},
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
	buf.Write(make([]byte, 8))
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint16(len(avPairs)))
	binary.Write(&buf, binary.LittleEndian, uint32(0x38))
	buf.Write(make([]byte, 8))
	buf.Write(avPairs)
	return buf.Bytes()
}

type avPair struct {
	id    uint16
	value []byte
}

func encodeAVPairs(pairs []avPair) []byte {
	var out bytes.Buffer
	for _, p := range pairs {
		binary.Write(&out, binary.LittleEndian, p.id)
		binary.Write(&out, binary.LittleEndian, uint16(len(p.value)))
		out.Write(p.value)
	}
	return out.Bytes()
}

func encodeUTF16LE(s string) []byte {
	var out bytes.Buffer
	for _, r := range s {
		binary.Write(&out, binary.LittleEndian, uint16(r))
	}
	return out.Bytes()
}

// findAVPairInAuthMessage locates AV pair `avId` inside the
// AUTHENTICATE_MESSAGE's NtChallengeResponseFields payload (MS-NLMP §2.2.1.3).
// Layout inside NtChallengeResponse: 16-byte NTProofStr, then temp{respType,
// reserved, 8-byte timestamp, 8-byte clientChallenge, 4-byte reserved,
// targetInfo AV pairs, 4-byte reserved}. AV pairs therefore start at
// offset 16+28 = 44.
func findAVPairInAuthMessage(authMsg []byte, avId uint16) ([]byte, bool) {
	ntResp, ok := ntChallengeResponse(authMsg)
	if !ok {
		return nil, false
	}
	avs := ntResp[16+28:]
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

func countAVPairInAuthMessage(authMsg []byte, avId uint16) int {
	ntResp, ok := ntChallengeResponse(authMsg)
	if !ok {
		return 0
	}
	count := 0
	avs := ntResp[16+28:]
	for len(avs) >= 4 {
		id := binary.LittleEndian.Uint16(avs[0:2])
		ln := binary.LittleEndian.Uint16(avs[2:4])
		if int(4+ln) > len(avs) {
			break
		}
		if id == 0x0000 {
			break
		}
		if id == avId {
			count++
		}
		avs = avs[4+ln:]
	}
	return count
}

// ntChallengeResponse extracts the NtChallengeResponse payload from an
// AUTHENTICATE_MESSAGE (MS-NLMP §2.2.1.3). Returns the slice and true on
// success, or (nil, false) if the message is malformed / too short.
func ntChallengeResponse(authMsg []byte) ([]byte, bool) {
	if len(authMsg) < 64 || !bytes.HasPrefix(authMsg, []byte("NTLMSSP\x00")) {
		return nil, false
	}
	ntRespLen := binary.LittleEndian.Uint16(authMsg[20:22])
	ntRespOff := binary.LittleEndian.Uint32(authMsg[24:28])
	if int(ntRespOff)+int(ntRespLen) > len(authMsg) || ntRespLen < 16+28 {
		return nil, false
	}
	return authMsg[ntRespOff : ntRespOff+uint32(ntRespLen)], true
}
