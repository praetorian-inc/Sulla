package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

type authenicateMessage struct {
	LmChallengeResponse []byte
	NtChallengeResponse []byte

	TargetName string
	UserName   string

	// only set if negotiateFlag_NTLMSSP_NEGOTIATE_KEY_EXCH
	EncryptedRandomSessionKey []byte

	NegotiateFlags negotiateFlags

	MIC []byte
}

type authenticateMessageFields struct {
	messageHeader
	LmChallengeResponse varField
	NtChallengeResponse varField
	TargetName          varField
	UserName            varField
	Workstation         varField
	_                   [8]byte
	NegotiateFlags      negotiateFlags
}

func (m authenicateMessage) MarshalBinary() ([]byte, error) {
	if !m.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEUNICODE) {
		return nil, errors.New("Only unicode is supported")
	}

	target, user := toUnicode(m.TargetName), toUnicode(m.UserName)
	workstation := toUnicode("")

	ptr := binary.Size(&authenticateMessageFields{})
	f := authenticateMessageFields{
		messageHeader:       newMessageHeader(3),
		NegotiateFlags:      m.NegotiateFlags,
		LmChallengeResponse: newVarField(&ptr, len(m.LmChallengeResponse)),
		NtChallengeResponse: newVarField(&ptr, len(m.NtChallengeResponse)),
		TargetName:          newVarField(&ptr, len(target)),
		UserName:            newVarField(&ptr, len(user)),
		Workstation:         newVarField(&ptr, len(workstation)),
	}

	f.NegotiateFlags.Unset(negotiateFlagNTLMSSPNEGOTIATEVERSION)

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &f); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.LmChallengeResponse); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &m.NtChallengeResponse); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &target); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &user); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &workstation); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// NewAuthenticateMessageWithCBT emits an NTLMv2 AUTHENTICATE_MESSAGE with an
// optional 16-byte channel-binding value (per MS-NLMP §3.1.5.1.2). When
// non-empty, it is embedded as AV pair 0x000A (MsvAvChannelBindings) in the
// TargetInfo section of the NtChallengeResponse; NTProofStr is computed over
// the modified TargetInfo so the DC's replay check succeeds.
//
// Callers compute channelBinding per RFC 5929 §4.1 "tls-server-end-point":
//
//	hash = SHA-256(peer_cert.DER)
//	app_data = "tls-server-end-point:" + hash
//	struct = 8 zero bytes + 8 zero bytes + uint32le(len(app_data)) + app_data
//	channelBinding = MD5(struct)
//
// See impacket PR #1844 for the reference Python implementation.
func NewAuthenticateMessageWithCBT(challengeMessageData []byte, user, password string, domainNeeded bool, channelBinding []byte) ([]byte, error) {
	return buildAuthenticateMessage(challengeMessageData, user, password, "", domainNeeded, channelBinding)
}

// NewAuthenticateMessageWithCBTWithHash is the hash-auth variant of
// NewAuthenticateMessageWithCBT. Accepts a hex-encoded NT hash (optionally
// in "LM:NT" format, in which case the LM half is discarded to match
// upstream ProcessChallengeWithHash). domainNeeded=true preserves the
// server's TargetName in NtProofStr, matching upstream's behavior.
func NewAuthenticateMessageWithCBTWithHash(challengeMessageData []byte, user, hash string, domainNeeded bool, channelBinding []byte) ([]byte, error) {
	return buildAuthenticateMessage(challengeMessageData, user, "", hash, domainNeeded, channelBinding)
}

// ProcessChallenge crafts an AUTHENTICATE message in response to the CHALLENGE
// message that was received from the server. Behavior-identical to the
// upstream implementation (authenticate_message.go:85-133 at commit
// 754e69321358) — the body is now a thin delegation to buildAuthenticateMessage
// with channelBinding=nil.
func ProcessChallenge(challengeMessageData []byte, user, password string, domainNeeded bool) ([]byte, error) {
	return buildAuthenticateMessage(challengeMessageData, user, password, "", domainNeeded, nil)
}

// ProcessChallengeWithHash is the hash-auth variant of ProcessChallenge.
// Behavior-identical to upstream (authenticate_message.go:135-187 at commit
// 754e69321358). domainNeeded=true hardcoded to match upstream's preservation
// of cm.TargetName in NtProofStr.
func ProcessChallengeWithHash(challengeMessageData []byte, user, hash string) ([]byte, error) {
	return buildAuthenticateMessage(challengeMessageData, user, "", hash, true, nil)
}

// buildAuthenticateMessage is the shared implementation of ProcessChallenge,
// ProcessChallengeWithHash, NewAuthenticateMessageWithCBT, and
// NewAuthenticateMessageWithCBTWithHash. The body is lifted from upstream
// ProcessChallenge (lines 85-133) with two modifications flagged by
// "CBT PATCH" comments:
//  1. Inject channelBinding into cm.TargetInfoRaw after UnmarshalBinary.
//  2. Support the hash-auth path by branching on hashHex (mirrors upstream
//     ProcessChallengeWithHash lines 169-177, including the "LM:NT" split).
func buildAuthenticateMessage(challengeMessageData []byte, user, password, hashHex string, domainNeeded bool, channelBinding []byte) ([]byte, error) {
	if user == "" && password == "" && hashHex == "" {
		return nil, errors.New("Anonymous authentication not supported")
	}

	var cm challengeMessage
	if err := cm.UnmarshalBinary(challengeMessageData); err != nil {
		return nil, err
	}

	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATELMKEY) {
		return nil, errors.New("Only NTLM v2 is supported, but server requested v1 (NTLMSSP_NEGOTIATE_LM_KEY)")
	}
	if cm.NegotiateFlags.Has(negotiateFlagNTLMSSPNEGOTIATEKEYEXCH) {
		return nil, errors.New("Key exchange requested but not supported (NTLMSSP_NEGOTIATE_KEY_EXCH)")
	}

	// CBT PATCH (1/2): inject MsvAvChannelBindings into TargetInfoRaw so the
	// AV pair appears in the NtChallengeResponse AND is covered by NTProofStr.
	// No-op when channelBinding is nil (preserves upstream behavior).
	cm.TargetInfoRaw = injectChannelBindingAVPair(cm.TargetInfoRaw, channelBinding)

	if !domainNeeded {
		cm.TargetName = ""
	}

	am := authenicateMessage{
		UserName:       user,
		TargetName:     cm.TargetName,
		NegotiateFlags: cm.NegotiateFlags,
	}

	timestamp := cm.TargetInfo[avIDMsvAvTimestamp]
	if timestamp == nil {
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)

	// CBT PATCH (2/2): select password-auth vs. hash-auth path. Hash branch
	// mirrors upstream ProcessChallengeWithHash (authenticate_message.go:169-177)
	// VERBATIM including the "LM:NT" split so callers passing the colon-delimited
	// hashdump format continue to work byte-for-byte after our refactor.
	var ntlmV2Hash []byte
	if hashHex != "" {
		hashParts := strings.Split(hashHex, ":")
		if len(hashParts) > 1 {
			hashHex = hashParts[1]
		}
		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil {
			return nil, err
		}
		ntlmV2Hash = hmacMd5(hashBytes, toUnicode(strings.ToUpper(user)+cm.TargetName))
	} else {
		ntlmV2Hash = getNtlmV2Hash(password, user, cm.TargetName)
	}

	am.NtChallengeResponse = computeNtlmV2Response(ntlmV2Hash,
		cm.ServerChallenge[:], clientChallenge, timestamp, cm.TargetInfoRaw)

	if cm.TargetInfoRaw == nil {
		am.LmChallengeResponse = computeLmV2Response(ntlmV2Hash,
			cm.ServerChallenge[:], clientChallenge)
	}
	return am.MarshalBinary()
}
