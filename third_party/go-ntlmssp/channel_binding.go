package ntlmssp

import (
	"encoding/binary"
)

// injectChannelBindingAVPair walks the TargetInfo AV-pair blob, removes any
// existing MsvAvChannelBindings entry, and inserts one with the provided
// 16-byte value immediately before the terminating MsvAvEOL. The blob
// layout is a sequence of (AvId:u16, AvLen:u16, Value) triples terminated
// by (0x0000, 0x0000) per MS-NLMP §2.2.2.1.
//
// When channelBinding is empty, the input is returned unchanged so
// non-CBT callers (ProcessChallenge, ProcessChallengeWithHash) see the
// original targetInfo bytes and remain byte-for-byte compatible.
func injectChannelBindingAVPair(targetInfoRaw, channelBinding []byte) []byte {
	if len(channelBinding) == 0 {
		return targetInfoRaw
	}
	out := make([]byte, 0, len(targetInfoRaw)+4+len(channelBinding))
	i := 0
	eolSeen := false
	for i+4 <= len(targetInfoRaw) {
		id := binary.LittleEndian.Uint16(targetInfoRaw[i : i+2])
		ln := binary.LittleEndian.Uint16(targetInfoRaw[i+2 : i+4])
		pairEnd := i + 4 + int(ln)
		if pairEnd > len(targetInfoRaw) {
			break
		}
		if avID(id) == avIDMsvChannelBindings {
			i = pairEnd
			continue
		}
		if avID(id) == avIDMsvAvEOL {
			out = append(out, encodeAVPairBytes(uint16(avIDMsvChannelBindings), channelBinding)...)
			out = append(out, targetInfoRaw[i:pairEnd]...)
			eolSeen = true
			i = pairEnd
			break
		}
		out = append(out, targetInfoRaw[i:pairEnd]...)
		i = pairEnd
	}
	if !eolSeen {
		out = append(out, encodeAVPairBytes(uint16(avIDMsvChannelBindings), channelBinding)...)
		out = append(out, encodeAVPairBytes(uint16(avIDMsvAvEOL), nil)...)
	}
	return out
}

func encodeAVPairBytes(id uint16, value []byte) []byte {
	buf := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(buf[0:2], id)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(value)))
	copy(buf[4:], value)
	return buf
}
