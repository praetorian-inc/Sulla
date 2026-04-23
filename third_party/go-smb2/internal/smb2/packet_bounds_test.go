// Regression tests for the length-guarded PacketCodec accessors added in
// the Praetorian fork. Without the guards, every one of these would
// panic with "slice bounds out of range". See NOTICE.md.
package smb2

import "testing"

func TestPacketCodecAccessorsEmpty(t *testing.T) {
	var p PacketCodec // nil, len 0

	if got := p.SessionId(); got != 0 {
		t.Errorf("SessionId on empty = %d, want 0", got)
	}
	if got := p.MessageId(); got != 0 {
		t.Errorf("MessageId on empty = %d, want 0", got)
	}
	if got := p.TreeId(); got != 0 {
		t.Errorf("TreeId on empty = %d, want 0", got)
	}
	if got := p.Command(); got != 0 {
		t.Errorf("Command on empty = %d, want 0", got)
	}
	if got := p.Status(); got != 0 {
		t.Errorf("Status on empty = %d, want 0", got)
	}
	if got := p.Flags(); got != 0 {
		t.Errorf("Flags on empty = %d, want 0", got)
	}
	if got := p.NextCommand(); got != 0 {
		t.Errorf("NextCommand on empty = %d, want 0", got)
	}
	if got := p.AsyncId(); got != 0 {
		t.Errorf("AsyncId on empty = %d, want 0", got)
	}
	if got := p.Signature(); got != nil {
		t.Errorf("Signature on empty = %v, want nil", got)
	}
	if got := p.Data(); got != nil {
		t.Errorf("Data on empty = %v, want nil", got)
	}
}

func TestPacketCodecAccessorsTruncated(t *testing.T) {
	// 40-byte buffer: just short enough to make SessionId's [40:48] slice
	// go out of range. The specific panic observed in smbellum in the wild.
	p := PacketCodec(make([]byte, 40))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("expected no panic, got: %v", r)
		}
	}()

	if got := p.SessionId(); got != 0 {
		t.Errorf("SessionId on 40-byte = %d, want 0", got)
	}
}
