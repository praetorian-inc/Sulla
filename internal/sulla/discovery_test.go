package sulla

import "testing"

func TestDomainToBaseDN(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"corp.example.com", "DC=corp,DC=example,DC=com"},
		{"local", "DC=local"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := domainToBaseDN(tt.domain)
			if got != tt.want {
				t.Errorf("domainToBaseDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestSidToString(t *testing.T) {
	t.Run("valid SID", func(t *testing.T) {
		// S-1-5-21-3623811015-3361044348-30300820-1013
		sid := []byte{
			0x01,                                     // revision
			0x05,                                     // sub-authority count
			0x00, 0x00, 0x00, 0x00, 0x00, 0x05,      // identifier authority (5)
		}
		// Sub-authorities (little-endian uint32)
		appendLE := func(v uint32) {
			sid = append(sid, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
		}
		appendLE(21)
		appendLE(3623811015)
		appendLE(3361044348)
		appendLE(30300820)
		appendLE(1013)

		got := sidToString(sid)
		want := "S-1-5-21-3623811015-3361044348-30300820-1013"
		if got != want {
			t.Errorf("sidToString = %q, want %q", got, want)
		}
	})

	t.Run("short input returns empty", func(t *testing.T) {
		got := sidToString([]byte{0x01, 0x02, 0x03})
		if got != "" {
			t.Errorf("sidToString(short) = %q, want empty", got)
		}
	})
}
