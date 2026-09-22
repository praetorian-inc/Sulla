package sulla

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestShouldResolveLocally(t *testing.T) {
	dialer, err := buildProxyDialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("buildProxyDialer: %v", err)
	}
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{name: "no proxy", config: Config{}, want: true},
		{name: "no proxy + dns", config: Config{DNSServer: "10.0.0.1"}, want: true},
		{name: "proxy, no dns", config: Config{proxyDialer: dialer}, want: false},
		{name: "proxy + dns", config: Config{proxyDialer: dialer, DNSServer: "10.0.0.1"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldResolveLocally(tt.config); got != tt.want {
				t.Errorf("shouldResolveLocally = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSServerAddr(t *testing.T) {
	tests := []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1:53"},
		{"10.0.0.1:5353", "10.0.0.1:5353"},
		{"::1", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
	}
	for _, tt := range tests {
		if got := dnsServerAddr(tt.in); got != tt.want {
			t.Errorf("dnsServerAddr(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestResolveOverProxy proves getResolver, with a proxy + custom DNS server,
// resolves a name by tunneling DNS-over-TCP through the SOCKS proxy.
func TestResolveOverProxy(t *testing.T) {
	dns := newTestDNSServer(t, net.IPv4(10, 83, 0, 10))
	defer dns.Close()
	socks := newTestSocks5(t, nil)
	defer socks.Close()

	d, err := buildProxyDialer(socks.addr())
	if err != nil {
		t.Fatalf("buildProxyDialer: %v", err)
	}
	config := Config{proxyDialer: d, DNSServer: dns.addr()}

	resolver := getResolver(config)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupHost(ctx, "roma.imperium.local")
	if err != nil {
		t.Fatalf("LookupHost through proxy: %v", err)
	}

	var found bool
	for _, ip := range ips {
		if ip == "10.83.0.10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("resolved ips = %v, want to contain 10.83.0.10", ips)
	}

	// The DNS query must have traversed the SOCKS proxy to reach the DNS server.
	if got := socks.lastTarget(); got != dns.addr() {
		t.Errorf("proxy target = %q, want DNS server %q", got, dns.addr())
	}
	if name := dns.lastName(); name != "roma.imperium.local." {
		t.Errorf("DNS server saw query %q, want roma.imperium.local.", name)
	}
}

// --- minimal DNS-over-TCP server for tests (answers A queries) ---

type testDNS struct {
	ln     net.Listener
	answer net.IP

	mu   sync.Mutex
	name string
}

func newTestDNSServer(t *testing.T, answer net.IP) *testDNS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	s := &testDNS{ln: ln, answer: answer.To4()}
	go s.serve()
	return s
}

func (s *testDNS) addr() string { return s.ln.Addr().String() }
func (s *testDNS) Close()       { s.ln.Close() }

func (s *testDNS) lastName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name
}

func (s *testDNS) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *testDNS) handle(c net.Conn) {
	defer c.Close()
	for {
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp, err := s.buildResponse(msg)
		if err != nil {
			return
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
		if _, err := c.Write(append(out[:], resp...)); err != nil {
			return
		}
	}
}

// buildResponse parses the DNS query and builds a response with a single A
// answer for A queries; other query types get an empty (NOERROR, 0-answer)
// reply. Using dnsmessage guarantees the wire format Go's resolver accepts.
func (s *testDNS) buildResponse(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.name = q.Name.String()
	s.mu.Unlock()

	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA {
		if err := b.StartAnswers(); err != nil {
			return nil, err
		}
		var ip [4]byte
		copy(ip[:], s.answer)
		if err := b.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.AResource{A: ip}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
