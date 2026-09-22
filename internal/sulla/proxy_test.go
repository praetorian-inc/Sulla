package sulla

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestParseSocks(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAddr string
		wantUser string
		wantPass string
		wantAuth bool
		wantErr  bool
	}{
		{name: "host:port only", input: "127.0.0.1:1080", wantAddr: "127.0.0.1:1080"},
		{name: "with scheme", input: "socks5://127.0.0.1:1080", wantAddr: "127.0.0.1:1080"},
		{name: "socks5h scheme", input: "socks5h://127.0.0.1:1080", wantAddr: "127.0.0.1:1080"},
		{name: "with creds", input: "user:pass@10.0.0.1:1080", wantAddr: "10.0.0.1:1080", wantUser: "user", wantPass: "pass", wantAuth: true},
		{name: "scheme and creds ipv6", input: "socks5://u:p@[::1]:1080", wantAddr: "[::1]:1080", wantUser: "u", wantPass: "p", wantAuth: true},
		{name: "empty user allowed pass", input: "u:@1.2.3.4:9050", wantAddr: "1.2.3.4:9050", wantUser: "u", wantPass: "", wantAuth: true},
		{name: "empty", input: "", wantErr: true},
		{name: "whitespace", input: "   ", wantErr: true},
		{name: "no port", input: "127.0.0.1", wantErr: true},
		{name: "bad scheme", input: "http://127.0.0.1:1080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, auth, err := parseSocks(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSocks(%q) expected error, got addr=%q auth=%v", tt.input, addr, auth)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSocks(%q) unexpected error: %v", tt.input, err)
			}
			if addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", addr, tt.wantAddr)
			}
			if tt.wantAuth {
				if auth == nil {
					t.Fatalf("expected auth, got nil")
				}
				if auth.User != tt.wantUser || auth.Password != tt.wantPass {
					t.Errorf("auth = {%q,%q}, want {%q,%q}", auth.User, auth.Password, tt.wantUser, tt.wantPass)
				}
			} else if auth != nil {
				t.Errorf("expected no auth, got %+v", auth)
			}
		})
	}
}

func TestBuildProxyDialer(t *testing.T) {
	d, err := buildProxyDialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil dialer")
	}
	if _, ok := d.(proxy.ContextDialer); !ok {
		t.Errorf("dialer should implement proxy.ContextDialer for cancellation support")
	}

	if _, err := buildProxyDialer("not a valid proxy"); err == nil {
		t.Error("expected error for invalid proxy spec")
	}
}

func TestProxyRequiresExplicitDC(t *testing.T) {
	dialer, err := buildProxyDialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("buildProxyDialer: %v", err)
	}
	creds := Config{Username: "u", Password: "p", Domain: "corp.local"}

	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{name: "no proxy", config: creds, want: false},
		{
			name:   "proxy + creds, no dc",
			config: withProxy(creds, dialer),
			want:   true,
		},
		{
			name:   "proxy + creds + explicit dc",
			config: withProxy(mergeDC(creds, "dc01.corp.local"), dialer),
			want:   false,
		},
		{
			name:   "proxy + host/share (not discovery)",
			config: withProxy(Config{Username: "u", Password: "p", Domain: "corp.local", Host: "fs01", Share: "Data"}, dialer),
			want:   false,
		},
		{
			name:   "proxy + target file",
			config: withProxy(Config{Username: "u", Password: "p", Domain: "corp.local", TargetsFile: "t.txt"}, dialer),
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyRequiresExplicitDC(tt.config); got != tt.want {
				t.Errorf("proxyRequiresExplicitDC = %v, want %v", got, tt.want)
			}
		})
	}
}

func withProxy(c Config, d proxy.Dialer) Config {
	c.proxyDialer = d
	return c
}

func mergeDC(c Config, dc string) Config {
	c.DomainController = dc
	return c
}

// TestDialTCPThroughProxy proves dialTCP routes through a SOCKS5 proxy, passes
// the hostname for remote resolution, and honors username/password auth.
func TestDialTCPThroughProxy(t *testing.T) {
	// Backend the proxy will ultimately connect to; greets and closes.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backend.Close()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte("HELLO"))
			}(c)
		}
	}()
	_, backendPort, _ := net.SplitHostPort(backend.Addr().String())

	t.Run("no auth routes through proxy", func(t *testing.T) {
		srv := newTestSocks5(t, nil)
		defer srv.Close()

		d, err := buildProxyDialer(srv.addr())
		if err != nil {
			t.Fatalf("buildProxyDialer: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Dial by hostname to exercise remote DNS (SOCKS5 domain address type).
		conn, err := dialTCP(ctx, Config{proxyDialer: d}, net.JoinHostPort("localhost", backendPort), 5*time.Second)
		if err != nil {
			t.Fatalf("dialTCP through proxy: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read from backend: %v", err)
		}
		if string(buf) != "HELLO" {
			t.Errorf("got %q, want HELLO", buf)
		}

		// Proxy must have observed a CONNECT, and the requested target must be
		// the hostname (remote DNS), not a pre-resolved IP.
		got := srv.lastTarget()
		if got != net.JoinHostPort("localhost", backendPort) {
			t.Errorf("proxy target = %q, want hostname-based %q (remote DNS)", got, net.JoinHostPort("localhost", backendPort))
		}
	})

	t.Run("correct credentials succeed", func(t *testing.T) {
		srv := newTestSocks5(t, &proxy.Auth{User: "u", Password: "p"})
		defer srv.Close()

		d, err := buildProxyDialer("u:p@" + srv.addr())
		if err != nil {
			t.Fatalf("buildProxyDialer: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := dialTCP(ctx, Config{proxyDialer: d}, net.JoinHostPort("127.0.0.1", backendPort), 5*time.Second)
		if err != nil {
			t.Fatalf("authenticated dial failed: %v", err)
		}
		conn.Close()
	})

	t.Run("wrong credentials fail", func(t *testing.T) {
		srv := newTestSocks5(t, &proxy.Auth{User: "u", Password: "p"})
		defer srv.Close()

		d, err := buildProxyDialer("u:wrong@" + srv.addr())
		if err != nil {
			t.Fatalf("buildProxyDialer: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if conn, err := dialTCP(ctx, Config{proxyDialer: d}, net.JoinHostPort("127.0.0.1", backendPort), 5*time.Second); err == nil {
			conn.Close()
			t.Fatal("expected auth failure, dial succeeded")
		}
	})
}

// TestDialTCPProxyHonorsTimeout proves the proxy branch enforces the caller's
// timeout via context, even when the passed ctx carries no deadline (as in
// smbConnect). The stub proxy accepts the TCP connection but never speaks SOCKS,
// so the dial blocks on the handshake until the timeout fires. Without the
// context timeout, this dial would hang until the test's own deadline.
func TestDialTCPProxyHonorsTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the conn open, but never respond to the SOCKS greeting.
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})

	d, err := buildProxyDialer(ln.Addr().String())
	if err != nil {
		t.Fatalf("buildProxyDialer: %v", err)
	}

	// context.Background() has no deadline, so only dialTCP's own timeout applies.
	start := time.Now()
	conn, err := dialTCP(context.Background(), Config{proxyDialer: d}, "10.255.255.1:445", 150*time.Millisecond)
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("expected error from timed-out proxy dial, got success")
	}
	// Effective budget is 150ms*proxyDialTimeoutFactor; allow a wide margin to
	// avoid flakiness on loaded CI, while still catching an unbounded dial.
	if elapsed > 3*time.Second {
		t.Errorf("proxy dial did not honor timeout: took %v", elapsed)
	}
}

func TestDialTCPDirect(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("DIRECT"))
		c.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// No proxyDialer => direct dial path.
	conn, err := dialTCP(ctx, Config{}, backend.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("direct dialTCP: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "DIRECT" {
		t.Errorf("got %q, want DIRECT", buf)
	}
}

// --- minimal in-process SOCKS5 server for tests (CONNECT only) ---

type testSocks5 struct {
	ln   net.Listener
	auth *proxy.Auth

	mu     sync.Mutex
	target string // host:port of the last CONNECT request, as sent by the client
}

func newTestSocks5(t *testing.T, auth *proxy.Auth) *testSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks listen: %v", err)
	}
	s := &testSocks5{ln: ln, auth: auth}
	go s.serve()
	return s
}

func (s *testSocks5) addr() string { return s.ln.Addr().String() }
func (s *testSocks5) Close()       { s.ln.Close() }

func (s *testSocks5) lastTarget() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target
}

func (s *testSocks5) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *testSocks5) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	// Greeting: ver, nmethods, methods[nmethods]
	ver, _ := br.ReadByte()
	if ver != 0x05 {
		return
	}
	nm, _ := br.ReadByte()
	methods := make([]byte, int(nm))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	if s.auth != nil {
		// Require username/password (method 0x02).
		c.Write([]byte{0x05, 0x02})
		if !s.doUserPassAuth(c, br) {
			return
		}
	} else {
		c.Write([]byte{0x05, 0x00}) // no auth
	}

	// Request: ver, cmd, rsv, atyp, addr, port
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 { // only CONNECT
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 0x03: // domain
		l, _ := br.ReadByte()
		b := make([]byte, int(l))
		io.ReadFull(br, b)
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	default:
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(portBuf[0])<<8 | int(portBuf[1])
	target := net.JoinHostPort(host, itoa(port))

	s.mu.Lock()
	s.target = target
	s.mu.Unlock()

	// Connect to the real target and relay.
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()

	// Success reply with dummy bound address 0.0.0.0:0.
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, br) }()
	go func() { defer wg.Done(); io.Copy(c, upstream) }()
	wg.Wait()
}

func (s *testSocks5) doUserPassAuth(c net.Conn, br *bufio.Reader) bool {
	ver, _ := br.ReadByte()
	if ver != 0x01 {
		return false
	}
	ulen, _ := br.ReadByte()
	user := make([]byte, int(ulen))
	io.ReadFull(br, user)
	plen, _ := br.ReadByte()
	pass := make([]byte, int(plen))
	if _, err := io.ReadFull(br, pass); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	if string(user) == s.auth.User && string(pass) == s.auth.Password {
		c.Write([]byte{0x01, 0x00}) // success
		return true
	}
	c.Write([]byte{0x01, 0x01}) // failure
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
