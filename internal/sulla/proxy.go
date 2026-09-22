package sulla

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// parseSocks parses a SOCKS5 proxy spec of the form:
//
//	[socks5://][user:pass@]host:port
//
// It returns the host:port address and optional auth (nil when no credentials
// are supplied).
func parseSocks(raw string) (addr string, auth *proxy.Auth, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("empty SOCKS proxy value")
	}

	// Normalize to a URL so we can reuse net/url's userinfo + host parsing.
	if !strings.Contains(raw, "://") {
		raw = "socks5://" + raw
	}
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", nil, fmt.Errorf("invalid SOCKS proxy %q: %w", raw, perr)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return "", nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 is supported)", u.Scheme)
	}
	if u.Host == "" {
		return "", nil, fmt.Errorf("SOCKS proxy must include host:port")
	}
	if _, _, splitErr := net.SplitHostPort(u.Host); splitErr != nil {
		return "", nil, fmt.Errorf("SOCKS proxy %q must be host:port: %w", u.Host, splitErr)
	}

	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	return u.Host, auth, nil
}

// buildProxyDialer constructs a SOCKS5 dialer from the raw flag value. The
// forward dialer is proxy.Direct so the proxy itself is reached directly.
func buildProxyDialer(raw string) (proxy.Dialer, error) {
	addr, auth, err := parseSocks(raw)
	if err != nil {
		return nil, err
	}
	d, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to build SOCKS5 dialer: %w", err)
	}
	return d, nil
}

// proxyRequiresExplicitDC reports whether the config would rely on SRV-based
// DC auto-discovery while a SOCKS proxy is set but no DNS server is given.
// SRV lookups need DNS, which cannot traverse SOCKS over UDP; without a
// proxied DNS server (-dns) the operator must supply an explicit -dc. When
// -dns is set, DNS is tunneled over TCP through the proxy and SRV
// auto-discovery works, so no -dc is required.
func proxyRequiresExplicitDC(config Config) bool {
	if config.proxyDialer == nil || config.DNSServer != "" {
		return false
	}
	hasExplicitDC := config.DomainController != ""
	hasCredentials := config.Username != "" && config.Password != "" && config.Domain != ""
	hasTargetFile := config.TargetsFile != ""
	hasPartialHostShare := config.Host != "" || config.Share != ""
	return hasCredentials && !hasExplicitDC && !hasTargetFile && !hasPartialHostShare
}

// shouldResolveLocally reports whether Sulla should resolve a hostname to an IP
// itself (via getResolver) before dialing, versus handing the hostname to the
// SOCKS proxy for remote resolution.
//
//   - No proxy: always resolve locally (existing behavior).
//   - Proxy + -dns: resolve via the DNS server, tunneled over TCP through the
//     proxy, so internal names resolve regardless of the pivot host's resolver.
//   - Proxy, no -dns: do not resolve locally; pass the hostname to the proxy
//     for remote DNS at the pivot host.
func shouldResolveLocally(config Config) bool {
	return config.proxyDialer == nil || config.DNSServer != ""
}

// proxyDialTimeoutFactor scales the caller's direct-dial timeout when dialing
// through a SOCKS proxy. A pivot adds a round-trip (client→proxy→target) plus
// the SOCKS handshake on top of the target connect, so the tight budgets tuned
// for direct dials (e.g. 3s for SMB) are too aggressive over a tunnel and cause
// false-negative connection failures. Doubling keeps failures bounded while
// giving the pivot room to breathe.
const proxyDialTimeoutFactor = 2

// dialTCP is the single choke point for every outbound TCP connection. When
// config carries a proxy dialer, it dials through the proxy passing the
// HOSTNAME so the proxy resolves it (remote DNS). Otherwise it performs a
// direct dial with the given timeout, preserving the pre-proxy behavior.
//
// The timeout is honored in both modes. In proxy mode the x/net SOCKS5 dialer
// has no timeout field of its own, so the budget is enforced via the context
// (and scaled by proxyDialTimeoutFactor for pivot latency). Any deadline
// already on ctx still takes precedence, so callers that wrap ctx with a
// tighter bound (dialLDAP, the DNS resolver) are unaffected.
func dialTCP(ctx context.Context, config Config, addr string, timeout time.Duration) (net.Conn, error) {
	if config.proxyDialer != nil {
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout*proxyDialTimeoutFactor)
			defer cancel()
		}
		if cd, ok := config.proxyDialer.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		// x/net's SOCKS5 dialer always implements ContextDialer; this is a
		// safety net for alternative dialer implementations.
		return config.proxyDialer.Dial("tcp", addr)
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", addr)
}
