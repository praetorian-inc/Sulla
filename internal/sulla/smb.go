package sulla

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// compileExcludedShares pre-compiles exclusion patterns into regexps.
// Invalid patterns are compiled as case-insensitive literal matches.
func compileExcludedShares(patterns []string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			// If invalid regex, fall back to literal match
			re = regexp.MustCompile("(?i)^" + regexp.QuoteMeta(pattern) + "$")
		}
		compiled = append(compiled, re)
	}
	return compiled
}

// isSigningError returns true if the error indicates an SMB signing negotiation failure,
// which typically means authentication was rejected or downgraded to guest on a host that
// requires signing.
func isSigningError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "signing required") ||
		strings.Contains(msg, "doesn't support signing")
}

// isShareExcluded checks if a share name should be excluded using pre-compiled patterns
func isShareExcluded(shareName string, compiledExclusions []*regexp.Regexp) bool {
	for _, re := range compiledExclusions {
		if re.MatchString(shareName) {
			return true
		}
	}
	return false
}

// checkShareAccess verifies read access to a share by stat-ing its root directory
func checkShareAccess(session *smb2.Session, shareName string) bool {
	share, err := session.Mount(shareName)
	if err != nil {
		return false
	}
	defer share.Umount()

	// Stat checks directory open permission. Cheaper than ReadDir (which fetches
	// all entries) but may succeed on shares where listing is denied. The scan
	// phase will catch those failures.
	_, err = share.Stat(".")
	return err == nil
}

// getResolver returns a DNS resolver. With a custom DNS server it queries that
// server directly; otherwise it returns a resolver that prefers Go's built-in
// resolver over cgo's getaddrinfo.
//
// When a SOCKS proxy and a custom DNS server are both set, DNS queries are
// tunneled over TCP through the proxy (see dnsStreamAsPacketConn), so internal
// names resolve via the specified server regardless of the pivot host's own
// resolver. Without a proxy, the custom DNS server is queried directly over UDP.
//
// Preferring the Go resolver avoids SIGSEGVs inside glibc getaddrinfo that occur
// when many discovery workers resolve concurrently on hosts with broken or
// non-thread-safe NSS modules. The cgo resolver is the CGO_ENABLED=1 default,
// which the vectorscan/Hyperscan build forces; pure-Go builds never use it.
//
// Escape hatch: set SULLA_SYSTEM_RESOLVER (any value) to fall back to the
// system (cgo) resolver for environments that depend on NSS-only name sources
// such as mDNS or sssd. Has no effect in pure-Go builds.
func getResolver(config Config) *net.Resolver {
	dnsServer := config.DNSServer

	// Proxy + custom DNS: resolve via DNS-over-TCP through the SOCKS proxy.
	// Returning a stream conn (rather than a net.PacketConn) makes the pure-Go
	// resolver use its DNS-over-TCP path — length-prefix framing and all — which
	// is exactly what we want, since SOCKS cannot carry UDP.
	if config.proxyDialer != nil && dnsServer != "" {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialTCP(ctx, config, dnsServerAddr(dnsServer), 5*time.Second)
			},
		}
	}

	if dnsServer == "" {
		if os.Getenv("SULLA_SYSTEM_RESOLVER") != "" {
			return net.DefaultResolver
		}
		return &net.Resolver{PreferGo: true}
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", dnsServerAddr(dnsServer))
		},
	}
}

// dnsServerAddr returns the DNS server as host:port. A bare IP/host gets the
// default DNS port 53; an address that already carries a port is used as-is.
func dnsServerAddr(dnsServer string) string {
	if _, _, err := net.SplitHostPort(dnsServer); err == nil {
		return dnsServer
	}
	return net.JoinHostPort(dnsServer, "53")
}

func resolveHostToIP(config Config, host string) string {
	// If it's already an IP address, return as-is
	if net.ParseIP(host) != nil {
		return host
	}

	// Try to resolve hostname to IP using custom resolver if configured
	resolver := getResolver(config)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs[0]
	}

	// If resolution fails, return original host
	return host
}

// smbConnect establishes an SMB session and mounts the target share.
// The caller must call share.Umount() and session.Logoff() when done.
func smbConnect(ctx context.Context, config Config) (net.Conn, *smb2.Session, *smb2.Share, error) {
	// Resolve locally unless we're proxying without a DNS server, in which case
	// the hostname is handed to the proxy for remote resolution.
	target := config.Host
	if shouldResolveLocally(config) {
		target = resolveHostToIP(config, config.Host)
	}

	conn, err := dialTCP(ctx, config, net.JoinHostPort(target, "445"), 3*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("SMB connection to %s (%s) failed: %w", config.Host, target, err)
	}

	// Cap SMB negotiation + auth + mount to 30s total
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     config.Username,
			Password: config.Password,
			Domain:   config.Domain,
		},
	}

	session, err := d.DialContext(ctx, conn)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("SMB auth to %s failed: %w", config.Host, err)
	}

	share, err := session.Mount(config.Share)
	if err != nil {
		session.Logoff()
		conn.Close()
		return nil, nil, nil, fmt.Errorf("mount %s\\%s failed: %w", config.Host, config.Share, err)
	}

	// Clear deadline so scanning isn't capped
	conn.SetDeadline(time.Time{})

	return conn, session, share, nil
}

// smbWalkDir recursively walks a share, calling fn for each file entry.
// Directories are filtered by shouldExcludeDir before recursion.
// dirCount is atomically incremented for each directory entered.
func smbWalkDir(ctx context.Context, share *smb2.Share, root string,
	excludedDirs dirExclusions, maxDepth int, maxFilesPerDir int, dirCount *int64, fn func(path string, size int64) error) error {

	return smbWalkDirRecursive(ctx, share, root, excludedDirs, maxDepth, maxFilesPerDir, 0, dirCount, fn)
}

func smbWalkDirRecursive(ctx context.Context, share *smb2.Share, dir string,
	excludedDirs dirExclusions, maxDepth int, maxFilesPerDir int, currentDepth int, dirCount *int64, fn func(path string, size int64) error) error {

	if ctx.Err() != nil {
		return ctx.Err()
	}

	atomic.AddInt64(dirCount, 1)

	entries, err := share.ReadDir(dir)
	if err != nil {
		return nil // skip unreadable directories
	}

	fileCount := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := entry.Name()
		fullPath := dir + "/" + name // go-smb2 uses forward slashes

		if entry.IsDir() {
			if shouldExcludeDir(name, excludedDirs) {
				continue
			}
			if maxDepth > 0 && currentDepth >= maxDepth {
				continue
			}
			if err := smbWalkDirRecursive(ctx, share, fullPath, excludedDirs, maxDepth, maxFilesPerDir, currentDepth+1, dirCount, fn); err != nil {
				return err
			}
		} else {
			if maxFilesPerDir > 0 && fileCount >= maxFilesPerDir {
				continue
			}
			if err := fn(fullPath, entry.Size()); err != nil {
				return err
			}
			fileCount++
		}
	}
	return nil
}
