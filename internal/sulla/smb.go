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
// Preferring the Go resolver avoids SIGSEGVs inside glibc getaddrinfo that occur
// when many discovery workers resolve concurrently on hosts with broken or
// non-thread-safe NSS modules. The cgo resolver is the CGO_ENABLED=1 default,
// which the vectorscan/Hyperscan build forces; pure-Go builds never use it.
//
// Escape hatch: set SULLA_SYSTEM_RESOLVER (any value) to fall back to the
// system (cgo) resolver for environments that depend on NSS-only name sources
// such as mDNS or sssd. Has no effect in pure-Go builds.
func getResolver(dnsServer string) *net.Resolver {
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
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}
}

func resolveHostToIP(host, dnsServer string) string {
	// If it's already an IP address, return as-is
	if net.ParseIP(host) != nil {
		return host
	}

	// Try to resolve hostname to IP using custom resolver if configured
	resolver := getResolver(dnsServer)
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
	ip := resolveHostToIP(config.Host, config.DNSServer)

	conn, err := net.DialTimeout("tcp", ip+":445", 3*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("SMB connection to %s (%s) failed: %w", config.Host, ip, err)
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
