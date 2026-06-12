package sulla

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/hirochachacha/go-smb2"
)

// domainToBaseDN converts a domain name to LDAP base DN
// e.g., "corp.local" -> "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var dnParts []string
	for _, part := range parts {
		dnParts = append(dnParts, "DC="+part)
	}
	return strings.Join(dnParts, ",")
}

// sidToString converts a binary SID to its string representation
// SID format: S-R-I-S-S-S...
// Where R=revision, I=identifier authority, S=sub-authorities
func sidToString(sidBytes []byte) string {
	if len(sidBytes) < 8 {
		return ""
	}

	revision := sidBytes[0]
	subAuthCount := int(sidBytes[1])

	// Identifier authority is 6 bytes big-endian
	var identAuth uint64
	for i := 2; i < 8; i++ {
		identAuth = (identAuth << 8) | uint64(sidBytes[i])
	}

	// Build SID string
	sid := fmt.Sprintf("S-%d-%d", revision, identAuth)

	// Sub-authorities are 4 bytes little-endian each
	for i := 0; i < subAuthCount && 8+i*4+4 <= len(sidBytes); i++ {
		subAuth := binary.LittleEndian.Uint32(sidBytes[8+i*4:])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// discoverTargets orchestrates host and share discovery with parallel workers
// If fetchSIDs is true, also fetches SIDs for capability-sdk output
func discoverTargets(config Config, fetchSIDs bool) ([]Target, *DiscoveryResult, error) {
	// Step 1: Get list of domain controllers to try
	var domainControllers []string

	if config.DomainController != "" {
		// User explicitly specified a DC
		domainControllers = []string{config.DomainController}
		logf("[*] Using specified domain controller: %s\n", config.DomainController)
	} else {
		// Auto-discover DCs via DNS SRV lookup
		logf("[*] Discovering domain controllers for %s...\n", config.Domain)
		dcs, err := discoverDomainControllers(config.Domain, config.DNSServer)
		if err != nil {
			return nil, nil, fmt.Errorf("could not auto-discover domain controller for %s: %w\n\nProvide a domain controller explicitly with -dc <hostname>\nor try a different DNS server with -dns <ip>", config.Domain, err)
		}
		domainControllers = dcs
		logf("[+] Discovered %d domain controller(s): %s\n", len(dcs), strings.Join(dcs, ", "))
	}

	// Step 2: Discover computers from AD
	logf("[*] Querying AD for computer objects...\n")
	computers, discoveryResult, err := discoverComputers(config, domainControllers, fetchSIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover computers: %w", err)
	}
	logf("[+] Found %d computers in AD\n", len(computers))

	if len(computers) == 0 {
		return nil, discoveryResult, nil
	}

	// Step 2: Discover shares on each computer (parallel workers)
	logln("[*] Identifying shares on discovered hosts (this could take a while)...")

	// Pre-compile share exclusion patterns once
	compiledExclusions := compileExcludedShares(config.ExcludedShares)

	type hostShares struct {
		host   string
		shares []string
		err    error
	}

	jobs := make(chan string, len(computers))
	results := make(chan hostShares, len(computers))

	// Start workers (use ShareWorkers for discovery too, minimum 20)
	discoveryWorkers := max(config.ShareWorkers, 20)
	var wg sync.WaitGroup
	for i := 0; i < discoveryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				shares, err := discoverSharesOnHost(host, config, compiledExclusions)
				results <- hostShares{host: host, shares: shares, err: err}
			}
		}()
	}

	// Send jobs
	for _, computer := range computers {
		jobs <- computer
	}
	close(jobs)

	// Wait for workers and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var targets []Target
	var hostsWithShares, totalShares, failedHosts int
	for result := range results {
		if result.err != nil {
			failedHosts++
			if config.Verbose {
				logf("[!] %s: %v\n", result.host, result.err)
			}
			continue
		}
		if len(result.shares) > 0 {
			hostsWithShares++
			for _, share := range result.shares {
				totalShares++
				targets = append(targets, Target{Host: result.host, Share: share})
				if config.Verbose {
					logf("[+] Found \\\\%s\\%s\n", result.host, share)
				}
			}
		}
	}

	logf("[+] Found %d accessible shares on %d hosts\n", totalShares, hostsWithShares)
	if failedHosts > 0 && !config.Verbose {
		logf("[*] %d hosts unreachable (use -v for details)\n", failedHosts)
	}

	// DFS namespace awareness: discover DFS links and deduplicate targets
	if !config.NoDFS && len(targets) > 0 {
		logln("[*] Querying AD for DFS namespaces...")
		dfsLinks, dfsErr := discoverDFSNamespaces(config, domainControllers)
		if dfsErr != nil {
			// DFS discovery failure is non-fatal — continue without dedup
			logf("[!] DFS namespace discovery failed (continuing without DFS dedup): %v\n", dfsErr)
		} else if len(dfsLinks) > 0 {
			if config.Verbose {
				logf("[+] Found DFS links covering %d physical share(s)\n", len(dfsLinks))
			}
			var removed int
			targets, removed = deduplicateTargetsWithDFS(targets, dfsLinks, config.Domain)
			if removed > 0 && config.Verbose {
				logf("[+] DFS dedup: removed %d duplicate target(s), %d target(s) remaining\n", removed, len(targets))
			}
		} else if config.Verbose {
			logln("[*] No DFS namespaces found")
		}

		// Deduplicate DFSR-replicated shares (SYSVOL, NETLOGON) across domain controllers.
		// These use DFSR replication (msDFSR-* AD objects) rather than standard DFS namespaces,
		// so discoverDFSNamespaces does not detect them. Every DC serves identical content.
		// Skip if DFS discovery failed — LDAP was unreachable, so the DC list may be incomplete.
		if dfsErr == nil {
			var replicatedRemoved int
			targets, replicatedRemoved = deduplicateReplicatedShares(targets, config.Domain)
			if replicatedRemoved > 0 && config.Verbose {
				logf("[+] DFSR dedup: removed %d duplicate replicated share(s), %d target(s) remaining\n", replicatedRemoved, len(targets))
			}
		}
	}

	return targets, discoveryResult, nil
}

// discoverDomainControllers performs DNS SRV lookup to find domain controllers for a domain
func discoverDomainControllers(domain, dnsServer string) ([]string, error) {
	resolver := getResolver(dnsServer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try the DC-specific SRV record first: _ldap._tcp.dc._msdcs.<domain>
	_, srvs, err := resolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil || len(srvs) == 0 {
		// Fallback to generic LDAP SRV record: _ldap._tcp.<domain>
		_, srvs, err = resolver.LookupSRV(ctx, "ldap", "tcp", domain)
	}

	if err != nil {
		return nil, fmt.Errorf("DNS SRV lookup failed: %w", err)
	}

	if len(srvs) == 0 {
		return nil, fmt.Errorf("no SRV records found")
	}

	// Extract hostnames, sorted by priority (lower = higher priority) and weight
	// Go's LookupSRV already returns results sorted by priority
	var dcs []string
	for _, srv := range srvs {
		// Remove trailing dot from DNS name
		dc := strings.TrimSuffix(srv.Target, ".")
		if dc != "" {
			dcs = append(dcs, dc)
		}
	}

	return dcs, nil
}

// connectToLDAP establishes an LDAP connection to the specified domain controller.
// Returns the connection, a description of the method used, and any error.
//
// Auto-negotiation (default, no flags):
//  1. LDAPS + NTLMv2 with RFC 5929 channel binding (port 636)
//  2. LDAPS + simple bind (port 636) — credentials transit cleartext inside TLS
//  3. Plain LDAP + simple bind (port 389) — credentials cleartext on the wire
//
// --ldaps: attempts 1 and 2 only; plain LDAP skipped.
// --channel-binding: attempt 1 only; failure returns an error rather than
//   falling back to simple bind. Use to guarantee the operator's password
//   never transits as cleartext, even inside a TLS tunnel.
func connectToLDAP(dc string, config Config) (*ldap.Conn, string, error) {
	// Resolve DC hostname using custom DNS server if configured
	dcAddr := dc
	if net.ParseIP(dc) == nil {
		// It's a hostname, resolve it
		resolver := getResolver(config.DNSServer)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ips, resolveErr := resolver.LookupHost(ctx, dc)
		if resolveErr != nil {
			return nil, "", fmt.Errorf("DNS resolution failed for %s: %w", dc, resolveErr)
		}
		if len(ips) == 0 {
			return nil, "", fmt.Errorf("no IP addresses found for %s", dc)
		}
		dcAddr = ips[0]
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         dc, // Use original hostname for TLS SNI
	}
	bindUser := fmt.Sprintf("%s@%s", config.Username, config.Domain)

	// Determine which methods to attempt based on flags
	autoNegotiate := !config.UseLDAPS && !config.ChannelBinding

	// Attempt 1: LDAPS + channel binding (NTLM)
	if config.ChannelBinding || config.UseLDAPS || autoNegotiate {
		var lastErr error
		l, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", dcAddr), ldap.DialWithTLSConfig(tlsConfig))
		if err == nil {
			if bindErr := bindNTLMWithCBT(ntlmChallengeBindAdapter{c: l}, config); bindErr == nil {
				return l, "LDAPS (NTLMv2 + channel binding)", nil
			} else {
				lastErr = bindErr
			}
			l.Close()
		} else {
			lastErr = err
		}
		// --channel-binding: refuse fallback so credentials never leak as
		// cleartext (even inside the TLS tunnel of a simple bind).
		if config.ChannelBinding {
			return nil, "", fmt.Errorf(
				"NTLMv2+CBT bind failed for %s (--channel-binding refuses simple-bind fallback): %w",
				dc, lastErr)
		}
	}

	// Attempt 2: LDAPS + simple bind
	if config.UseLDAPS || autoNegotiate {
		var lastErr error
		l, err := ldap.DialURL(fmt.Sprintf("ldaps://%s:636", dcAddr), ldap.DialWithTLSConfig(tlsConfig))
		if err == nil {
			if bindErr := l.Bind(bindUser, config.Password); bindErr == nil {
				return l, "LDAPS", nil
			} else {
				lastErr = bindErr
			}
			l.Close()
		} else {
			lastErr = err
		}
		// If --ldaps was explicitly requested, don't fall back to plain LDAP
		if config.UseLDAPS {
			return nil, "", fmt.Errorf("LDAPS connection failed for %s: %w", dc, lastErr)
		}
	}

	// Attempt 3: Plain LDAP (port 389)
	if autoNegotiate {
		l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", dcAddr))
		if err == nil {
			if bindErr := l.Bind(bindUser, config.Password); bindErr == nil {
				return l, "LDAP", nil
			} else {
				l.Close()
				return nil, "", fmt.Errorf("LDAP bind failed for %s: %w", dc, bindErr)
			}
		}
		return nil, "", fmt.Errorf("failed to connect to DC %s: %w", dc, err)
	}

	return nil, "", fmt.Errorf("all LDAP connection methods failed for %s", dc)
}

// discoverComputers queries AD via LDAP for all computer objects
// It tries each domain controller in the list until one succeeds
// Returns computer hostnames and optionally DiscoveryResult with SIDs for capability-sdk output
func discoverComputers(config Config, domainControllers []string, fetchSIDs bool) ([]string, *DiscoveryResult, error) {
	var l *ldap.Conn
	var err error
	var connectedDC string
	var connMethod string

	// Try each DC until one works
	for _, dc := range domainControllers {
		l, connMethod, err = connectToLDAP(dc, config)
		if err == nil {
			connectedDC = dc
			break
		}
		logf("[!] Failed to connect to %s: %v\n", dc, err)
	}

	if l == nil {
		return nil, nil, fmt.Errorf("failed to connect to any domain controller")
	}
	defer l.Close()

	if config.Verbose {
		logf("[+] %s connection established to %s\n", connMethod, connectedDC)
	}

	baseDN := domainToBaseDN(config.Domain)

	// Initialize discovery result if fetching SIDs
	var discoveryResult *DiscoveryResult
	if fetchSIDs {
		discoveryResult = &DiscoveryResult{
			Computers: make(map[string]ComputerInfo),
		}

		// Fetch domain SID
		domainSearchRequest := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=domain)",
			[]string{"objectSid", "distinguishedName"},
			nil,
		)
		domainResult, err := l.Search(domainSearchRequest)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch domain SID: %w", err)
		}
		if len(domainResult.Entries) > 0 {
			entry := domainResult.Entries[0]
			sidBytes := entry.GetRawAttributeValue("objectSid")
			discoveryResult.Domain = DomainInfo{
				Name:              strings.ToLower(config.Domain),
				SID:               sidToString(sidBytes),
				DistinguishedName: entry.GetAttributeValue("distinguishedName"),
			}
			logf("[+] Domain SID: %s\n", discoveryResult.Domain.SID)
		}
	}

	// Calculate timestamp for 4 months ago in Windows FILETIME format
	// FILETIME is 100-nanosecond intervals since January 1, 1601
	// Unix epoch (Jan 1, 1970) = 116444736000000000 in FILETIME
	const unixEpochDiff = 116444736000000000
	fourMonthsAgo := time.Now().AddDate(0, -4, 0)
	fileTime := (fourMonthsAgo.Unix() * 10000000) + unixEpochDiff

	// Build LDAP filter:
	// - objectClass=computer: only computer accounts
	// - !(userAccountControl:1.2.840.113556.1.4.803:=2): exclude disabled accounts (bit 2 = ACCOUNTDISABLE)
	// - lastLogonTimestamp>=X: only machines that logged in within last 4 months
	ldapFilter := fmt.Sprintf("(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=%d))", fileTime)

	// Fetch additional attributes if we need SIDs
	attributes := []string{"dNSHostName"}
	if fetchSIDs {
		attributes = append(attributes, "objectSid", "distinguishedName")
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		ldapFilter,
		attributes,
		nil,
	)

	// Use paged search with 500 entries per page to avoid size limit errors
	sr, err := l.SearchWithPaging(searchRequest, 500)
	if err != nil {
		return nil, nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	var computers []string
	for _, entry := range sr.Entries {
		dnsHostName := entry.GetAttributeValue("dNSHostName")
		if dnsHostName != "" {
			computers = append(computers, dnsHostName)

			// Store computer info if fetching SIDs
			if fetchSIDs && discoveryResult != nil {
				sidBytes := entry.GetRawAttributeValue("objectSid")
				discoveryResult.Computers[dnsHostName] = ComputerInfo{
					DNSHostName:       dnsHostName,
					SID:               sidToString(sidBytes),
					DistinguishedName: entry.GetAttributeValue("distinguishedName"),
				}
			}
		}
	}

	return computers, discoveryResult, nil
}

// discoverSharesOnHost enumerates SMB shares on a host and returns those with read access
func discoverSharesOnHost(host string, config Config, compiledExclusions []*regexp.Regexp) ([]string, error) {
	// Resolve hostname to IP using custom resolver if configured
	resolver := getResolver(config.DNSServer)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found")
	}

	// Connect to SMB
	conn, err := net.DialTimeout("tcp", ips[0]+":445", 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()
	// Cap entire SMB session (auth + list shares + access checks) so slow/hung
	// hosts don't block discovery workers indefinitely.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Create SMB dialer
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     config.Username,
			Password: config.Password,
			Domain:   config.Domain,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		if isSigningError(err) {
			return nil, fmt.Errorf("authentication failed (server requires signing): %w", err)
		}
		return nil, fmt.Errorf("SMB dial failed: %w", err)
	}
	defer s.Logoff()

	// List shares
	shareNames, err := s.ListSharenames()
	if err != nil {
		if isSigningError(err) {
			return nil, fmt.Errorf("authentication failed (server requires signing): %w", err)
		}
		return nil, fmt.Errorf("failed to list shares: %w", err)
	}

	// Check read access for each share (skip excluded shares)
	var accessibleShares []string
	for _, shareName := range shareNames {
		if isShareExcluded(shareName, compiledExclusions) {
			continue
		}
		if checkShareAccess(s, shareName) {
			accessibleShares = append(accessibleShares, shareName)
		}
	}

	return accessibleShares, nil
}
