package sulla

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// discoverDFSNamespaces queries AD for domain-based DFS namespace configurations.
// Returns a map from normalized "host\share" → []DFSLink for deduplication.
// A physical share may back multiple DFS links, so each key maps to a slice.
func discoverDFSNamespaces(config Config, domainControllers []string) (map[string][]DFSLink, error) {
	var l *ldap.Conn
	var err error

	// Try each DC until one works
	for _, dc := range domainControllers {
		l, _, err = connectToLDAP(dc, config)
		if err == nil {
			break
		}
	}
	if l == nil {
		return nil, fmt.Errorf("failed to connect to any domain controller for DFS discovery")
	}
	defer l.Close()

	baseDN := domainToBaseDN(config.Domain)
	dfsConfigDN := fmt.Sprintf("CN=Dfs-Configuration,CN=System,%s", baseDN)

	// Search for DFS namespace link objects (fTDfs class represents DFS links)
	// Domain-based DFS namespaces store links under:
	//   CN=<link>,CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...
	searchRequest := ldap.NewSearchRequest(
		dfsConfigDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=msDFS-Linkv2)",
		[]string{"msDFS-LinkPathv2", "msDFS-TargetListv2", "distinguishedName", "cn"},
		nil,
	)

	// Try v2 DFS objects first (Windows Server 2008+ domain-based DFS)
	sr, v2Err := l.SearchWithPaging(searchRequest, 500)
	var v2Results map[string][]DFSLink
	if v2Err == nil && len(sr.Entries) > 0 {
		v2Results = parseDFSv2Entries(sr.Entries, config.Domain)
		if config.Debug {
			logf("[*] DFS: found %d v2 link entries\n", len(sr.Entries))
		}
	}

	// Also try legacy DFS objects (Windows 2000/2003 style fTDfs)
	// Many environments use legacy objects even on modern DCs
	legacyRequest := ldap.NewSearchRequest(
		dfsConfigDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=fTDfs)",
		[]string{"remoteServerName", "distinguishedName", "cn"},
		nil,
	)
	legacySR, legacyErr := l.SearchWithPaging(legacyRequest, 500)
	var legacyResults map[string][]DFSLink
	if legacyErr == nil && len(legacySR.Entries) > 0 {
		legacyResults = parseLegacyDFSEntries(legacySR.Entries, config.Domain)
		if config.Debug {
			logf("[*] DFS: found %d legacy (fTDfs) entries\n", len(legacySR.Entries))
		}
	}

	// If both failed, report the errors
	if v2Err != nil && legacyErr != nil {
		return nil, fmt.Errorf("DFS LDAP query failed (v2: %v, legacy: %w)", v2Err, legacyErr)
	}

	// Merge results — legacy entries may cover namespaces that v2 missed
	merged := make(map[string][]DFSLink)
	for k, v := range v2Results {
		merged[k] = v
	}
	for k, v := range legacyResults {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}

	return merged, nil
}

// parseDFSv2Entries parses msDFS-Linkv2 LDAP entries into a target lookup map.
func parseDFSv2Entries(entries []*ldap.Entry, domain string) map[string][]DFSLink {
	result := make(map[string][]DFSLink)
	domainLower := strings.ToLower(domain)

	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		linkPath := entry.GetAttributeValue("msDFS-LinkPathv2")
		targetListRaw := entry.GetRawAttributeValues("msDFS-TargetListv2")

		if linkPath == "" || len(targetListRaw) == 0 {
			continue
		}

		// Clean the link path (remove leading backslash if present)
		linkPath = strings.TrimPrefix(linkPath, "\\")

		// Extract namespace name from DN: CN=<link>,CN=<namespace>,CN=Dfs-Configuration,...
		namespace := extractNamespaceFromDN(dn)
		if namespace == "" {
			continue
		}

		dfsPath := fmt.Sprintf(`\\%s\%s\%s`, domainLower, namespace, linkPath)

		// Parse all target list blobs to extract physical server/share targets
		var targets []DFSTarget
		for _, raw := range targetListRaw {
			targets = append(targets, parseDFSTargetListBytes(raw)...)
		}

		link := DFSLink{
			Namespace: namespace,
			LinkPath:  linkPath,
			DFSPath:   dfsPath,
			Targets:   targets,
		}

		// Map each physical target to this DFS link (accumulate — a share may back multiple links)
		for _, t := range targets {
			key := strings.ToLower(t.Host + `\` + t.Share)
			if t.Path != "" {
				key += `\` + strings.ToLower(t.Path)
			}
			result[key] = append(result[key], link)
		}
	}

	return result
}

// parseLegacyDFSEntries parses legacy fTDfs LDAP entries (Windows 2000/2003 DFS).
func parseLegacyDFSEntries(entries []*ldap.Entry, domain string) map[string][]DFSLink {
	result := make(map[string][]DFSLink)
	domainLower := strings.ToLower(domain)

	for _, entry := range entries {
		dn := entry.GetAttributeValue("distinguishedName")
		remoteServers := entry.GetAttributeValues("remoteServerName")

		if len(remoteServers) == 0 {
			continue
		}

		namespace := extractNamespaceFromDN(dn)
		linkName := entry.GetAttributeValue("cn")
		if namespace == "" || linkName == "" {
			continue
		}

		dfsPath := fmt.Sprintf(`\\%s\%s\%s`, domainLower, namespace, linkName)

		var targets []DFSTarget
		for _, rs := range remoteServers {
			t := parseRemoteServerName(rs)
			if t.Host != "" {
				targets = append(targets, t)
			}
		}

		link := DFSLink{
			Namespace: namespace,
			LinkPath:  linkName,
			DFSPath:   dfsPath,
			Targets:   targets,
		}

		for _, t := range targets {
			key := strings.ToLower(t.Host + `\` + t.Share)
			result[key] = append(result[key], link)
		}
	}

	return result
}

// extractNamespaceFromDN extracts the DFS namespace name from a distinguished name.
// DN format: CN=<link>,CN=<namespace>,CN=Dfs-Configuration,CN=System,DC=...
func extractNamespaceFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, part := range parts {
		if strings.EqualFold(strings.TrimSpace(part), "CN=Dfs-Configuration") && i >= 2 {
			// The namespace is the CN immediately before Dfs-Configuration
			nsPart := strings.TrimSpace(parts[i-1])
			if strings.HasPrefix(strings.ToUpper(nsPart), "CN=") {
				return nsPart[3:]
			}
		}
	}
	return ""
}

// parseDFSTargetListBytes extracts server/share targets from a raw msDFS-TargetListv2 blob.
// The blob is a binary structure (MS-DFSNM wire format) that may contain UNC paths in
// either ASCII or UTF-16LE encoding. We extract UNC paths by scanning for \\ patterns.
func parseDFSTargetListBytes(raw []byte) []DFSTarget {
	var targets []DFSTarget

	// Try to decode as UTF-16LE first (common in AD binary attributes).
	// If that yields valid UNC paths, use them. Otherwise fall back to raw bytes as ASCII.
	text := decodeUTF16LEIfPresent(raw)

	remaining := text
	for {
		idx := strings.Index(remaining, `\\`)
		if idx == -1 {
			break
		}
		remaining = remaining[idx:]

		// Extract the UNC path (up to whitespace, null, or control char)
		endIdx := len(remaining)
		for i, c := range remaining[2:] {
			if c == 0 || c == '\t' || c == '\n' || c == '\r' || c == ' ' {
				endIdx = i + 2
				break
			}
		}

		uncPath := remaining[:endIdx]
		remaining = remaining[endIdx:]

		t := parseUNCToTarget(uncPath)
		if t.Host != "" && t.Share != "" {
			targets = append(targets, t)
		}
	}

	return targets
}

// decodeUTF16LEIfPresent checks if the byte slice appears to be UTF-16LE encoded
// (contains null bytes interleaved with ASCII) and decodes it. Otherwise returns
// the bytes as a plain string.
func decodeUTF16LEIfPresent(data []byte) string {
	if len(data) < 4 {
		return string(data)
	}

	// Heuristic: if the second byte is 0x00 and the first is printable ASCII,
	// it's likely UTF-16LE
	if data[1] == 0 && data[0] >= 0x20 && data[0] < 0x7f {
		var sb strings.Builder
		for i := 0; i+1 < len(data); i += 2 {
			ch := uint16(data[i]) | uint16(data[i+1])<<8
			if ch == 0 {
				sb.WriteByte(0) // preserve null terminators for boundary detection
			} else if ch < 128 {
				sb.WriteByte(byte(ch))
			} else {
				sb.WriteRune(rune(ch))
			}
		}
		return sb.String()
	}

	return string(data)
}

// parseUNCToTarget converts a UNC path like \\server\share\path to a DFSTarget.
func parseUNCToTarget(unc string) DFSTarget {
	// Remove leading backslashes
	trimmed := strings.TrimLeft(unc, `\`)
	parts := strings.SplitN(trimmed, `\`, 3)

	var t DFSTarget
	if len(parts) >= 1 {
		t.Host = parts[0]
	}
	if len(parts) >= 2 {
		t.Share = parts[1]
	}
	if len(parts) >= 3 {
		t.Path = parts[2]
	}
	return t
}

// parseRemoteServerName parses a legacy DFS remoteServerName value.
// Format is typically: *\server\share or \\server\share
func parseRemoteServerName(rs string) DFSTarget {
	return parseUNCToTarget(strings.TrimLeft(rs, "*"))
}

// deduplicateTargetsWithDFS removes targets that are physical backends of DFS links.
// For each such target, the DFS namespace path is preferred. Targets not covered by DFS are kept as-is.
// Returns the deduplicated target list and the count of removed duplicates.
func deduplicateTargetsWithDFS(targets []Target, dfsLinks map[string][]DFSLink, domain string) ([]Target, int) {
	if len(dfsLinks) == 0 {
		return targets, 0
	}

	domainLower := strings.ToLower(domain)

	// Track which DFS namespaces we need to add as scan targets
	namespacesToAdd := make(map[string]bool) // keyed by lowercase namespace name
	// Track which targets to keep (those not covered by DFS)
	var kept []Target
	removed := 0

	for _, t := range targets {
		key := strings.ToLower(t.Host + `\` + t.Share)
		if links, isDFSTarget := dfsLinks[key]; isDFSTarget {
			// This physical share is a DFS link target — skip it, add namespace(s) instead
			for _, link := range links {
				namespacesToAdd[strings.ToLower(link.Namespace)] = true
			}
			removed++
		} else {
			// Check if this target IS a DFS namespace root (the namespace share on the domain FQDN)
			// e.g., \\corp.local\namespace — only match exact domain FQDN, not arbitrary hosts
			isNamespaceRoot := false
			for _, links := range dfsLinks {
				for _, link := range links {
					if strings.EqualFold(t.Share, link.Namespace) && strings.EqualFold(t.Host, domainLower) {
						isNamespaceRoot = true
						break
					}
				}
				if isNamespaceRoot {
					break
				}
			}
			if isNamespaceRoot {
				// It's a DFS namespace root share on a DC — keep it as the canonical scan target
				t.DFSPath = fmt.Sprintf(`\\%s\%s`, domainLower, t.Share)
			}
			kept = append(kept, t)
		}
	}

	// Add DFS namespace root targets for links whose physical backends were removed.
	// We mount \\domain\namespace (the namespace root share) and let cifs follow DFS referrals.
	for nsName := range namespacesToAdd {
		// Check if we already have a target for this namespace root
		alreadyHave := false
		for _, t := range kept {
			if strings.EqualFold(t.Share, nsName) && strings.EqualFold(t.Host, domainLower) {
				alreadyHave = true
				break
			}
		}
		if !alreadyHave {
			// Add the DFS namespace root as a scan target — mount \\domain\namespace
			kept = append(kept, Target{
				Host:    domainLower,
				Share:   nsName,
				DFSPath: fmt.Sprintf(`\\%s\%s`, domainLower, nsName),
			})
		}
	}

	return kept, removed
}

// deduplicateReplicatedShares removes redundant SYSVOL and NETLOGON targets.
// These shares use DFSR replication and serve identical content on every DC, so scanning one is sufficient.
// Any host exposing these shares is a DC by definition — we don't rely on the DNS SRV DC list
// because SRV records often only contain a subset of DCs in large environments.
func deduplicateReplicatedShares(targets []Target, domain string) ([]Target, int) {
	// Well-known DFSR-replicated shares present on every DC
	replicatedShares := map[string]bool{
		"sysvol":   true,
		"netlogon": true,
	}

	// Track which replicated shares we've already kept (keyed by lowercase share name)
	seen := make(map[string]bool)
	var kept []Target
	removed := 0

	for _, t := range targets {
		shareLower := strings.ToLower(t.Share)

		if replicatedShares[shareLower] {
			if seen[shareLower] {
				removed++
				continue
			}
			seen[shareLower] = true
			// Tag the kept target with a DFS path for cleaner output
			if t.DFSPath == "" {
				t.DFSPath = fmt.Sprintf(`\\%s\%s`, strings.ToLower(domain), shareLower)
			}
		}
		kept = append(kept, t)
	}

	return kept, removed
}
