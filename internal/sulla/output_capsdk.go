package sulla

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

// capSDKEnvelope is the on-disk wire envelope the capability-sdk parser
// expects: top-level "items" array, each item carrying a "_type" discriminator
// that matches a registered converter on the parser side.
type capSDKEnvelope struct {
	Items []any `json:"items"`
}

// marshalCapSDKItem stamps the "_type" discriminator onto a capmodel struct
// by re-marshalling the struct's fields into a map and injecting the type
// tag. This avoids defining per-item wrapper structs.
func marshalCapSDKItem(typ string, body any) (json.RawMessage, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(bodyBytes, &obj); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	typeBytes, _ := json.Marshal(typ)
	obj["_type"] = typeBytes
	return json.Marshal(obj)
}

// generateCapabilitySDKOutput writes a <domain>.tabularium file consumed by
// the capability-sdk parser. Replaces the hand-rolled Tabularium emitter in
// output.go.
func generateCapabilitySDKOutput(config Config, results []ScanResult) error {
	discovery := config.DiscoveryResult
	if discovery == nil {
		return fmt.Errorf("no discovery result available")
	}

	domainLower := strings.ToLower(config.Domain)
	envelope := capSDKEnvelope{Items: []any{}}

	domainObj := capmodel.ADObject{
		Label:             "ADDomain",
		Domain:            domainLower,
		ObjectID:          discovery.Domain.SID,
		SID:               discovery.Domain.SID,
		DomainSID:         discovery.Domain.SID,
		DistinguishedName: discovery.Domain.DistinguishedName,
	}
	item, err := marshalCapSDKItem("ADObject", domainObj)
	if err != nil {
		return err
	}
	envelope.Items = append(envelope.Items, item)

	hostFindings := make(map[string][]ScanResult)
	for _, r := range results {
		if r.HasFindings {
			hostFindings[r.Host] = append(hostFindings[r.Host], r)
		}
	}

	for host, hostResults := range hostFindings {
		computerInfo, ok := discovery.Computers[host]
		if !ok {
			logf("[!] Warning: Computer %s not found in discovery result, skipping capsdk entry\n", host)
			continue
		}

		computerObj := capmodel.ADObject{
			Label:             "ADComputer",
			Domain:            domainLower,
			ObjectID:          computerInfo.SID,
			SID:               computerInfo.SID,
			DistinguishedName: computerInfo.DistinguishedName,
			DNSHostname:       strings.ToLower(computerInfo.DNSHostName),
		}
		item, err := marshalCapSDKItem("ADObject", computerObj)
		if err != nil {
			return err
		}
		envelope.Items = append(envelope.Items, item)

		var proofContent strings.Builder
		fmt.Fprintf(&proofContent, "Host: %s\n", host)
		fmt.Fprintf(&proofContent, "Shares with findings: %d\n", len(hostResults))
		proofContent.WriteString("=" + strings.Repeat("=", 50) + "\n\n")
		for _, r := range hostResults {
			fmt.Fprintf(&proofContent, "Share: %s\n", r.Share)
			proofContent.WriteString("-" + strings.Repeat("-", 30) + "\n")
			if r.OutputPath != "" {
				content, err := os.ReadFile(r.OutputPath)
				if err == nil {
					proofContent.WriteString(redactProofContent(string(content)))
				} else {
					fmt.Fprintf(&proofContent, "[Could not read output file: %v]\n", err)
				}
			} else {
				proofContent.WriteString("[No output file saved]\n")
			}
			proofContent.WriteString("\n")
		}

		hostLower := strings.ToLower(host)
		// Embedded target must carry its own _type for convertRisk
		// (parser.go docstring lines 9-11). Use a minimal ADComputer
		// stub so convertRisk has enough to resolve the target node.
		targetItem, err := marshalCapSDKItem("ADObject", capmodel.ADObject{
			Label:       "ADComputer",
			Domain:      domainLower,
			ObjectID:    computerInfo.SID,
			SID:         computerInfo.SID,
			DNSHostname: strings.ToLower(computerInfo.DNSHostName),
		})
		if err != nil {
			return err
		}
		risk := capmodel.Risk{
			TargetName: hostLower,
			Name:       "smb-exposed-secrets",
			Title:      "Secrets in Network Shares",
			Source:     "sulla:TITUS",
			Status:     "TM",
			Proof:      []byte(proofContent.String()),
			Target:     json.RawMessage(targetItem),
		}
		item, err = marshalCapSDKItem("Risk", risk)
		if err != nil {
			return err
		}
		envelope.Items = append(envelope.Items, item)
	}

	jsonData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize capsdk output: %w", err)
	}
	filename := fmt.Sprintf("%s.tabularium", sanitizeFilename(config.Domain))
	outputPath := filename
	if config.OutputFile != "" {
		if info, err := os.Stat(config.OutputFile); err == nil && info.IsDir() {
			outputPath = filepath.Join(config.OutputFile, filename)
		} else if strings.HasSuffix(config.OutputFile, "/") || strings.HasSuffix(config.OutputFile, string(os.PathSeparator)) {
			if err := os.MkdirAll(config.OutputFile, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}
			outputPath = filepath.Join(config.OutputFile, filename)
		}
	}
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write capsdk output: %w", err)
	}
	logf("[+] capability-sdk output written to %s\n", outputPath)
	return nil
}
