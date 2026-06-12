package sulla

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateCapSDKOutput_Shape verifies the generated file conforms to the
// capability-sdk parser wire contract (PascalCase _type strings,
// capmodel field names, Risk.proof as raw []byte, no separate File item).
func TestGenerateCapSDKOutput_Shape(t *testing.T) {
	tmp := t.TempDir()
	config := Config{
		Domain:        "corp.local",
		OutputFile:    tmp,
		OutputFormats: []string{"capability-sdk"},
		DiscoveryResult: &DiscoveryResult{
			Domain: DomainInfo{
				Name:              "corp.local",
				SID:               "S-1-5-21-domain",
				DistinguishedName: "DC=corp,DC=local",
			},
			Computers: map[string]ComputerInfo{
				"host1.corp.local": {
					DNSHostName:       "host1.corp.local",
					SID:               "S-1-5-21-host1",
					DistinguishedName: "CN=HOST1,DC=corp,DC=local",
				},
			},
		},
	}

	proofPath := filepath.Join(tmp, "host1.proof.txt")
	if err := os.WriteFile(proofPath, []byte("found secret on share\n"), 0644); err != nil {
		t.Fatal(err)
	}
	results := []ScanResult{
		{Host: "host1.corp.local", Share: "C$", HasFindings: true, OutputPath: proofPath},
	}

	if err := generateCapabilitySDKOutput(config, results); err != nil {
		t.Fatalf("generateCapabilitySDKOutput: %v", err)
	}

	out := filepath.Join(tmp, "corp_local.tabularium")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var envelope struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("envelope unmarshal: %v", err)
	}
	if len(envelope.Items) == 0 {
		t.Fatal("no items emitted")
	}

	var sawADDomain, sawADComputer, sawRisk bool
	var sawLegacyFile, sawLegacyTabulariumType bool

	for _, item := range envelope.Items {
		var typ string
		_ = json.Unmarshal(item["_type"], &typ)
		switch typ {
		case "ADObject":
			var label string
			_ = json.Unmarshal(item["label"], &label)
			if label == "ADDomain" {
				sawADDomain = true
			}
			if label == "ADComputer" {
				sawADComputer = true
				if _, ok := item["dnshostname"]; !ok {
					t.Error("ADObject(ADComputer) missing dnshostname field (capmodel uses lowercase 'dnshostname')")
				}
			}
		case "Risk":
			sawRisk = true
			if _, ok := item["proof"]; !ok {
				t.Error("Risk missing proof field")
			} else {
				var encoded string
				_ = json.Unmarshal(item["proof"], &encoded)
				encoded = strings.TrimPrefix(encoded, "base64:")
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil || len(decoded) == 0 {
					t.Errorf("Risk.proof not valid base64-encoded content: %v", err)
				}
			}
			if _, ok := item["target_name"]; !ok {
				t.Error("Risk missing target_name field")
			}
			if _, ok := item["target"]; !ok {
				t.Error("Risk missing target field (capmodel renames _target -> target)")
			}
			if _, ok := item["_target"]; ok {
				t.Error("Risk uses _target -- should be target for capmodel parser")
			}
			if _, ok := item["title"]; !ok {
				t.Error("Risk missing title field")
			}
		case "File":
			sawLegacyFile = true
		case "addomain", "adcomputer", "risk", "file":
			sawLegacyTabulariumType = true
		}
	}

	if !sawADDomain {
		t.Error("expected ADObject with label=ADDomain")
	}
	if !sawADComputer {
		t.Error("expected ADObject with label=ADComputer")
	}
	if !sawRisk {
		t.Error("expected Risk item")
	}
	if sawLegacyFile {
		t.Error("emitter must not produce separate File items -- parser auto-extracts from Risk.proof")
	}
	if sawLegacyTabulariumType {
		t.Error("emitter must not produce lowercase tabularium _type strings")
	}
}

// TestValidateOutputFormat_TabulariumIsDeprecatedAlias verifies the legacy
// "tabularium" value is rewritten to "capability-sdk" so old scripts keep
// working for one release.
func TestValidateOutputFormat_TabulariumIsDeprecatedAlias(t *testing.T) {
	got, err := validateOutputFormats("tabularium")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range got {
		if f == "tabularium" {
			t.Error("validateOutputFormats returned 'tabularium' but it should be rewritten to 'capability-sdk'")
		}
	}
	found := false
	for _, f := range got {
		if f == "capability-sdk" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'tabularium' to be rewritten to 'capability-sdk'")
	}
}

// TestValidateOutputFormat_AcceptsCapabilitySDK verifies the CLI accepts
// the new format name. The legacy "tabularium" alias is covered in a
// separate test in Task 5.
func TestValidateOutputFormat_AcceptsCapabilitySDK(t *testing.T) {
	got, err := validateOutputFormats("capability-sdk")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, f := range got {
		if f == "capability-sdk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("validateOutputFormats(%q) did not include capability-sdk: %v", "capability-sdk", got)
	}
}
