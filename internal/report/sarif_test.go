package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateSARIFFile(t *testing.T, schema *jsonschema.Schema, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if err := schema.Validate(doc); err != nil {
		t.Errorf("%s does not match schemas/sarif-2.1.0.json: %v", path, err)
	}
}

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft4)
	schema, err := c.Compile(filepath.Join("..", "..", "schemas", name))
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func TestSARIFGoldenSchemas(t *testing.T) {
	// schemas/sarif-2.1.0.json is the official OASIS SARIF 2.1.0 errata01 schema
	// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json).
	schema := compileSchema(t, "sarif-2.1.0.json")
	root := filepath.Join("..", "..")
	goldens, err := filepath.Glob(filepath.Join(root, "testdata", "repos", "*", "scan.sarif.golden"))
	if err != nil {
		t.Fatal(err)
	}
	clusterGoldens, err := filepath.Glob(filepath.Join(root, "testdata", "cluster", "*", "scan.sarif.golden"))
	if err != nil {
		t.Fatal(err)
	}
	goldens = append(goldens, clusterGoldens...)
	if len(goldens) == 0 {
		t.Fatal("no SARIF goldens found")
	}
	for _, golden := range goldens {
		validateSARIFFile(t, schema, golden)
	}
}

func TestRulesGoldenSchema(t *testing.T) {
	schema := compileSchema(t, "rules-v1.json")
	root := filepath.Join("..", "..")
	for _, format := range []string{"table", "json"} {
		path := filepath.Join(root, "testdata", "rules."+format+".golden")
		if format != "json" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s does not match schemas/rules-v1.json: %v", path, err)
		}
	}
}

func TestRegistryMatchesSARIFRules(t *testing.T) {
	r := diag.Report{}
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID               string `json:"id"`
						Name             string `json:"name"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						HelpURI              string `json:"helpUri"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	rules := log.Runs[0].Tool.Driver.Rules
	entries := diag.List()
	wantRules := 0
	for _, entry := range entries {
		if entry.Severity != "" {
			wantRules++
		}
	}
	if len(rules) != wantRules {
		t.Fatalf("SARIF rules=%d registry rules=%d", len(rules), wantRules)
	}
	ruleIndex := 0
	for _, entry := range entries {
		if entry.Severity == "" {
			continue
		}
		rule := rules[ruleIndex]
		ruleIndex++
		if rule.ID != entry.Code || rule.Name != strings.ToLower(strings.ReplaceAll(entry.Title, " ", "-")) || rule.ShortDescription.Text != entry.Title || rule.HelpURI != entry.DocURL() {
			t.Errorf("registry/SARIF mismatch at %s: %#v", entry.Code, rule)
		}
		wantLevel := map[diag.Severity]string{diag.SeverityHigh: "error", diag.SeverityMedium: "warning", diag.SeverityLow: "note"}[entry.Severity]
		if rule.DefaultConfiguration.Level != wantLevel {
			t.Errorf("%s level=%q want=%q", entry.Code, rule.DefaultConfiguration.Level, wantLevel)
		}
	}
	for _, result := range log.Runs[0].Results {
		found := false
		for _, rule := range rules {
			if rule.ID == result.RuleID {
				found = true
			}
		}
		if !found {
			t.Errorf("result rule %s missing from rules", result.RuleID)
		}
	}
}

func TestClusterAndDiagnosticsSARIF(t *testing.T) {
	r := diag.Report{
		Summary: diag.Summary{Complete: false, Ignored: 1},
		Findings: []diag.Finding{{
			RuleID: "DSD-IMG-002", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed,
			Impact: diag.ImpactHigh, Location: diag.Location{Path: "cluster/db/Pod/pg"},
			Reference: "docker.io/bitnami/redis:7", Fingerprint: "0123456789abcdef",
			Resource: &diag.Resource{Kind: "Pod", Name: "pg"},
		}},
		Diagnostics: []diag.Diagnostic{{Code: "DSD-SCN-001", Level: diag.LevelError, Message: "bad yaml", Location: diag.Location{Path: "values.yaml"}}},
	}
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool              `json:"executionSuccessful"`
				ExitCode            int               `json:"exitCode"`
				Notifications       []json.RawMessage `json:"toolExecutionNotifications"`
				Properties          struct {
					Ignored int `json:"ignored"`
				} `json:"properties"`
			} `json:"invocations"`
			Results []json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	inv := log.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || inv.ExitCode != 3 || inv.Properties.Ignored != 1 || len(inv.Notifications) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("unexpected invocation/results: %+v", log.Runs[0])
	}
	var result struct {
		Locations []struct {
			LogicalLocations []struct {
				FullyQualifiedName string `json:"fullyQualifiedName"`
				Kind               string `json:"kind"`
			} `json:"logicalLocations"`
			PhysicalLocation json.RawMessage `json:"physicalLocation"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(log.Runs[0].Results[0], &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Locations[0].LogicalLocations) != 1 || result.Locations[0].LogicalLocations[0].Kind != "Pod" || len(result.Locations[0].PhysicalLocation) != 0 {
		t.Fatalf("cluster result location: %+v", result)
	}
	if !bytes.Contains(inv.Notifications[0], []byte("DSD-SCN-001")) {
		t.Fatalf("diagnostic notification: %s", inv.Notifications[0])
	}
	for _, raw := range log.Runs[0].Results {
		var result struct {
			RuleID string `json:"ruleId"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(result.RuleID, "DSD-SCN-") {
			t.Fatalf("diagnostic %s landed in results", result.RuleID)
		}
	}
}

func TestSARIFRedactionAndDeterminism(t *testing.T) {
	r := diag.Report{
		Summary: diag.Summary{Complete: true},
		Findings: []diag.Finding{{
			RuleID: "DSD-IMG-003", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactLow,
			Location: diag.Location{Path: "values.yaml", Line: 1, Column: 1}, Reference: "bitnami/postgres:latest",
			Original: "user:pass@registry.example.com/bitnami/postgres:latest", Fingerprint: "fedcba9876543210",
		}},
		Diagnostics: []diag.Diagnostic{{Code: "DSD-SCN-007", Level: diag.LevelInfo, Message: "{{ secret body }}", Location: diag.Location{Path: "templates/deploy.yaml"}}},
	}
	var first bytes.Buffer
	if err := SARIF(&first, r); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(first.Bytes(), []byte("user:pass@")) || bytes.Contains(first.Bytes(), []byte("PLANTED-secret-token-123")) {
		t.Fatal("redaction violation")
	}
	for i := 1; i < 20; i++ {
		var next bytes.Buffer
		if err := SARIF(&next, r); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), next.Bytes()) {
			t.Fatalf("run %d differs", i)
		}
	}
}

func TestIgnoredFindingsAbsentFromSARIFResults(t *testing.T) {
	r := diag.Report{
		Summary:     diag.Summary{Ignored: 1, Complete: true},
		Findings:    nil,
		Diagnostics: []diag.Diagnostic{{Code: "DSD-SCN-006", Level: diag.LevelWarning, Message: "expired", Location: diag.Location{Path: ".disdetta.yaml"}}},
	}
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results     []json.RawMessage `json:"results"`
			Invocations []struct {
				Properties struct {
					Ignored int `json:"ignored"`
				} `json:"properties"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs[0].Results) != 0 || log.Runs[0].Invocations[0].Properties.Ignored != 1 {
		t.Fatalf("ignored count/results: %+v", log.Runs[0])
	}
}

// audit F5: the SARIF writer escapes the Unicode format characters that
// SafeText escapes in the table, so no raw bidi override survives in the
// machine-readable output. The escape is lossless: a JSON parser decodes it
// back to the original character.
func TestSARIFEscapesFormatCharacters(t *testing.T) {
	name := "web\u202etxt\u2066"
	r := diag.Report{
		Summary: diag.Summary{Complete: true},
		Findings: []diag.Finding{{
			RuleID: "DSD-IMG-002", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactHigh,
			Location:  diag.Location{Path: "cluster/db/Deployment/" + name},
			Reference: "docker.io/bitnami/redis:7",
			Resource:  &diag.Resource{Namespace: "db", Kind: "Deployment", Name: name, Container: "web"},
		}},
		Diagnostics: []diag.Diagnostic{{Code: "DSD-SCN-010", Level: diag.LevelWarning, Message: "hostile \u202e name"}},
	}
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if bytes.Contains(out, []byte("\u202e")) || bytes.Contains(out, []byte("\u2066")) {
		t.Fatalf("audit F5: raw format character in the SARIF: %s", out)
	}
	if !bytes.Contains(out, []byte(`\u202e`)) || !bytes.Contains(out, []byte(`\u2066`)) {
		t.Fatalf("audit F5: not escaped in the SARIF: %s", out)
	}
	var decoded struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
						Kind               string `json:"kind"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
			Invocations []struct {
				ToolExecutionNotifications []struct {
					Message struct {
						Text string `json:"text"`
					} `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	result := decoded.Runs[0].Results[0]
	if result.Locations[0].LogicalLocations[0].FullyQualifiedName != "cluster/db/Deployment/"+name {
		t.Errorf("audit F5: the SARIF does not decode back to the original path: %q", result.Locations[0].LogicalLocations[0].FullyQualifiedName)
	}
	if result.Locations[0].LogicalLocations[0].Kind != "Deployment" {
		t.Errorf("audit F5: the SARIF does not decode back to the original kind: %q", result.Locations[0].LogicalLocations[0].Kind)
	}
	if decoded.Runs[0].Invocations[0].ToolExecutionNotifications[0].Message.Text != "hostile \u202e name" {
		t.Errorf("audit F5: the SARIF does not decode back to the original diagnostic")
	}
}

func TestSARIFDoesNotLeakUnsafeFindingFields(t *testing.T) {
	secret := "PLANTED-secret-token-123"
	r := diag.Report{
		Summary: diag.Summary{Complete: true},
		Findings: []diag.Finding{{
			RuleID: "DSD-IMG-003", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactLow,
			Location:  diag.Location{Path: "values.yaml", Line: 1, Column: 1},
			Reference: "bitnami/postgres:latest", Original: "user:pass@registry.example.com/" + secret + ":{{ .Values.password }}",
			Fingerprint: "0011223344556677",
		}},
	}
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"user:pass@", secret, "registry.example.com"} {
		if bytes.Contains(b.Bytes(), []byte(forbidden)) {
			t.Fatalf("SARIF leaked %q", forbidden)
		}
	}
}
