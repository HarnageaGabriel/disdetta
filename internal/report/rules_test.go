package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type rulesJSONEntry struct {
	Code     string `json:"code"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Level    string `json:"level"`
	Title    string `json:"title"`
	OneLiner string `json:"oneLiner"`
	Docs     string `json:"docs"`
}

type rulesJSONPayload struct {
	SchemaVersion string           `json:"schemaVersion"`
	Rules         []rulesJSONEntry `json:"rules"`
}

func registryEntry(t *testing.T, code string) diag.Entry {
	t.Helper()
	for _, entry := range diag.List() {
		if entry.Code == code {
			return entry
		}
	}
	t.Fatalf("registry entry %s not found", code)
	return diag.Entry{}
}

func validateRulesTable(t *testing.T, output []byte) {
	t.Helper()
	entries := diag.List()
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != len(entries)+1 {
		t.Fatalf("table lines=%d want=%d", len(lines), len(entries)+1)
	}
	for i, entry := range entries {
		columns := strings.Fields(lines[i+1])
		if len(columns) == 0 || columns[0] != entry.Code {
			t.Fatalf("row %d=%q want code %s", i, lines[i+1], entry.Code)
		}
	}
	ruleRow := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.TrimSpace(line), "DSD-IMG-003") {
			ruleRow = line
			break
		}
	}
	if ruleRow == "" || !strings.Contains(ruleRow, "medium") || !strings.Contains(ruleRow, "-") {
		t.Fatalf("rule row lacks severity/diagnostic placeholder: %q", ruleRow)
	}
	diagnosticRow := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.TrimSpace(line), "DSD-SCN-001") {
			diagnosticRow = line
			break
		}
	}
	if diagnosticRow == "" || !strings.Contains(diagnosticRow, "error") || !strings.Contains(diagnosticRow, "-") {
		t.Fatalf("diagnostic row lacks level/severity placeholder: %q", diagnosticRow)
	}
}

func validateRulesJSON(t *testing.T, output []byte) {
	t.Helper()
	var payload rulesJSONPayload
	if err := json.Unmarshal(output, &payload); err != nil {
		t.Fatalf("decode rules JSON: %v", err)
	}
	entries := diag.List()
	if payload.SchemaVersion != "1" || len(payload.Rules) != len(entries) {
		t.Fatalf("schemaVersion=%q rules=%d want schemaVersion=1 rules=%d", payload.SchemaVersion, len(payload.Rules), len(entries))
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(output))
	if err != nil {
		t.Fatalf("prepare rules JSON for schema: %v", err)
	}
	if err := compileSchema(t, "rules-v1.json").Validate(doc); err != nil {
		t.Fatalf("rules JSON schema: %v", err)
	}

	byCode := make(map[string]rulesJSONEntry, len(payload.Rules))
	for _, rule := range payload.Rules {
		byCode[rule.Code] = rule
	}
	for _, code := range []string{"DSD-IMG-003", "DSD-SCN-001"} {
		entry := registryEntry(t, code)
		got, ok := byCode[code]
		if !ok {
			t.Fatalf("%s missing from rules JSON", code)
		}
		if got.Kind != entry.Kind() || got.Severity != string(entry.Severity) || got.Level != string(entry.Level) || got.Title != entry.Title || got.OneLiner != entry.OneLiner || got.Docs != entry.DocURL() {
			t.Errorf("%s=%+v want kind=%q severity=%q level=%q title=%q oneLiner=%q docs=%q", code, got, entry.Kind(), entry.Severity, entry.Level, entry.Title, entry.OneLiner, entry.DocURL())
		}
	}
}

// Source: docs/spec/v0.4-sarif-rules.md section 2.
func TestRulesRenderersMatchGoldensAndRegistry(t *testing.T) {
	tests := []struct {
		name   string
		format string
		render func(io.Writer) error
	}{
		{name: "table", format: "table", render: RulesTable},
		{name: "json", format: "json", render: RulesJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := test.render(&output); err != nil {
				t.Fatal(err)
			}
			golden, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rules."+test.format+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), golden) {
				t.Fatalf("%s output does not match testdata/rules.%s.golden", test.name, test.format)
			}
			if test.format == "table" {
				validateRulesTable(t, output.Bytes())
			} else {
				validateRulesJSON(t, output.Bytes())
			}

			t.Run("writer error", func(t *testing.T) {
				err := test.render(failingWriter{})
				if err == nil || !strings.Contains(err.Error(), "boom") {
					t.Fatalf("write error=%v want underlying boom error", err)
				}
			})
		})
	}
}

// Source: docs/spec/v0.4-sarif-rules.md section 1.
func TestSARIFRejectsUnregisteredRule(t *testing.T) {
	tests := []struct {
		name   string
		ruleID string
	}{
		{name: "unknown code", ruleID: "DSD-UNREGISTERED-001"},
		{name: "empty code", ruleID: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			err := SARIF(&output, diag.Report{Findings: []diag.Finding{{RuleID: test.ruleID}}})
			if err == nil {
				t.Fatal("SARIF accepted an unregistered rule")
			}
			if want := `rule "` + test.ruleID + `" is not registered`; err.Error() != want {
				t.Fatalf("error=%q want=%q", err.Error(), want)
			}
		})
	}
}
