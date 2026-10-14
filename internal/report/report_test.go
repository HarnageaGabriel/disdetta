package report

import (
	"bytes"
	"encoding/json"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"strings"
	"testing"
)

func TestTableEscapesCellsAndSummarizes(t *testing.T) {
	r := diag.Report{Summary: diag.Summary{Complete: true}, Findings: []diag.Finding{{RuleID: "DSD-IMG-003\nforged", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactLow, Location: diag.Location{Path: "bad\tpath", Line: 1}, Reference: "x\x1b"}}}
	var b bytes.Buffer
	if err := Table(&b, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.ContainsRune(s, '\x1b') || strings.Contains(s, "forged\nmedium") || !strings.Contains(s, "scanned 0 files") {
		t.Fatalf("source docs/spec/v0.1.md sections 6,8: %q", s)
	}
}
func TestJSONEnvelope(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, diag.Report{Summary: diag.Summary{Complete: true}}); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schemaVersion", "tool", "summary", "findings", "diagnostics"} {
		if _, ok := v[key]; !ok {
			t.Errorf("source docs/spec/v0.1.md section 8: missing %s", key)
		}
	}
}
