package report

import (
	"bytes"
	"encoding/json"
	"errors"
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

// review 02 F15: Unicode format characters (category Cf) must be escaped, not
// emitted raw, so they cannot forge a table row (spec section 6).
func TestTableEscapesFormatCharacters(t *testing.T) {
	r := diag.Report{Findings: []diag.Finding{{RuleID: "DSD-IMG-003", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactLow, Location: diag.Location{Path: "a\u202eb.yaml", Line: 1}, Reference: "bitnami/redis\u200b:7"}}}
	var b bytes.Buffer
	if err := Table(&b, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.ContainsRune(s, '\u202e') || strings.ContainsRune(s, '\u200b') {
		t.Fatalf("review 02 F15: raw format character in %q", s)
	}
	if !strings.Contains(s, "\\u202e") || !strings.Contains(s, "\\u200b") {
		t.Fatalf("review 02 F15: not escaped in %q", s)
	}
}

// audit F5: the JSON writer escapes the Unicode format characters that
// SafeText escapes in the table, so no raw bidi override or zero-width
// character survives in the machine-readable output. The escape is lossless: a
// JSON parser decodes it back to the original character.
func TestJSONEscapesFormatCharacters(t *testing.T) {
	name := "web\u202etxt\u2066"
	r := diag.Report{
		Summary: diag.Summary{Complete: true},
		Findings: []diag.Finding{{
			RuleID: "DSD-IMG-002", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactHigh,
			Location:  diag.Location{Path: "cluster/db/Deployment/" + name},
			Reference: "docker.io/bitnami/redis:7",
			Resource:  &diag.Resource{Namespace: "db", Kind: "Deployment", Name: name, Container: "web"},
		}},
		Diagnostics: []diag.Diagnostic{{Code: "DSD-SCN-010", Level: diag.LevelWarning, Message: "hostile \u202e name", Location: diag.Location{Path: "cluster/db/" + name}}},
	}
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	if bytes.Contains(out, []byte("\u202e")) || bytes.Contains(out, []byte("\u2066")) {
		t.Fatalf("audit F5: raw format character in the JSON: %s", out)
	}
	if !bytes.Contains(out, []byte(`\u202e`)) || !bytes.Contains(out, []byte(`\u2066`)) {
		t.Fatalf("audit F5: not escaped in the JSON: %s", out)
	}
	var decoded struct {
		Findings []struct {
			Location struct {
				Path string `json:"path"`
			} `json:"location"`
			Resource struct {
				Name string `json:"name"`
			} `json:"resource"`
		} `json:"findings"`
		Diagnostics []struct {
			Message  string `json:"message"`
			Location struct {
				Path string `json:"path"`
			} `json:"location"`
		} `json:"diagnostics"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Findings[0].Location.Path != "cluster/db/Deployment/"+name {
		t.Errorf("audit F5: the JSON does not decode back to the original path: %q", decoded.Findings[0].Location.Path)
	}
	if decoded.Findings[0].Resource.Name != name {
		t.Errorf("audit F5: the JSON does not decode back to the original name: %q", decoded.Findings[0].Resource.Name)
	}
	if decoded.Diagnostics[0].Message != "hostile \u202e name" || decoded.Diagnostics[0].Location.Path != "cluster/db/"+name {
		t.Errorf("audit F5: the JSON does not decode back to the original diagnostic: %#v", decoded.Diagnostics[0])
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// Renders diagnostics (warning and error only), location variants, and the
// writer error path (spec section 8).
func TestTableRendersDiagnosticsAndLocationVariants(t *testing.T) {
	r := diag.Report{
		Summary:  diag.Summary{Complete: false},
		Findings: []diag.Finding{{RuleID: "DSD-IMG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactHigh, Location: diag.Location{Path: "a.yaml", Line: 2}, Reference: "docker.io/bitnamilegacy/redis:7"}},
		Diagnostics: []diag.Diagnostic{
			{Code: "DSD-SCN-002", Level: diag.LevelWarning, Message: "symbolic link skipped", Location: diag.Location{Path: "b.yaml"}},
			{Code: "DSD-SCN-001", Level: diag.LevelError, Message: "malformed YAML", Location: diag.Location{Path: "c.yaml", Line: 4, Column: 2}},
			{Code: "DSD-SCN-003", Level: diag.LevelInfo, Message: "unresolved reference", Location: diag.Location{Path: "d.yaml"}},
			{Code: "DSD-SCN-008", Level: diag.LevelError, Message: "file exceeds 16 MiB limit; skipped", Location: diag.Location{Path: "e.yaml"}},
		},
	}
	var b bytes.Buffer
	if err := Table(&b, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "b.yaml") || !strings.Contains(s, "c.yaml:4:2") || !strings.Contains(s, "a.yaml:2") || !strings.Contains(s, "e.yaml") {
		t.Fatalf("source docs/spec/v0.1.md section 8: %q", s)
	}
	if strings.Contains(s, "d.yaml") {
		t.Fatalf("source docs/spec/v0.1.md section 8: info diagnostic rendered: %q", s)
	}
	if err := Table(failingWriter{}, r); err == nil {
		t.Fatal("source docs/spec/v0.1.md section 8: write error not returned")
	}
}

// review 02 F15: quotes, backslashes and invalid UTF-8 bytes are escaped
// so no cell can forge a row (spec section 6).
func TestSafeCellEscapesQuotesAndInvalidUTF8(t *testing.T) {
	r := diag.Report{Findings: []diag.Finding{{RuleID: "a\"b\\c", Severity: diag.SeverityLow, Confidence: diag.ConfidenceInferred, Impact: diag.ImpactUnknown, Location: diag.Location{Path: "p"}, Reference: "p\xffq"}}}
	var b bytes.Buffer
	if err := Table(&b, r); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if strings.Contains(s, "\xff") || !strings.Contains(s, `p\xffq`) {
		t.Fatalf("review 02 F15: invalid UTF-8 not escaped: %q", s)
	}
	if !strings.Contains(s, `a\"b\\c`) {
		t.Fatalf("review 02 F15: quotes not escaped: %q", s)
	}
}

func TestJSONWriteError(t *testing.T) {
	if err := JSON(failingWriter{}, diag.Report{}); err == nil {
		t.Fatal("source docs/spec/v0.1.md section 8: write error not returned")
	}
}
