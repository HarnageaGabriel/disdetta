package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

func TestTableEscapesEveryCell(t *testing.T) {
	t.Parallel()
	result := diag.Report{Findings: []diag.Diagnostic{{
		Code: "DSD-003\nforged", Severity: diag.SeverityBitnami, Reference: "docker.io/bitnami/redis:\x1b[2J", Path: "bad\tpath.yaml", Line: 1,
	}}}
	var output bytes.Buffer
	if err := Table(&output, result); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if strings.ContainsRune(got, '\x1b') || strings.Contains(got, "DSD-003\nforged") || !strings.Contains(got, `DSD-003\nforged`) || !strings.Contains(got, `bad\tpath.yaml`) {
		t.Fatalf("source review finding 2: unsafe table output %q", got)
	}
}

func TestJSONHasSeparateDiagnostics(t *testing.T) {
	t.Parallel()
	result := diag.Report{Diagnostics: []diag.ScanDiagnostic{{Code: "DSD-006", Message: "malformed YAML", Path: "bad.yaml"}}}
	var output bytes.Buffer
	if err := JSON(&output, result); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	if !strings.Contains(got, `"findings": []`) || !strings.Contains(got, `"diagnostics": [`) {
		t.Fatalf("source review finding 3: incomplete JSON envelope %s", got)
	}
}
