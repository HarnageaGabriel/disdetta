package detect

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// A file with many YAML documents is scanned in one pass over its findings:
// the cost of the scan is linear in the number of documents, never quadratic
// (docs/spec/v0.1.md section 9). The timeout keeps the test honest on a slow
// runner: the old quadratic scan needed more than a minute for this input.
func TestManyDocumentsAreScannedInLinearTime(t *testing.T) {
	const documents = 50000
	var data strings.Builder
	for i := 0; i < documents; i++ {
		data.WriteString("---\nx: bitnami/postgresql:14.1.0\n")
	}
	type outcome struct {
		findings int
	}
	done := make(chan outcome, 1)
	go func() {
		got := YAML("values.yaml", []byte(data.String()))
		done <- outcome{findings: len(got.Findings)}
	}()
	select {
	case got := <-done:
		if got.findings != MaxFindingsPerFile {
			t.Fatalf("source docs/spec/v0.1.md section 3: got %d findings, want the limit %d", got.findings, MaxFindingsPerFile)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("source docs/spec/v0.1.md section 9: the scan of 50000 documents did not finish in 30 seconds")
	}
}

// A file with more findings than the per-file limit keeps the first findings,
// in the order they were found, and reports the limit once
// (docs/spec/v0.1.md section 3). The hostile file is either many documents or
// one document with many image lines.
func TestFindingLimitPerFile(t *testing.T) {
	tests := []struct {
		name      string
		input     func(images int) string
		firstLine int
	}{
		{
			name: "many documents",
			input: func(images int) string {
				var data strings.Builder
				for i := 0; i < images; i++ {
					data.WriteString("---\nimage: bitnami/postgresql:14.1.0\n")
				}
				return data.String()
			},
			firstLine: 2,
		},
		{
			name: "one document",
			input: func(images int) string {
				var data strings.Builder
				for i := 0; i < images; i++ {
					fmt.Fprintf(&data, "key%d: bitnami/postgresql:14.1.0\n", i)
				}
				return data.String()
			},
			firstLine: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("values.yaml", []byte(tt.input(12000)))
			if len(got.Findings) != MaxFindingsPerFile {
				t.Fatalf("source docs/spec/v0.1.md section 3: got %d findings, want %d", len(got.Findings), MaxFindingsPerFile)
			}
			if got.Findings[0].Location.Line != tt.firstLine || got.Findings[0].Original != "bitnami/postgresql:14.1.0" {
				t.Fatalf("source docs/spec/v0.1.md section 3: the first finding is %+v, want the first image line", got.Findings[0])
			}
			limits := 0
			for _, d := range got.Diagnostics {
				if d.Code != "DSD-SCN-005" {
					continue
				}
				limits++
				if d.Level != diag.LevelWarning {
					t.Fatalf("source docs/spec/v0.1.md section 3: the limit diagnostic is %+v, want a warning", d)
				}
				if d.Message != "finding limit reached: 10000 findings per file" {
					t.Fatalf("source docs/spec/v0.1.md section 3: the limit diagnostic is %+v, want the limit in its message", d)
				}
			}
			if limits != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 3: got %d limit diagnostics, want exactly one: %+v", limits, got.Diagnostics)
			}
		})
	}
}

// A file under the limit is unchanged: every finding is reported and no limit
// diagnostic is emitted (docs/spec/v0.1.md section 3).
func TestFindingLimitNotReached(t *testing.T) {
	got := YAML("values.yaml", []byte("image: bitnami/postgresql:14.1.0\n"))
	want := []diag.Finding{{
		RuleID:     "DSD-IMG-002",
		Severity:   diag.SeverityHigh,
		Confidence: diag.ConfidenceConfirmed,
		Impact:     diag.ImpactHigh,
		Component:  "postgresql",
		Location:   diag.Location{Path: "values.yaml", Line: 1, Column: 8},
		Reference:  "docker.io/bitnami/postgresql:14.1.0",
		Original:   "bitnami/postgresql:14.1.0",
		Attributes: []string{"pull-risk"},
	}}
	if !reflect.DeepEqual(got.Findings, want) {
		t.Fatalf("source docs/spec/v0.1.md section 3: got %#v, want %#v", got.Findings, want)
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got diagnostics %#v, want none", got.Diagnostics)
	}
}

// The documents of a file are scanned together: the whole-scalar fallback and
// the deduplication run once per file, so the findings of the documents keep
// the order they were found in (docs/spec/v0.1.md sections 5 and 9).
func TestDocumentsOfAFileKeepTheirOrder(t *testing.T) {
	input := "---\nimage: bitnami/postgresql:14.1.0\n---\nx: bitnami/redis:7\n---\nimage: bitnami/nginx:1\n"
	got := YAML("values.yaml", []byte(input))
	want := []struct {
		rule       string
		line       int
		confidence diag.Confidence
	}{
		{"DSD-IMG-002", 2, diag.ConfidenceConfirmed},
		{"DSD-IMG-002", 4, diag.ConfidenceInferred},
		{"DSD-IMG-002", 6, diag.ConfidenceConfirmed},
	}
	if len(got.Findings) != len(want) {
		t.Fatalf("source docs/spec/v0.1.md section 9: got %d findings, want %d: %#v", len(got.Findings), len(want), got.Findings)
	}
	for i, w := range want {
		f := got.Findings[i]
		if f.RuleID != w.rule || f.Location.Line != w.line || f.Confidence != w.confidence {
			t.Fatalf("source docs/spec/v0.1.md section 9: finding %d is %+v, want %s at line %d with confidence %s", i, f, w.rule, w.line, w.confidence)
		}
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9: got diagnostics %#v, want none", got.Diagnostics)
	}
}

// The values file of a chart is scanned with the same limits as any other
// file: the findings of the documents of the file are deduplicated together
// (docs/spec/v0.1.md sections 3 and 5).
func TestHelmValuesKeepsTheOrderOfTheDocuments(t *testing.T) {
	input := "---\nimage: bitnami/postgresql:14.1.0\n---\nx: bitnami/redis:7\n---\nimage: bitnami/nginx:1\n"
	got := HelmValues("values.yaml", []byte(input))
	if len(got.Findings) != 3 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: got %d findings, want 3: %#v", len(got.Findings), got.Findings)
	}
	for i, line := range []int{2, 4, 6} {
		if got.Findings[i].Location.Line != line {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: finding %d is at line %d, want line %d", i, got.Findings[i].Location.Line, line)
		}
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: got diagnostics %#v, want none", got.Diagnostics)
	}
}
