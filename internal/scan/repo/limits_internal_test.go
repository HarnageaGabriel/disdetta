package repo

import (
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// The repository finding limit bounds the report of a hostile repository: the
// first findings are kept, in the contract order, and the limit is reported
// once as DSD-SCN-005 (docs/spec/v0.1.md section 3).
func TestRepositoryFindingLimit(t *testing.T) {
	r := diag.Report{Findings: make([]diag.Finding, MaxFindingsPerRepository+3)}
	for i := range r.Findings {
		r.Findings[i] = diag.Finding{
			RuleID:    "DSD-IMG-002",
			Severity:  diag.SeverityHigh,
			Impact:    diag.ImpactHigh,
			Location:  diag.Location{Path: "values.yaml", Line: i + 1},
			Reference: "docker.io/bitnami/redis:7",
			Original:  "bitnami/redis:7",
		}
	}
	finalize(&r, "root")
	if len(r.Findings) != MaxFindingsPerRepository {
		t.Fatalf("source docs/spec/v0.1.md section 3: got %d findings, want %d", len(r.Findings), MaxFindingsPerRepository)
	}
	if r.Findings[0].Location.Line != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 3: the first finding is at line %d, want line 1", r.Findings[0].Location.Line)
	}
	limits := 0
	for _, d := range r.Diagnostics {
		if d.Code != "DSD-SCN-005" {
			continue
		}
		limits++
		if d.Level != diag.LevelWarning {
			t.Fatalf("source docs/spec/v0.1.md section 3: the limit diagnostic is %+v, want a warning", d)
		}
		if d.Message != "finding limit reached: 100000 findings per repository" {
			t.Fatalf("source docs/spec/v0.1.md section 3: the limit diagnostic is %+v, want the limit in its message", d)
		}
	}
	if limits != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got %d limit diagnostics, want exactly one: %+v", limits, r.Diagnostics)
	}
}
