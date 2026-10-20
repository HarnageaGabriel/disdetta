package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// dockerfileWithContinuations builds a Dockerfile whose first instruction
// chains n continuation lines, closed by a line without a backslash, followed
// by one more instruction.
//
// Source: docs/spec/v0.1.md section 3 (Dockerfile line continuations).
func dockerfileWithContinuations(n int) []byte {
	var b strings.Builder
	b.WriteString("FROM bitnami/redis:7 \\\n")
	for i := 0; i < n; i++ {
		b.WriteString("x \\\n")
	}
	b.WriteString("end\n")
	b.WriteString("FROM bitnami/x:1\n")
	return []byte(b.String())
}

// A chain below the limit is scanned as one logical instruction: the FROM
// image of the first line is still reported, and the scan stays fast.
func TestDockerfileContinuationChainUnderLimit(t *testing.T) {
	data := dockerfileWithContinuations(9000)
	done := make(chan diag.Report, 1)
	go func() { done <- Dockerfile("Dockerfile", data) }()
	var got diag.Report
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("source docs/spec/v0.1.md section 3: the Dockerfile scan did not finish in 30s")
	}
	if len(got.Diagnostics) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got diagnostics %#v, want none", got.Diagnostics)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got findings %#v, want two", got.Findings)
	}
	if got.Findings[0].Location.Line != 1 || got.Findings[0].Original != "bitnami/redis:7" {
		t.Fatalf("source docs/spec/v0.1.md section 3: got finding %#v, want bitnami/redis:7 on line 1", got.Findings[0])
	}
}

// A chain over the limit is not scanned: it is reported once as DSD-SCN-005 at
// the start line of the instruction, and the next instruction is still
// scanned.
func TestDockerfileContinuationChainOverLimit(t *testing.T) {
	data := dockerfileWithContinuations(20000)
	got := Dockerfile("Dockerfile", data)
	if len(got.Diagnostics) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got diagnostics %#v, want one DSD-SCN-005", got.Diagnostics)
	}
	d := got.Diagnostics[0]
	if d.Code != "DSD-SCN-005" || d.Level != diag.LevelWarning {
		t.Fatalf("source docs/spec/v0.1.md section 3: got diagnostic %#v, want a DSD-SCN-005 warning", d)
	}
	if d.Location.Line != 1 || d.Location.Column != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got DSD-SCN-005 at %d:%d, want 1:1", d.Location.Line, d.Location.Column)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got findings %#v, want only the instruction after the chain", got.Findings)
	}
	if got.Findings[0].Original != "bitnami/x:1" || got.Findings[0].Location.Line != 20003 {
		t.Fatalf("source docs/spec/v0.1.md section 3: got finding %#v, want bitnami/x:1 on line 20003", got.Findings[0])
	}
}

func BenchmarkDockerfileContinuationChain(b *testing.B) {
	data := dockerfileWithContinuations(5000)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if len(Dockerfile("Dockerfile", data).Findings) == 0 {
			b.Fatal("no findings")
		}
	}
}
