package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestExcludeFlag(t *testing.T) {
	chart := filepath.Join("..", "..", "testdata", "repos", "helm-template")
	var out, err bytes.Buffer
	if got := Execute(context.Background(), []string{"scan", chart, "--exclude", "templates/**"}, IO{Out: &out, Err: &err}); got != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 7: exit=%d stderr=%s", got, err.String())
	}
}

// A chart whose only diagnostics are DSD-SCN-007 must never be incomplete.
func TestTemplateChartNeverIncomplete(t *testing.T) {
	chart := filepath.Join("..", "..", "testdata", "repos", "helm-template")
	var out, err bytes.Buffer
	got := Execute(context.Background(), []string{"scan", chart, "--fail-on", "none"}, IO{Out: &out, Err: &err})
	if got == ExitIncomplete {
		t.Fatalf("source docs/spec/v0.1.md section 9.1: exit=%d output=%s", got, out.String())
	}
	if got != ExitOK {
		t.Fatalf("source docs/spec/v0.1.md section 9.1: exit=%d stderr=%s", got, err.String())
	}
}
