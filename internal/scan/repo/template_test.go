package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Source: docs/spec/v0.1.md sections 3 and 9.1: a chart whose only diagnostics
// are DSD-SCN-007 stays complete, so the scan never exits 3 for template text.
func TestTemplateChartStaysComplete(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("Chart.yaml", "apiVersion: v2\nname: plain\nversion: 0.1.0\n")
	write("templates/deployment.yaml", "metadata:\n  name: {{ .Chart.Name }}\n")

	got, err := ScanWithOptions(context.Background(), root, Options{Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Summary.Complete || got.Summary.FilesScanned != 2 || len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.1: %#v", got.Summary)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-007" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got.Diagnostics)
	}
}
