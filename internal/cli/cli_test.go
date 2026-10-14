package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanExitCodes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, source string
		args         []string
		want         int
	}{
		{"findings", "docs/diagnostics/README.md", []string{"scan", filepath.Join("..", "..", "testdata", "repos", "helm")}, ExitFindings},
		{"diagnostics", "review finding 3", []string{"scan", writeMalformedYAML(t)}, ExitFindings},
		{"usage", "docs/diagnostics/README.md", []string{"scan", "--format", "xml"}, ExitError},
		{"version", "M0 CLI milestone", []string{"version"}, ExitOK},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := Execute(context.Background(), tt.args, IO{Out: &stdout, Err: &stderr}); got != tt.want {
				t.Errorf("source %s: got exit %d, want %d; stderr=%s", tt.source, got, tt.want, stderr.String())
			}
		})
	}
}

func writeMalformedYAML(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("image: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
