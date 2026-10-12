package cli

import (
	"bytes"
	"context"
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
