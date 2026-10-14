package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodeMatrix(t *testing.T) {
	finding := write(t, "image: bitnami/redis:7\n")
	malformed := write(t, "image: [\n")
	tests := []struct {
		name string
		args []string
		want int
	}{{"default", []string{"scan", finding}, 1}, {"above threshold", []string{"scan", finding, "--fail-on", "high"}, 1}, {"none", []string{"scan", finding, "--fail-on", "none"}, 0}, {"incomplete", []string{"scan", malformed}, 3}, {"usage", []string{"scan", "--fail-on", "bad"}, 2}, {"missing", []string{"scan", filepath.Join(t.TempDir(), "missing")}, 2}, {"cluster with path", []string{"scan", ".", "--cluster"}, 2}, {"cluster missing kubeconfig", []string{"scan", "--cluster", "--kubeconfig", filepath.Join(t.TempDir(), "missing")}, 2}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, err bytes.Buffer
			if got := Execute(context.Background(), tt.args, IO{Out: &out, Err: &err}); got != tt.want {
				t.Fatalf("source docs/spec/v0.1.md section 7: got %d want %d stderr %s", got, tt.want, err.String())
			}
		})
	}
}
func TestRuleFilter(t *testing.T) {
	path := write(t, "image: bitnami/redis:7\nother:\n  image: bitnami/nginx:latest\n")
	var out, err bytes.Buffer
	got := Execute(context.Background(), []string{"scan", path, "--rule", "DSD-IMG-003"}, IO{Out: &out, Err: &err})
	if got != 1 || bytes.Contains(out.Bytes(), []byte("DSD-IMG-002")) {
		t.Fatalf("source docs/spec/v0.1.md section 7: exit=%d output=%s", got, out.String())
	}
}
func write(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
