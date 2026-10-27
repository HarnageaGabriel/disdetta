package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
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

// audit F3: --deny-exec-plugins refuses a kubeconfig whose user runs a
// credential plugin, with a usage error (exit code 2) before the plugin runs.
func TestClusterDenyExecPlugins(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	content := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:1/
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: "disdetta-marker"
      interactiveMode: Never
`
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, err bytes.Buffer
	code := Execute(context.Background(), []string{"scan", "--cluster", "--kubeconfig", kubeconfig, "--deny-exec-plugins"}, IO{Out: &out, Err: &err})
	if code != ExitError {
		t.Fatalf("audit F3: got %d want %d stderr %s", code, ExitError, err.String())
	}
	if !strings.Contains(err.String(), "exec credential plugin") {
		t.Errorf("audit F3: unclear message: %s", err.String())
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

func TestSARIFAndRulesCLI(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "repos", "helm")
	var sarif, sarifErr bytes.Buffer
	exit := Execute(context.Background(), []string{"scan", fixture, "--format", "sarif", "--fail-on", "none"}, IO{Out: &sarif, Err: &sarifErr})
	if exit != ExitOK || !bytes.HasPrefix(sarif.Bytes(), []byte("{\n  \"version\": \"2.1.0\"")) {
		t.Fatalf("sarif exit=%d stderr=%s output=%s", exit, sarifErr.String(), sarif.String())
	}
	golden, err := os.ReadFile(filepath.Join(fixture, "scan.sarif.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sarif.Bytes(), golden) {
		n := len(sarif.Bytes())
		if len(golden) < n {
			n = len(golden)
		}
		for i := 0; i < n; i++ {
			if sarif.Bytes()[i] != golden[i] {
				t.Fatalf("SARIF differs at %d: got %q want %q lens %d/%d", i, sarif.Bytes()[i], golden[i], len(sarif.Bytes()), len(golden))
			}
		}
		t.Fatalf("SARIF differs lens %d/%d", len(sarif.Bytes()), len(golden))
	}

	var table, jsonOut, ruleErr bytes.Buffer
	if exit := Execute(context.Background(), []string{"rules"}, IO{Out: &table, Err: &ruleErr}); exit != ExitOK {
		t.Fatalf("rules table exit=%d stderr=%s", exit, ruleErr.String())
	}
	wantTable, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rules.table.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(table.Bytes(), wantTable) {
		t.Fatal("rules table differs from golden")
	}
	if exit := Execute(context.Background(), []string{"rules", "--format", "json"}, IO{Out: &jsonOut, Err: &ruleErr}); exit != ExitOK {
		t.Fatalf("rules json exit=%d stderr=%s", exit, ruleErr.String())
	}
	wantJSON, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rules.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(jsonOut.Bytes(), wantJSON) {
		t.Fatal("rules JSON differs from golden")
	}
	for _, code := range []string{"DSD-CFG-001", "DSD-IMG-001", "DSD-IMG-002", "DSD-IMG-003", "DSD-IMG-004", "DSD-CHT-001", "DSD-CHT-002", "DSD-SCN-001", "DSD-SCN-010"} {
		if !bytes.Contains(table.Bytes(), []byte(code)) {
			t.Errorf("rules table missing %s", code)
		}
	}
}

func TestPlanRejectsSARIF(t *testing.T) {
	var out, stderr bytes.Buffer
	exit := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", ".", "--format", "sarif"}, IO{Out: &out, Err: &stderr})
	if exit != ExitError || !strings.Contains(stderr.String(), "want table or json") {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
}
