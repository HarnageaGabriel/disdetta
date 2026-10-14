package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

// review 04 #1 and review 04 #2: an alias-planted secret is absent from
// stdout, stderr, JSON, target, unmapped, and checklist output.
func TestReview04CLIPlantedSecretCorpus(t *testing.T) {
	root := t.TempDir()
	secret := "PLANTED-secret-token-123"
	release := fmt.Sprintf(`kind: HelmRelease
metadata: {name: pg}
spec:
  chart:
    spec: {chart: postgresql, version: 16.7.4}
  values:
    auth:
      password: &credential %s
    architecture: *credential
    primary:
      resources:
        requests: {cpu: 1}
        password: %s
      configuration: |
        app.password = '%s'
      pgHbaConfiguration: |
        host all all 0.0.0.0/0 ldap ldapbindpasswd=%s
`, secret, secret, secret, secret)
	if err := os.WriteFile(filepath.Join(root, "release.yaml"), []byte(release), 0600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")
	var stdout, stderr bytes.Buffer
	exit := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", root, "--out", outDir, "--format", "json"}, IO{Out: &stdout, Err: &stderr})
	if exit != ExitPlanIncomplete {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	outputs := map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes()}
	for _, name := range []string{"plan.json", "target.yaml", "unmapped", "checklist.md"} {
		data, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatal(err)
		}
		outputs[name] = data
	}
	for name, output := range outputs {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatalf("secret leaked in %s", name)
		}
	}
}

// review 04 #3: --from-repo reuses bounded regular-file reads plus YAML depth,
// alias-budget, and symlink guards.
func TestReview04RepoPlanInputGuards(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "large.yaml"), make([]byte, repo.MaxFileSize+1), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := repoPlanInput(root, "pg", nil); err == nil || !strings.Contains(err.Error(), "16 MiB") {
			t.Fatalf("size guard: %v", err)
		}
	})
	t.Run("alias budget", func(t *testing.T) {
		root := t.TempDir()
		var yaml strings.Builder
		yaml.WriteString("base: &base {x: y}\nitems:\n")
		for i := 0; i < 10001; i++ {
			yaml.WriteString("  - *base\n")
		}
		if err := os.WriteFile(filepath.Join(root, "aliases.yaml"), []byte(yaml.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := repoPlanInput(root, "pg", nil); err == nil || !strings.Contains(err.Error(), "invalid or unsafe YAML") {
			t.Fatalf("alias guard: %v", err)
		}
	})
	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		var yaml strings.Builder
		for i := 0; i < 260; i++ {
			yaml.WriteString(strings.Repeat("  ", i) + "level:\n")
		}
		yaml.WriteString(strings.Repeat("  ", 260) + "value: true\n")
		if err := os.WriteFile(filepath.Join(root, "deep.yaml"), []byte(yaml.String()), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := repoPlanInput(root, "pg", nil); err == nil || !strings.Contains(err.Error(), "invalid or unsafe YAML") {
			t.Fatalf("depth guard: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.yaml")
		if err := os.WriteFile(target, []byte("kind: HelmRelease\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "linked.yaml")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := repoPlanInput(root, "pg", nil); err == nil || !strings.Contains(err.Error(), "symbolic") {
			t.Fatalf("symlink guard: %v", err)
		}
	})
}

// review 04 #10: a matched release with no user values exits 4 after emitting
// the chart-default checklist item.
func TestReview04EmptyValuesExitFour(t *testing.T) {
	root := t.TempDir()
	release := []byte("kind: HelmRelease\nmetadata: {name: pg}\nspec:\n  chart:\n    spec: {chart: postgresql, version: 16.7.4}\n  values: {}\n")
	if err := os.WriteFile(filepath.Join(root, "release.yaml"), release, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if exit := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", root}, IO{Out: &stdout, Err: &stderr}); exit != ExitPlanIncomplete {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "no user values found; review the chart defaults") {
		t.Fatalf("output=%s", stdout.String())
	}
}
