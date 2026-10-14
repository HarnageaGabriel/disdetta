package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPlanCLI(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "plan", "postgresql")
	tests := []struct {
		name     string
		fixture  string
		want     int
		contains []string
	}{{"standalone", "standalone", 0, []string{"kind: Cluster", "mapped 5 of 5 user-set keys"}}, {"replication", "replication", 0, []string{"instances: 3", "mapped 4 of 4 user-set keys"}}, {"custom conf", "custom-conf", 4, []string{"listen_addresses", "managed by CloudNativePG", "pgaudit requires a standard", "mapped 6 of 7 user-set keys"}}, {"existing secret", "existing-secret", 4, []string{"auth.existingSecret", "auth.password"}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			got := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", filepath.Join(root, tt.fixture)}, IO{Out: &out, Err: &stderr})
			if got != tt.want {
				t.Fatalf("exit=%d want=%d stderr=%s", got, tt.want, stderr.String())
			}
			for _, s := range tt.contains {
				if !bytes.Contains(out.Bytes(), []byte(s)) {
					t.Errorf("missing %q in %s", s, out.String())
				}
			}
			if bytes.Contains(out.Bytes(), []byte("PLANTED-secret-token-123")) {
				t.Fatal("planted secret leaked")
			}
			golden, err := os.ReadFile(filepath.Join(root, tt.fixture, "plan.table.golden"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), golden) {
				t.Errorf("table output differs from golden")
			}
			var jsonOut, jsonErr bytes.Buffer
			jsonExit := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", filepath.Join(root, tt.fixture), "--format", "json"}, IO{Out: &jsonOut, Err: &jsonErr})
			if jsonExit != tt.want {
				t.Fatalf("json exit=%d stderr=%s", jsonExit, jsonErr.String())
			}
			jsonGolden, err := os.ReadFile(filepath.Join(root, tt.fixture, "plan.json.golden"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(jsonOut.Bytes(), jsonGolden) {
				t.Errorf("JSON output differs from golden")
			}
		})
	}
}

func TestPlanOutFiles(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "plan", "postgresql", "custom-conf")
	outDir := t.TempDir()
	var out, stderr bytes.Buffer
	if got := Execute(context.Background(), []string{"plan", "--release", "pg", "--from-repo", root, "--out", outDir, "--format", "json"}, IO{Out: &out, Err: &stderr}); got != 4 {
		t.Fatalf("exit=%d stderr=%s", got, stderr.String())
	}
	for _, name := range []string{"target.yaml", "unmapped", "checklist.md", "plan.json"} {
		b, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if bytes.Contains(b, []byte("PLANTED-secret-token-123")) {
			t.Errorf("secret leaked in %s", name)
		}
	}
}

func TestPlanUsage(t *testing.T) {
	tests := [][]string{{"plan", "--release", "pg", "--from-cluster"}, {"plan", "--release", "pg"}, {"plan", "--release", "pg", "--from-repo", ".", "--from-cluster", "--read-helm-secrets"}, {"plan", "--release", "pg", "--from-repo", ".", "--format", "xml"}}
	for _, args := range tests {
		var out, stderr bytes.Buffer
		if got := Execute(context.Background(), args, IO{Out: &out, Err: &stderr}); got != 2 {
			t.Errorf("args=%v exit=%d stderr=%s", args, got, stderr.String())
		}
	}
}
