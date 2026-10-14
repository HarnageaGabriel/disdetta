package repo_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

var update = flag.Bool("update", false, "update golden files")

func TestGoldenReports(t *testing.T) {
	tests := []struct {
		name, source string
	}{
		{"helm", "docs/PLAN.md M1 fixtures"},
		{"flux", "RESEARCH-NOTES section 4"},
		{"argocd", "RESEARCH-NOTES section 4"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join("..", "..", "..", "testdata", "repos", tt.name)
			result, err := repo.Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			renderers := map[string]func(*bytes.Buffer) error{
				"table": func(buffer *bytes.Buffer) error { return report.Table(buffer, result) },
				"json":  func(buffer *bytes.Buffer) error { return report.JSON(buffer, result) },
			}
			for _, format := range []string{"table", "json"} {
				var got bytes.Buffer
				if err := renderers[format](&got); err != nil {
					t.Fatal(err)
				}
				golden := filepath.Join(root, "scan."+format+".golden")
				if *update {
					if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Errorf("source %s: %s golden differs; run go test ./internal/scan/repo -update", tt.source, format)
				}
			}
		})
	}
}

func TestSkipsDependencyDirectories(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, dir := range []string{".git", "node_modules", "vendor"} {
		path := filepath.Join(root, dir)
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "values.yaml"), []byte("image: bitnami/redis\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || len(got.Diagnostics) != 0 {
		t.Fatalf("got unexpected report from skipped directories: %#v", got)
	}
}

func TestAdversarialFilesContinue(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("image: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "good.yaml"), []byte("image: bitnami/redis:7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "large.yaml"), make([]byte, 5*1024*1024+1), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 || len(got.Diagnostics) != 2 {
		t.Fatalf("source review findings 3 and 8: got %d findings/%d diagnostics", len(got.Findings), len(got.Diagnostics))
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(outside, []byte("image: bitnami/redis:7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "values.yaml")); err != nil {
		t.Skipf("source review finding 1: symlink unavailable: %v", err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Path != "values.yaml" {
		t.Fatalf("source review finding 1: got %#v", got)
	}
}
