package repo_test

import (
	"bytes"
	"context"
	"flag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

func TestGoldenReports(t *testing.T) {
	for _, name := range []string{"helm", "flux", "argocd", "kustomize", "compose", "gitlab", "azure", "actions", "dockerfile", "nested-values", "helm-template", "chart-vendored", "corpus-fallback"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "..", "testdata", "repos", name)
			got, err := repo.Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			renders := map[string]func(*bytes.Buffer) error{"table": func(b *bytes.Buffer) error { return report.Table(b, got) }, "json": func(b *bytes.Buffer) error { return report.JSON(b, got) }}
			for _, format := range []string{"table", "json"} {
				var b bytes.Buffer
				if err := renders[format](&b); err != nil {
					t.Fatal(err)
				}
				golden := filepath.Join(root, "scan."+format+".golden")
				if *update {
					if err := os.WriteFile(golden, b.Bytes(), 0644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(b.Bytes(), want) {
					t.Errorf("source docs/spec/v0.1.md section 8: %s golden differs", format)
				}
			}
		})
	}
}
func TestFingerprintStabilityAndOccurrence(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "values.yaml")
	scan := func(data string) []string {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := repo.Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(r.Findings))
		for i, f := range r.Findings {
			out[i] = f.Fingerprint
		}
		return out
	}
	a := scan("image: bitnami/redis:7\ncopy:\n  image: bitnami/redis:7\n")
	b := scan("unrelated: true\nimage: bitnami/redis:7\ncopy:\n  image: bitnami/redis:7\n")
	if a[0] != b[0] || a[1] != b[1] || a[0] == a[1] {
		t.Fatalf("source docs/spec/v0.1.md section 5: before=%v after=%v", a, b)
	}
}
func TestSkippedAndMalformed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bad.yaml"), []byte("image: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "large.yaml"), make([]byte, repo.MaxFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	// review 02 F17: the oversize file is an error (DSD-SCN-008) and still a
	// skip; the malformed file stays a DSD-SCN-001 error.
	if len(r.Diagnostics) != 2 || r.Summary.FilesSkipped != 1 || r.Summary.Complete {
		t.Fatalf("source docs/spec/v0.1.md sections 3,8: %#v", r)
	}
	codes := map[string]bool{}
	for _, d := range r.Diagnostics {
		codes[d.Code] = true
	}
	if !codes["DSD-SCN-001"] || !codes["DSD-SCN-008"] {
		t.Fatalf("review 02 F17: %#v", r.Diagnostics)
	}
}
