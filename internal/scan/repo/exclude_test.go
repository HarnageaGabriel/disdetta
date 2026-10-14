package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Source: docs/spec/v0.1.md section 7 (--exclude glob, ** supported).
func TestExcludeGlob(t *testing.T) {
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
	write("values.yaml", "image: bitnami/redis:7\n")
	write("charts/app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 0.1.0\n")
	write("charts/app/templates/job.yaml", "image: bitnami/kubectl:latest\n")

	base, err := ScanWithOptions(context.Background(), root, Options{Clock: time.Now})
	if err != nil || base.Summary.FilesScanned != 3 || len(base.Findings) != 2 {
		t.Fatalf("baseline %#v %v", base.Summary, err)
	}

	one, err := ScanWithOptions(context.Background(), root, Options{Clock: time.Now, Exclude: []string{"charts/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if one.Summary.FilesScanned != 1 || one.Summary.FilesSkipped != 0 || len(one.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 7: %#v", one.Summary)
	}

	doubled, err := ScanWithOptions(context.Background(), root, Options{Clock: time.Now, Exclude: []string{"**/templates/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if doubled.Summary.FilesScanned != 2 || len(doubled.Findings) != 1 || doubled.Findings[0].RuleID != "DSD-IMG-002" {
		t.Fatalf("source docs/spec/v0.1.md section 7: %#v", doubled.Summary)
	}

	kept, err := ScanWithOptions(context.Background(), root, Options{Clock: time.Now, Exclude: []string{"nomatch/**"}})
	if err != nil {
		t.Fatal(err)
	}
	if kept.Summary.FilesScanned != 3 || len(kept.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 7: %#v", kept.Summary)
	}
}
