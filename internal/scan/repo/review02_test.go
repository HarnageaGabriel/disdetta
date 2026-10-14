package repo_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

func renderJSON(t *testing.T, r diag.Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := report.JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// review 02 F3: fingerprints and occurrence numbering must not depend on Go map
// iteration order (spec sections 4, 5, 10).
func TestComposeFingerprintsAreDeterministic(t *testing.T) {
	root := t.TempDir()
	compose := "services:\n  a:\n    image: bitnami/redis:7\n  b:\n    image: bitnami/redis:7\n"
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	first := ""
	for i := 0; i < 20; i++ {
		got, err := repo.Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Findings) != 2 {
			t.Fatalf("review 02 F3: %#v", got.Findings)
		}
		out := renderJSON(t, got)
		if i == 0 {
			first = out
			continue
		}
		if out != first {
			t.Fatalf("review 02 F3: run %d differs:\n%s\n%s", i, first, out)
		}
	}
}

// Every checked-in fixture renders byte-identical JSON across 20 in-process
// scans (spec section 10 acceptance).
func TestFixtureReportsAreDeterministic(t *testing.T) {
	for _, name := range []string{"helm", "flux", "argocd", "kustomize", "compose", "gitlab", "azure", "actions", "dockerfile", "nested-values", "helm-template", "chart-vendored", "corpus-fallback"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "..", "testdata", "repos", name)
			first := ""
			for i := 0; i < 20; i++ {
				got, err := repo.Scan(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				out := renderJSON(t, got)
				if i == 0 {
					first = out
					continue
				}
				if out != first {
					t.Fatalf("run %d differs", i)
				}
			}
		})
	}
}

// review 02 F7: every skip counts in summary.filesSkipped, including a
// symbolic-link root (spec sections 3, 8).
func TestEverySkipCountsInSummary(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "values.yaml")
	if err := os.WriteFile(target, []byte("image: bitnami/redis:7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("review 02 F7: symlinks unavailable: %v", err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.FilesSkipped != 1 || len(got.Findings) != 1 {
		t.Fatalf("review 02 F7: %#v", got.Summary)
	}
	rootReport, err := repo.Scan(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if rootReport.Summary.FilesSkipped != 1 || len(rootReport.Diagnostics) != 1 || rootReport.Diagnostics[0].Code != "DSD-SCN-002" {
		t.Fatalf("review 02 F7: %#v", rootReport)
	}
}

// review 02 F11: summary.unresolved counts DSD-SCN-003 diagnostics only, not
// findings whose confidence is unresolved (spec section 2.2).
func TestUnresolvedCountsDiagnosticsOnly(t *testing.T) {
	root := t.TempDir()
	values := "tagged:\n  image: 'bitnami/redis:{{ .Values.tag }}'\n" +
		"first:\n  image: '{{ .Values.a }}'\n" +
		"second:\n  image: '{{ .Values.b }}'\n"
	if err := os.WriteFile(filepath.Join(root, "values.yaml"), []byte(values), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.Unresolved != 2 {
		t.Fatalf("review 02 F11: unresolved=%d %#v", got.Summary.Unresolved, got.Summary)
	}
	if len(got.Findings) != 1 || got.Findings[0].Confidence != diag.ConfidenceUnresolved {
		t.Fatalf("review 02 F11: %#v", got.Findings)
	}
}

// review 02 F14: a config file outside the scan root is reported by base name
// only, never as an absolute host path (spec section 6).
func TestConfigPathOutsideRootIsBaseNameOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "values.yaml"), []byte("image: bitnami/redis:7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "ignores.yaml")
	body := "ignores:\n- rule: DSD-IMG-002\n  path: values.yaml\n  reason: temporary\n  expires: 2000-01-01\n"
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := repo.ScanWithOptions(context.Background(), root, repo.Options{ConfigPath: cfg, Clock: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got.Diagnostics {
		if d.Code == "DSD-SCN-006" {
			if d.Location.Path != "ignores.yaml" {
				t.Fatalf("review 02 F14: %q", d.Location.Path)
			}
			return
		}
	}
	t.Fatalf("review 02 F14: no expired-ignore diagnostic in %#v", got.Diagnostics)
}

// review 02 F17: a file over 16 MiB is an error diagnostic counted as skipped, so
// the scan is incomplete and can never look clean (spec section 3).
func TestOversizeFileIsErrorAndSkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.yaml"), make([]byte, repo.MaxFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.FilesSkipped != 1 || got.Summary.Complete || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-008" || got.Diagnostics[0].Level != diag.LevelError {
		t.Fatalf("review 02 F17: %#v", got)
	}
}
