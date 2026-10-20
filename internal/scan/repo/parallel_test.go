package repo_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

// scanReport scans the root with the given number of workers and returns the
// report.
func scanReport(t *testing.T, root, workers string) diag.Report {
	t.Helper()
	t.Setenv(repo.WorkersEnv, workers)
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// scanJSON scans the root with the given number of workers and returns the
// JSON report.
func scanJSON(t *testing.T, root, workers string) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := report.JSON(&out, scanReport(t, root, workers)); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// scanJSONWithOptions scans the root with the given options and returns the
// JSON report.
func scanJSONWithOptions(t *testing.T, root string, options repo.Options) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := report.JSON(&out, scanWithTimeout(t, root, options)); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// scanWithTimeout scans the root with the given options and fails the test
// if the scan does not finish in time, so a deadlock fails the test instead
// of hanging it.
func scanWithTimeout(t *testing.T, root string, options repo.Options) diag.Report {
	t.Helper()
	type outcome struct {
		report diag.Report
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		report, err := repo.ScanWithOptions(context.Background(), root, options)
		done <- outcome{report: report, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		return result.report
	case <-time.After(30 * time.Second):
		t.Fatal("the scan did not finish in time")
		return diag.Report{}
	}
}

// fixtureRoots returns the scan root of every fixture repository.
func fixtureRoots(t *testing.T) []string {
	t.Helper()
	base := filepath.Join("..", "..", "..", "testdata", "repos")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	var roots []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		roots = append(roots, filepath.Join(base, entry.Name()))
	}
	sort.Strings(roots)
	if len(roots) == 0 {
		t.Fatal("no fixture repository found")
	}
	return roots
}

// generateTree writes a tree that holds the cases a scan must keep stable: a
// values file, a Helm template, a Dockerfile, a Kustomization that claims a
// values file, a HelmChartInflationGenerator, a malformed document and a file
// the scan never reads.
func generateTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("charts/app/Chart.yaml", "apiVersion: v2\nname: app\nversion: 1.0.0\n")
	write("charts/app/values.yaml", "global:\n  imageRegistry: registry.example\nimages:\n  - name: app\n    image: bitnami/redis:7\n")
	write("charts/app/templates/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: \"bitnami/postgresql:{{ .Values.tag }}\"\n")
	write("kustomization.yaml", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nhelmCharts:\n  - name: app\n    valuesFile: charts/app/values.yaml\n")
	write("generator.yaml", "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmChartInflationGenerator\nmetadata:\n  name: app\nspec:\n  valuesFile: charts/app/values.yaml\n")
	write("docker/Dockerfile", "FROM bitnami/minideb:latest\n")
	write("compose/compose.yaml", "services:\n  app:\n    image: bitnami/redis:7\n")
	write("broken/bad.yaml", "image: [\n")
	write("notes/README.md", "not scanned\n")
	return root
}

// TestScanIsIdenticalForEveryWorkerCount scans every fixture repository and
// a generated tree with one worker and with eight workers, and compares the
// JSON reports byte for byte. The eight worker scan runs several times,
// because the order in which the files are parsed changes from run to run.
func TestScanIsIdenticalForEveryWorkerCount(t *testing.T) {
	cases := []struct{ name, root string }{}
	for _, root := range fixtureRoots(t) {
		cases = append(cases, struct{ name, root string }{filepath.Base(root), root})
	}
	cases = append(cases, struct{ name, root string }{"generated", generateTree(t)})
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sequential := scanJSON(t, testCase.root, "1")
			for run := 1; run <= 3; run++ {
				parallel := scanJSON(t, testCase.root, "8")
				if !bytes.Equal(sequential, parallel) {
					t.Fatalf("run %d: the report with 8 workers differs from the sequential report:\nsequential:\n%s\nparallel:\n%s", run, sequential, parallel)
				}
			}
		})
	}
}

// TestPerFileOversizeDiagnosticsKeepWalkOrder checks the per file size limit:
// a file above the limit is skipped and reported with DSD-SCN-008, in walk
// order, even when the workers finish the files in the reverse order. The
// scanner has no aggregate limit: only the per file limit of 16 MiB applies.
func TestPerFileOversizeDiagnosticsKeepWalkOrder(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, content []byte) {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("00-values.yaml", []byte("image: bitnami/redis:7\n"))
	write("10-oversized.yaml", make([]byte, repo.MaxFileSize+1))
	write("20-values.yaml", []byte("image: bitnami/postgresql:15\n"))
	write("30-oversized.yaml", make([]byte, repo.MaxFileSize+1))
	// The hook holds every file until the next one is done, so the workers
	// finish the files in the reverse of the walk order.
	gates := make([]chan struct{}, 4)
	for i := range gates {
		gates[i] = make(chan struct{}, 1)
	}
	var mu sync.Mutex
	var finished []int
	options := repo.Options{JobHook: func(index int, scan func() diag.Report) diag.Report {
		if index+1 < len(gates) {
			<-gates[index+1]
		}
		parsed := scan()
		mu.Lock()
		finished = append(finished, index)
		mu.Unlock()
		if index < len(gates) {
			gates[index] <- struct{}{}
		}
		return parsed
	}}
	t.Setenv(repo.WorkersEnv, "1")
	sequential := scanJSONWithOptions(t, root, repo.Options{})
	t.Setenv(repo.WorkersEnv, "8")
	got := scanWithTimeout(t, root, options)
	mu.Lock()
	order := append([]int(nil), finished...)
	mu.Unlock()
	wantOrder := []int{3, 2, 1, 0}
	if len(order) != len(wantOrder) {
		t.Fatalf("%d files were parsed, want %d", len(order), len(wantOrder))
	}
	for i := range wantOrder {
		if order[i] != wantOrder[i] {
			t.Fatalf("the files finished in the order %v, want %v", order, wantOrder)
		}
	}
	var out bytes.Buffer
	if err := report.JSON(&out, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sequential, out.Bytes()) {
		t.Fatalf("the report with 8 workers differs from the sequential report:\nsequential:\n%s\nparallel:\n%s", sequential, out.Bytes())
	}
	if got.Summary.FilesScanned != 2 || got.Summary.FilesSkipped != 2 {
		t.Fatalf("scanned %d files and skipped %d, want 2 scanned and 2 skipped", got.Summary.FilesScanned, got.Summary.FilesSkipped)
	}
	var skipped []string
	for _, d := range got.Diagnostics {
		if d.Code != "DSD-SCN-008" {
			t.Fatalf("diagnostic %s at %s, want DSD-SCN-008", d.Code, d.Location.Path)
		}
		skipped = append(skipped, d.Location.Path)
	}
	want := []string{"10-oversized.yaml", "30-oversized.yaml"}
	if len(skipped) != len(want) {
		t.Fatalf("skipped %v, want %v", skipped, want)
	}
	for i := range want {
		if skipped[i] != want[i] {
			t.Fatalf("skipped %v, want %v in walk order", skipped, want)
		}
	}
}

// TestCancelledScanFailsForEveryWorkerCount checks that a cancelled context
// fails the scan the same way, whatever the number of workers: the scan
// returns an error and no report, never a partial one.
func TestCancelledScanFailsForEveryWorkerCount(t *testing.T) {
	root := generateTree(t)
	for _, workers := range []string{"1", "8"} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		t.Setenv(repo.WorkersEnv, workers)
		got, err := repo.Scan(ctx, root)
		if err == nil {
			t.Fatalf("workers %s: a cancelled scan returned no error", workers)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("workers %s: error %v does not wrap context.Canceled", workers, err)
		}
		if got.Summary.Complete || len(got.Findings) != 0 {
			t.Fatalf("workers %s: a cancelled scan returned a report: %#v", workers, got.Summary)
		}
	}
}
