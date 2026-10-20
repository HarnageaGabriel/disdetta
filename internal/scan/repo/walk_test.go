package repo_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
)

// mixedTreeFiles are the files of the tree the differential test scans. The
// tree holds one file of every kind the scan dispatches on, the files the
// scan never reads, and the documents that declare a values file.
var mixedTreeFiles = map[string]string{
	".disdetta.yaml":                  "ignores: []\n",
	"README.md":                       "not scanner input\n",
	"data/config.json":                "{}\n",
	"chart/Chart.yaml":                "apiVersion: v2\nname: app\nversion: 1.0.0\n",
	"chart/values.yaml":               "global:\n  imageRegistry: registry.example\nimages:\n  - name: app\n    image: bitnami/redis:7\n",
	"chart/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: \"bitnami/postgresql:{{ .Values.tag }}\"\n",
	"kustomization.yaml":              "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nhelmCharts:\n  - name: app\n    valuesFile: chart/values.yaml\n",
	"generator.yaml":                  "kind: HelmChartInflationGenerator\nname: app\nrepo: https://charts.bitnami.com/bitnami\nvaluesFile: chart/values.yaml\n",
	"missing-values.yaml":             "kind: HelmChartInflationGenerator\nname: app\nrepo: https://charts.bitnami.com/bitnami\nvaluesFile: chart/absent.yaml\n",
	"docker/Dockerfile":               "FROM bitnami/minideb:latest\n",
	"docker/Dockerfile.prod":          "FROM bitnami/minideb:latest\nENV TAG=prod\n",
	"main.tf":                         "terraform {\n  required_version = \">= 1.0\"\n}\n",
	"template.tpl":                    "image: bitnami/redis:7\n",
	"broken.yaml":                     "image: [\n",
	"Kustomization":                   "images:\n- name: example/redis\n  newName: bitnami/redis\n  newTag: '7'\n",
}

// TestScanSkipsIrrelevantFilesButKeepsTheirDiagnostics checks that the walk
// may drop the files no detector reads, and that the files it cannot drop
// keep their diagnostics: a link is reported as skipped whatever its name.
func TestScanSkipsIrrelevantFilesButKeepsTheirDiagnostics(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	if err := os.WriteFile(target, []byte("apiVersion: v1\nkind: ConfigMap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "notes.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary.FilesSkipped != 1 {
		t.Fatalf("skipped %d files, want 1", got.Summary.FilesSkipped)
	}
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-002" {
		t.Fatalf("diagnostics %#v, want one DSD-SCN-002", got.Diagnostics)
	}
	if got.Diagnostics[0].Location.Path != "notes.txt" {
		t.Fatalf("the diagnostic names %q, want notes.txt", got.Diagnostics[0].Location.Path)
	}
}

// TestScanMixedTreeMatchesGolden is the differential test of the walk: the
// report of a tree that holds one file of every kind must stay byte for byte
// the one the scanner produced before the walk was optimized. The golden file
// is the output of that scanner, so a change in the report fails the test.
func TestScanMixedTreeMatchesGolden(t *testing.T) {
	root := t.TempDir()
	for name, contents := range mixedTreeFiles {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := report.JSON(&out, got); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "walk-mixed.json")
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("the report of the mixed tree changed:\ngot:\n%s\nwant:\n%s", out.String(), string(want))
	}
}
