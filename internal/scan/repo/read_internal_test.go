package repo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The walk skips the files no detector reads before it looks at their
// metadata. The names it skips must be exactly the names the scan would not
// read anyway, so the report of a repository never changes.
func TestScannableNameMatchesTheScan(t *testing.T) {
	cases := []struct {
		name      string
		contents  string
		scannable bool
	}{
		{name: "values.yaml", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: true},
		{name: "values.yml", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: true},
		{name: "VALUES.YAML", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: true},
		{name: "values.yaml.bak", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: false},
		{name: "yaml", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: false},
		{name: "Dockerfile", contents: "FROM scratch\n", scannable: true},
		{name: "dockerfile", contents: "FROM scratch\n", scannable: true},
		{name: "dockerfile.prod", contents: "FROM scratch\n", scannable: true},
		{name: "app.dockerfile", contents: "FROM scratch\n", scannable: true},
		{name: "notes.tpl", contents: "image: bitnami/redis:7\n", scannable: true},
		{name: "notes.yaml.gotmpl", contents: "apiVersion: v1\nkind: ConfigMap\n", scannable: true},
		{name: "main.tf", contents: "terraform {}\n", scannable: true},
		{name: "Kustomization", contents: "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n", scannable: true},
		{name: "kustomization.yaml", contents: "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n", scannable: true},
		{name: "kustomization.yml", contents: "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n", scannable: true},
		{name: ".disdetta.yaml", contents: "ignores: []\n", scannable: false},
		{name: "README.md", contents: "not scanner input\n", scannable: false},
		{name: "config.json", contents: "{}\n", scannable: false},
		{name: "notes.txt", contents: "not scanner input\n", scannable: false},
		{name: "Makefile", contents: "all:\n\techo hello\n", scannable: false},
	}
	root := t.TempDir()
	for _, testCase := range cases {
		path := filepath.Join(root, testCase.name)
		if err := os.WriteFile(path, []byte(testCase.contents), 0o600); err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(filepath.Base(path))
		got := scannableName(lower, path)
		if got != testCase.scannable {
			t.Fatalf("%s: scannableName is %v, want %v", testCase.name, got, testCase.scannable)
		}
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		report := scanFile(path, testCase.name, info)
		read := report.Summary.FilesScanned == 1
		if read != testCase.scannable {
			t.Fatalf("%s: the scan reads the file: %v, want %v", testCase.name, read, testCase.scannable)
		}
	}
}
