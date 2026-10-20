package repo

import (
	"context"
	"os"
	"path/filepath"
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
		got := scannableName(path)
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

// deploymentManifest is a Kubernetes manifest that names a Bitnami image, so
// the file it is written in always reports a finding when a detector reads it.
const deploymentManifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: bitnami/redis:7\n"

// kustomizeImages is a Kustomize image list that names a Bitnami image, so
// the file it is written in always reports a finding when a detector reads it.
const kustomizeImages = "images:\n  - name: example/redis\n    newName: bitnami/redis\n    newTag: \"7\"\n"

// terraformRelease is a Terraform release that sets a Bitnami image, so the
// file it is written in always reports a finding when a detector reads it.
const terraformRelease = "resource \"helm_release\" \"app\" {\n  set {\n    name  = \"image\"\n    value = \"bitnami/redis:7\"\n  }\n}\n"

// walkFilterCases are the file names the walk filter and the scan must agree
// on: every name the scan dispatches on, and the names no detector reads.
// Every file holds a Bitnami image, so a file the scan reads always reports a
// finding and a file the scan never reads reports none.
var walkFilterCases = []struct {
	name      string
	contents  string
	scannable bool
}{
	{name: "values.yaml", contents: "image: bitnami/redis:7\n", scannable: true},
	{name: "Chart.yaml", contents: "apiVersion: v2\nname: app\nversion: 1.0.0\nannotations:\n  images:\n    - bitnami/redis:7\n", scannable: true},
	{name: "helmfile.yaml.gotmpl", contents: "image: bitnami/redis:7\n", scannable: true},
	{name: "main.tf", contents: terraformRelease, scannable: true},
	{name: "Dockerfile", contents: "FROM bitnami/redis:7\n", scannable: true},
	{name: "Dockerfile.dev", contents: "FROM bitnami/redis:7\n", scannable: true},
	{name: "app.dockerfile", contents: "FROM bitnami/redis:7\n", scannable: true},
	{name: "Kustomization", contents: kustomizeImages, scannable: true},
	{name: "kustomization.yml", contents: kustomizeImages, scannable: true},
	{name: "x.tpl", contents: "image: bitnami/redis:7\n", scannable: true},
	{name: "ci.yaml", contents: deploymentManifest, scannable: true},
	{name: ".gitlab-ci.yml", contents: "image: bitnami/redis:7\n", scannable: true},
	{name: "azure-pipelines.yml", contents: "container: bitnami/redis:7\n", scannable: true},
	{name: "README.md", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "image.png", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "main.go", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: ".disdetta.yaml", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "notes.txt", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "Makefile", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "package.json", contents: "image: bitnami/redis:7\n", scannable: false},
	{name: "main.tf.json", contents: "image: bitnami/redis:7\n", scannable: false},
}

// TestWalkFilterAndScanAgreeOnFileNames checks that the filter of the walk
// and the scan of a tree take the same decision for every file name: the
// filter the walk uses must read exactly the files the scan reads, so a kind
// of file that is added to the scan is never dropped by the walk.
func TestWalkFilterAndScanAgreeOnFileNames(t *testing.T) {
	root := t.TempDir()
	tree := filepath.Join(root, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	scannable := 0
	for _, testCase := range walkFilterCases {
		path := filepath.Join(tree, testCase.name)
		if err := os.WriteFile(path, []byte(testCase.contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if testCase.scannable {
			scannable++
		}
		got := scannableName(path)
		if got != testCase.scannable {
			t.Fatalf("%s: the walk filter reads the file: %v, want %v", testCase.name, got, testCase.scannable)
		}
	}
	report, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, finding := range report.Findings {
		found[finding.Location.Path] = true
	}
	for _, testCase := range walkFilterCases {
		path := "tree/" + testCase.name
		if found[path] != testCase.scannable {
			t.Fatalf("%s: the scan reports a finding: %v, want %v", path, found[path], testCase.scannable)
		}
	}
	if len(found) != scannable {
		t.Fatalf("the scan reports findings in %d files, want %d: %v", len(found), scannable, found)
	}
}
