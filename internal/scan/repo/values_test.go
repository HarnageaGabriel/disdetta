package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// writeTree writes the given files, whose names are slash-separated and
// relative to root, creating the directories they need.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Source: docs/spec/v0.1.md section 9.2 (the Kustomization file names, the
// valuesFile resolution and the scan root restriction).
func TestValuesFileResolution(t *testing.T) {
	tests := []struct {
		name         string
		files        map[string]string
		outside      map[string]string
		wantFindings []string
		wantCodes    []string
		wantScanned  int
		wantComplete bool
	}{
		{
			name: "extensionless kustomization is scanned",
			files: map[string]string{
				"Kustomization": "images:\n- name: example/redis\n  newName: bitnami/redis\n  newTag: '7'\n",
			},
			wantFindings: []string{"DSD-IMG-002|Kustomization|3"},
			wantScanned:  1,
			wantComplete: true,
		},
		{
			name: "values file is scanned as chart values whatever its name",
			files: map[string]string{
				"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: overrides.yaml\n",
				"overrides.yaml":     "image: bitnamilegacy/postgresql:16.4.0\n",
			},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3", "DSD-IMG-001|overrides.yaml|1"},
			wantScanned:  2,
			wantComplete: true,
		},
		{
			name: "values file of a generator is scanned as chart values",
			files: map[string]string{
				"generator.yaml": "kind: HelmChartInflationGenerator\nname: postgresql\nrepo: https://charts.bitnami.com/bitnami\nvaluesFile: overrides.yaml\n",
				"overrides.yaml": "image: bitnamilegacy/postgresql:16.4.0\n",
			},
			wantFindings: []string{"DSD-CHT-001|generator.yaml|3", "DSD-IMG-001|overrides.yaml|1"},
			wantScanned:  2,
			wantComplete: true,
		},
		{
			name: "values file of a generator is resolved relative to the generator file",
			files: map[string]string{
				"base/generator.yaml": "kind: HelmChartInflationGenerator\nname: postgresql\nrepo: https://charts.bitnami.com/bitnami\nvaluesFile: overrides.yaml\n",
				"base/overrides.yaml": "image: bitnamilegacy/postgresql:16.4.0\n",
			},
			wantFindings: []string{"DSD-CHT-001|base/generator.yaml|3", "DSD-IMG-001|base/overrides.yaml|1"},
			wantScanned:  2,
			wantComplete: true,
		},
		{
			name: "values file outside the scan root is refused",
			files: map[string]string{
				"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: ../outside.yaml\n",
			},
			outside:      map[string]string{"outside.yaml": "image: bitnamilegacy/postgresql:16.4.0\n"},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3"},
			wantCodes:    []string{"DSD-SCN-004"},
			wantScanned:  1,
			wantComplete: false,
		},
		{
			name: "absolute values file is refused",
			files: map[string]string{
				"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: /etc/values.yaml\n",
			},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3"},
			wantCodes:    []string{"DSD-SCN-004"},
			wantScanned:  1,
			wantComplete: false,
		},
		{
			name: "missing values file is a diagnostic",
			files: map[string]string{
				"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: missing.yaml\n",
			},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3"},
			wantCodes:    []string{"DSD-SCN-004"},
			wantScanned:  1,
			wantComplete: false,
		},
		{
			name: "values file the walk also finds is scanned once",
			files: map[string]string{
				"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: values.yaml\n",
				"values.yaml":        "image: bitnamilegacy/postgresql:16.4.0\n",
			},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3", "DSD-IMG-001|values.yaml|1"},
			wantScanned:  2,
			wantComplete: true,
		},
		{
			name: "values file referenced twice is scanned once",
			files: map[string]string{
				"kustomization.yaml":       "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: shared/values.yaml\n",
				"other/kustomization.yaml": "helmCharts:\n- name: redis\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: ../shared/values.yaml\n",
				"shared/values.yaml":       "image: bitnamilegacy/postgresql:16.4.0\n",
			},
			wantFindings: []string{"DSD-CHT-001|kustomization.yaml|3", "DSD-CHT-001|other/kustomization.yaml|3", "DSD-IMG-001|shared/values.yaml|1"},
			wantScanned:  3,
			wantComplete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "repo")
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTree(t, root, tt.files)
			if tt.outside != nil {
				writeTree(t, parent, tt.outside)
			}
			got, err := Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			var findings []string
			for _, f := range got.Findings {
				findings = append(findings, f.RuleID+"|"+f.Location.Path+"|"+strconv.Itoa(f.Location.Line))
			}
			sort.Strings(findings)
			if strings.Join(findings, ",") != strings.Join(tt.wantFindings, ",") {
				t.Errorf("findings = %v, want %v", findings, tt.wantFindings)
			}
			var codes []string
			for _, d := range got.Diagnostics {
				codes = append(codes, d.Code)
			}
			sort.Strings(codes)
			if strings.Join(codes, ",") != strings.Join(tt.wantCodes, ",") {
				t.Errorf("diagnostics = %v, want %v", codes, tt.wantCodes)
			}
			if got.Summary.FilesScanned != tt.wantScanned {
				t.Errorf("files scanned = %d, want %d", got.Summary.FilesScanned, tt.wantScanned)
			}
			if got.Summary.Complete != tt.wantComplete {
				t.Errorf("complete = %v, want %v", got.Summary.Complete, tt.wantComplete)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 (a values file is never read through a
// symbolic link, and a declared reference that cannot be read is a read
// error).
func TestValuesFileSymlinkIsNotFollowed(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("image: bitnamilegacy/postgresql:16.4.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "values.yaml")); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}
	writeTree(t, root, map[string]string{
		"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: values.yaml\n",
	})
	got, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Findings {
		if f.Location.Path == "values.yaml" {
			t.Errorf("a values file reached through a symbolic link was scanned: %#v", f)
		}
	}
	codes := map[string]bool{}
	for _, d := range got.Diagnostics {
		codes[d.Code] = true
	}
	if !codes["DSD-SCN-002"] {
		t.Errorf("the skipped symbolic link was not reported: %#v", got.Diagnostics)
	}
	if !codes["DSD-SCN-004"] {
		t.Errorf("the unreadable values file reference was not reported: %#v", got.Diagnostics)
	}
	if got.Summary.Complete {
		t.Errorf("a scan with an unreadable values file reference is complete: %#v", got.Summary)
	}
}

// Source: docs/spec/v0.1.md section 9.2 (a values file below a symbolic link
// is never read: the link is never followed).
func TestValuesFileBelowSymlinkedParentIsRefused(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	for _, dir := range []string{root, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "values.yaml"), []byte("image: bitnamilegacy/postgresql:16.4.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}
	writeTree(t, root, map[string]string{
		"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: link/values.yaml\n",
	})
	got, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Findings {
		if f.Location.Path == "link/values.yaml" {
			t.Errorf("a values file below a symbolic link was scanned: %#v", f)
		}
	}
	codes := map[string]bool{}
	for _, d := range got.Diagnostics {
		codes[d.Code] = true
	}
	if !codes["DSD-SCN-004"] {
		t.Errorf("the values file below a symbolic link was not refused: %#v", got.Diagnostics)
	}
	if got.Summary.Complete {
		t.Errorf("a scan with a refused values file reference is complete: %#v", got.Summary)
	}
}

// Source: docs/spec/v0.1.md section 9.2 (a values file below a Windows
// junction is never read: a junction is not a plain directory).
func TestValuesFileBelowJunctionIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions exist only on Windows")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	for _, dir := range []string{root, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "values.yaml"), []byte("image: bitnamilegacy/postgresql:16.4.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
		t.Skipf("a junction could not be created: %v: %s", err, out)
	}
	writeTree(t, root, map[string]string{
		"kustomization.yaml": "helmCharts:\n- name: postgresql\n  repo: https://charts.bitnami.com/bitnami\n  valuesFile: link/values.yaml\n",
	})
	got, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Findings {
		if f.Location.Path == "link/values.yaml" {
			t.Errorf("a values file below a junction was scanned: %#v", f)
		}
	}
	codes := map[string]bool{}
	for _, d := range got.Diagnostics {
		codes[d.Code] = true
	}
	if !codes["DSD-SCN-004"] {
		t.Errorf("the values file below a junction was not refused: %#v", got.Diagnostics)
	}
	if got.Summary.Complete {
		t.Errorf("a scan with a refused values file reference is complete: %#v", got.Summary)
	}
}

// Source: docs/spec/v0.1.md section 9.2 (the resolution of a valuesFile
// reference).
func TestResolveValuesFile(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTree(t, root, map[string]string{"values.yaml": "image: bitnami/redis:7\n"})
	tests := []struct {
		name string
		ref  string
		want valuesStatus
	}{
		{"relative file inside the root", "values.yaml", valuesOK},
		{"relative file in a subdirectory", "sub/values.yaml", valuesMissing},
		{"escape with a parent reference", "../outside.yaml", valuesOutside},
		{"absolute path", filepath.Join(parent, "outside.yaml"), valuesOutside},
		{"missing file", "missing.yaml", valuesMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got := resolveValuesFile(root, root, tt.ref)
			if got != tt.want {
				t.Errorf("resolveValuesFile(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 (every directory between the root and
// a values file must be a plain directory).
func TestResolveValuesFileRejectsLinkedParent(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	outside := filepath.Join(parent, "outside")
	for _, dir := range []string{root, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "values.yaml"), []byte("image: bitnami/redis:7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}
	_, _, got := resolveValuesFile(root, root, filepath.Join("link", "values.yaml"))
	if got != valuesLinkedParent {
		t.Errorf("resolveValuesFile below a symbolic link = %v, want %v", got, valuesLinkedParent)
	}
	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plain, "values.yaml"), []byte("image: bitnami/redis:7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, got = resolveValuesFile(root, root, filepath.Join("plain", "values.yaml"))
	if got != valuesOK {
		t.Errorf("resolveValuesFile below a plain directory = %v, want %v", got, valuesOK)
	}
}
