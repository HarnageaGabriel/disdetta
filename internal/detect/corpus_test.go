package detect

import (
	"sort"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

func ruleIDs(r diag.Report) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID)
	}
	sort.Strings(out)
	return out
}

func diagnosticCodes(r diag.Report) []string {
	out := make([]string, 0, len(r.Diagnostics))
	for _, d := range r.Diagnostics {
		out = append(out, d.Code)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Source: camunda/camunda-platform-helm@24369e0 charts/camunda-platform-8.7/values.yaml
// (allowInsecureImages under identityKeycloak) and docs/spec/v0.1.md section 2.1.
func TestConfigAnyDepth(t *testing.T) {
	tests := []struct {
		name, input string
		want        []string
	}{
		{"subchart key", "identityKeycloak:\n  global:\n    security:\n      allowInsecureImages: true\n", []string{"DSD-CFG-001"}},
		{"top level", "global:\n  security:\n    allowInsecureImages: true\n", []string{"DSD-CFG-001"}},
		{"deep nesting", "a:\n  b:\n    c:\n      global:\n        security:\n          allowInsecureImages: TRUE\n", []string{"DSD-CFG-001"}},
		{"disabled negative", "identityKeycloak:\n  global:\n    security:\n      allowInsecureImages: false\n", nil},
		{"string literal negative", "global:\n  security:\n    allowInsecureImages: 'true'\n", nil},
		{"other key negative", "global:\n  security:\n    allowInsecureImagesHint: true\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("values.yaml", []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.want) {
				t.Fatalf("source docs/spec/v0.1.md section 2.1: got %v", ruleIDs(got))
			}
		})
	}
}

// Source: camunda/camunda-platform-helm@24369e0 charts/web-modeler-postgresql-15/Chart.yaml
// and docs/spec/v0.1.md section 2.1 (DSD-CHT-002).
func TestVendoredChart(t *testing.T) {
	tests := []struct {
		name, input string
		want        []string
	}{
		{"sources url", "apiVersion: v2\nname: postgresql\nsources:\n  - https://github.com/bitnami/charts/tree/main/bitnami/postgresql\n", []string{"DSD-CHT-002"}},
		{"home url", "name: redis\nhome: https://github.com/bitnami/charts\n", []string{"DSD-CHT-002"}},
		{"annotations images one finding", "name: postgresql\nannotations:\n  images: |\n    - name: postgresql\n      image: docker.io/bitnami/postgresql:17.4.0-debian-12-r5\n    - name: redis\n      image: docker.io/bitnami/redis:7.4.0-debian-12-r0\n", []string{"DSD-CHT-002"}},
		{"github url outside sources negative", "name: app\nkeywords:\n  - https://github.com/bitnami/charts\n", nil},
		{"non bitnami annotations negative", "name: app\nannotations:\n  images: |\n    - name: app\n      image: docker.io/library/nginx:1\n", nil},
		{"chart repository is cht-001 only", "name: app\ndependencies:\n  - name: common\n    repository: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"both rules do not double count", "name: postgresql\ndependencies:\n  - name: common\n    repository: https://charts.bitnami.com/bitnami\nsources:\n  - https://github.com/bitnami/charts\n", []string{"DSD-CHT-001", "DSD-CHT-002"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("Chart.yaml", []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.want) {
				t.Fatalf("source docs/spec/v0.1.md section 2.1: got %v", ruleIDs(got))
			}
		})
	}
}

// Source: camunda/camunda-platform-helm@24369e0 charts/camunda-platform-8.7/values.yaml
// (sysctlImage.repository) and docs/spec/v0.1.md section 9 (repository triples).
func TestRepositoryTriples(t *testing.T) {
	tests := []struct {
		name, input string
		want        []string
	}{
		{"sysctl image", "elasticsearch:\n  sysctlImage:\n    enabled: true\n    repository: bitnamilegacy/os-shell\n", []string{"DSD-IMG-001"}},
		{"volume permissions", "volumePermissions:\n  image:\n    registry: docker.io\n    repository: bitnami/os-shell\n    tag: 12\n", []string{"DSD-IMG-002"}},
		{"chart url under repository is cht-001 only", "chart:\n  repository: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"leading slash is not image shaped", "chart:\n  repository: /bitnami/redis\n", nil},
		{"non bitnami repository", "helper:\n  repository: example/tool\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("values.yaml", []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.want) {
				t.Fatalf("source docs/spec/v0.1.md section 9: got %v", ruleIDs(got))
			}
		})
	}
}
