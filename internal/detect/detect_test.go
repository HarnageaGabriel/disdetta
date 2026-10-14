package detect

import (
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/google/go-cmp/cmp"
)

func TestYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, source, input string
		wantCodes           []string
	}{
		{"values", "RESEARCH-NOTES sections 2-3", "global:\n  imageRegistry: mirror.local\n  security:\n    allowInsecureImages: true\nimage:\n  repository: bitnamilegacy/postgresql\n  tag: '16'\n", []string{"DSD-001", "DSD-002"}},
		{"chart", "RESEARCH-NOTES section 4", "dependencies:\n- name: redis\n  repository: https://charts.bitnami.com/bitnami\n", []string{"DSD-004"}},
		{"kubernetes", "RESEARCH-NOTES section 4", "kind: Pod\nspec:\n  containers:\n  - image: bitnami/redis:7\n", []string{"DSD-003"}},
		{"flux", "RESEARCH-NOTES section 4", "kind: HelmRepository\nspec:\n  url: oci://registry-1.docker.io/bitnamicharts\n", []string{"DSD-004"}},
		{"argo embedded", "RESEARCH-NOTES section 4", "kind: Application\nspec:\n  source:\n    helm:\n      values: |\n        image:\n          repository: bitnami/keycloak\n", []string{"DSD-003"}},
		{"action", "RESEARCH-NOTES section 4", "jobs:\n  test:\n    container:\n      image: bitnamisecure/keycloak:latest\n    steps:\n    - uses: docker://bitnami/redis:7\n", []string{"DSD-003", "DSD-003"}},
		{"template", "ADR 0005", "image: '{{ .Values.image }}'\n", []string{"DSD-005"}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := YAML("input.yaml", []byte(tt.input))
			codes := make([]string, len(got.Findings))
			for i := range got.Findings {
				codes[i] = got.Findings[i].Code
			}
			if diff := cmp.Diff(tt.wantCodes, codes); diff != "" {
				t.Errorf("source %s (-want +got):\n%s", tt.source, diff)
			}
		})
	}
}

func TestYAMLAdversarial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, source, input string
		wantFindings        int
		wantDiagnostics     int
		wantLine            int
	}{
		{"secret stringData", "review finding 2", "kind: Secret\nstringData:\n  image: bitnami/redis:super-secret-token\n", 0, 0, 0},
		{"bool lowercase", "review finding 9", "global:\n  security:\n    allowInsecureImages: true\n", 1, 0, 3},
		{"bool titlecase", "review finding 9", "global:\n  security:\n    allowInsecureImages: True\n", 1, 0, 3},
		{"bool uppercase", "review finding 9", "global:\n  security:\n    allowInsecureImages: TRUE\n", 1, 0, 3},
		{"quoted bool", "review finding 9", "global:\n  security:\n    allowInsecureImages: \"true\"\n", 0, 0, 0},
		{"embedded line", "review finding 10", "kind: Application\nspec:\n  source:\n    helm:\n      values: |\n        image:\n          repository: bitnami/keycloak\n", 1, 0, 7},
		{"malformed embedded", "review finding 3", "kind: Application\nspec:\n  source:\n    helm:\n      values: |\n        image: [\n", 0, 1, 0},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := YAML("input.yaml", []byte(tt.input))
			if len(got.Findings) != tt.wantFindings || len(got.Diagnostics) != tt.wantDiagnostics {
				t.Fatalf("source %s: got %d findings/%d diagnostics, want %d/%d", tt.source, len(got.Findings), len(got.Diagnostics), tt.wantFindings, tt.wantDiagnostics)
			}
			if tt.wantLine > 0 && got.Findings[0].Line != tt.wantLine {
				t.Errorf("source %s: got line %d, want %d", tt.source, got.Findings[0].Line, tt.wantLine)
			}
		})
	}
}

func TestYAMLDepthLimit(t *testing.T) {
	t.Parallel()
	var input strings.Builder
	for depth := 0; depth < maxYAMLDepth+2; depth++ {
		input.WriteString(strings.Repeat("  ", depth))
		input.WriteString("a:\n")
	}
	input.WriteString(strings.Repeat("  ", maxYAMLDepth+2))
	input.WriteString("image: bitnami/redis\n")
	got := YAML("deep.yaml", []byte(input.String()))
	if len(got.Diagnostics) != 1 || !strings.Contains(got.Diagnostics[0].Message, "depth limit") {
		t.Fatalf("source review finding 8: got diagnostics %#v", got.Diagnostics)
	}
}

func TestDockerfile(t *testing.T) {
	t.Parallel()
	got := Dockerfile("Dockerfile", []byte("FROM --platform=linux/amd64 bitnamilegacy/kafka:3 AS broker\nFROM alpine\n"))
	want := []diag.Diagnostic{{Code: "DSD-002", Severity: diag.SeverityLegacy, Message: "Bitnami legacy image", Reference: "docker.io/bitnamilegacy/kafka:3", Classification: "bitnamilegacy", Path: "Dockerfile", Line: 1, Stateful: true}}
	if diff := cmp.Diff(want, got.Findings); diff != "" {
		t.Errorf("source RESEARCH-NOTES section 4 (-want +got):\n%s", diff)
	}
}

func TestDockerfileLongLine(t *testing.T) {
	t.Parallel()
	input := strings.Repeat("#", 70*1024) + "\nFROM bitnami/redis:7\n"
	got := Dockerfile("Dockerfile", []byte(input))
	if len(got.Findings) != 1 || got.Findings[0].Line != 2 || len(got.Diagnostics) != 0 {
		t.Fatalf("source review finding 7: got %#v", got)
	}
}

func TestDockerfileLineLimitDiagnostic(t *testing.T) {
	t.Parallel()
	got := Dockerfile("Dockerfile", []byte(strings.Repeat("#", maxDockerfileLine+1)))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 {
		t.Fatalf("source review finding 7: got %#v", got)
	}
}
