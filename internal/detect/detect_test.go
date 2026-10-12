package detect

import (
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
			got, err := YAML("input.yaml", []byte(tt.input))
			if err != nil {
				t.Fatal(err)
			}
			codes := make([]string, len(got))
			for i := range got {
				codes[i] = got[i].Code
			}
			if diff := cmp.Diff(tt.wantCodes, codes); diff != "" {
				t.Errorf("source %s (-want +got):\n%s", tt.source, diff)
			}
		})
	}
}

func TestDockerfile(t *testing.T) {
	t.Parallel()
	got := Dockerfile("Dockerfile", []byte("FROM --platform=linux/amd64 bitnamilegacy/kafka:3 AS broker\nFROM alpine\n"))
	want := []diag.Diagnostic{{Code: "DSD-002", Severity: diag.SeverityLegacy, Message: "Bitnami legacy image", Reference: "docker.io/bitnamilegacy/kafka:3", Classification: "bitnamilegacy", Path: "Dockerfile", Line: 1, Stateful: true}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("source RESEARCH-NOTES section 4 (-want +got):\n%s", diff)
	}
}
