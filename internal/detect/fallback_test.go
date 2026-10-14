package detect

import (
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// Whole-scalar fallback and DSD-IMG-004 table tests (docs/spec/v0.1.md section
// 9 paragraph "Whole-scalar fallback" and section 2.1). Every case cites the
// corpus repository at its pinned commit, or the spec section it comes from.
func TestWholeScalarFallback(t *testing.T) {
	tests := []struct {
		name, source, path, input string
		want                      []string
		confidence                diag.Confidence
		attributes                []string
	}{
		{
			name:       "bitnami namespace below a registry path",
			source:     "wiremind/wiremind-helm-charts@b0e8b0d charts/keycloak/values.yaml",
			path:       "values.yaml",
			input:      "image:\n  registry: ghcr.io/wiremind\n  repository: bitnami/keycloak\n  tag: 26.5.0-debian-12-r3\n",
			want:       []string{"DSD-IMG-004"},
			confidence: diag.ConfidenceInferred,
			attributes: []string{"mirror"},
		},
		{
			name:       "mirrored legacy image stays img-001",
			source:     "docs/spec/v0.1.md section 2.1 (DSD-IMG-004: bitnamilegacy under another registry)",
			path:       "values.yaml",
			input:      "image: registry.example.internal/mirror/bitnamilegacy/redis:7.2\n",
			want:       []string{"DSD-IMG-001"},
			confidence: diag.ConfidenceInferred,
			attributes: []string{"mirror"},
		},
		{
			name:       "whole scalar legacy image under an unknown key",
			source:     "tmforum-oda/oda-canvas@75f29ac charts/canvas-oda/values.yaml",
			path:       "values.yaml",
			input:      "kubectl: bitnamilegacy/kubectl:latest\n",
			want:       []string{"DSD-IMG-001"},
			confidence: diag.ConfidenceInferred,
		},
		{
			name:   "chart url inside a longer scalar",
			source: "cowboysysop/charts@5a6a728 ct.yaml",
			path:   "ct.yaml",
			input:  "chart-repos:\n  - bitnami=https://charts.bitnami.com/bitnami/\n",
			want:   []string{"DSD-CHT-001"},
		},
		{
			name:   "chart url in a non chart yaml file",
			source: "linode/apl-core@984d959 charts/dependencies.yaml",
			path:   "dependencies.yaml",
			input:  "repository: https://charts.bitnami.com/bitnami\n",
			want:   []string{"DSD-CHT-001"},
		},
		{
			name:       "docker hub aliases are not another registry",
			source:     "docs/spec/v0.1.md section 2.2",
			path:       "values.yaml",
			input:      "image: index.docker.io/bitnami/redis:7\n",
			want:       []string{"DSD-IMG-002"},
			confidence: diag.ConfidenceConfirmed,
			attributes: []string{"pull-risk"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.want) {
				t.Fatalf("source %s: got %v", tt.source, ruleIDs(got))
			}
			if tt.confidence == "" {
				return
			}
			f := got.Findings[0]
			if f.Confidence != tt.confidence || !equalStrings(f.Attributes, tt.attributes) {
				t.Fatalf("source %s: %#v", tt.source, f)
			}
		})
	}
}

// Negatives: a partial match is never a finding (docs/spec/v0.1.md section 9).
func TestWholeScalarFallbackNegatives(t *testing.T) {
	tests := []struct{ name, source, path, input string }{
		{"excluded project sealed-secrets", "docs/spec/v0.1.md section 2.1", "values.yaml", "helper: bitnami/sealed-secrets-controller\n"},
		{"excluded project minideb", "docs/spec/v0.1.md section 2.1", "values.yaml", "helper: bitnami/minideb\n"},
		{"filesystem path", "docs/spec/v0.1.md section 9", "values.yaml", "postgresqlDataDir: /opt/bitnami/postgresql/conf\n"},
		{"shell fragment", "docs/spec/v0.1.md section 9", "values.yaml", "command: cp -a /opt/bitnami/keycloak/conf/* /config\n"},
		{"github url outside chart sources", "docs/spec/v0.1.md section 9", "values.yaml", "keywords:\n  - https://github.com/bitnami/charts/tree/main/bitnami/postgresql\n"},
		{"prose scalar is not a whole image", "docs/spec/v0.1.md section 9", "values.yaml", "note: see bitnami/redis docs\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			if len(got.Findings) != 0 {
				t.Fatalf("source %s: got %#v", tt.source, got.Findings)
			}
		})
	}
	stage := Dockerfile("Dockerfile", []byte("FROM alpine AS bitnami\nCOPY --from=bitnami /a /b\n"))
	if len(stage.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9 (dockerfile stage): %#v", stage.Findings)
	}
}

// No double counting: a scalar a specific detector already reported is not
// reported again by the fallbacks (docs/spec/v0.1.md section 9).
func TestWholeScalarFallbackNoDoubleCounting(t *testing.T) {
	tests := []struct {
		name, source, path, input string
		want                      []string
	}{
		{"image triple once", "docs/spec/v0.1.md section 9", "values.yaml", "image:\n  registry: ghcr.io/acme\n  repository: bitnami/redis\n  tag: 7\n", []string{"DSD-IMG-004"}},
		{"image key once", "docs/spec/v0.1.md section 2.1", "values.yaml", "image: bitnami/redis:7\n", []string{"DSD-IMG-002"}},
		{"chart dependency once", "docs/spec/v0.1.md section 2.1", "Chart.yaml", "name: app\ndependencies:\n  - name: app\n    repository: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"flux url once", "docs/spec/v0.1.md section 2.1", "flux.yaml", "kind: HelmRepository\nspec:\n  url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"same line findings both kept", "docs/spec/v0.1.md section 9", "local.gitlab-ci.yml", "services: [bitnami/redis:1, {name: bitnami/nginx:1}]\n", []string{"DSD-IMG-002", "DSD-IMG-002"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.want) {
				t.Fatalf("source %s: got %v", tt.source, ruleIDs(got))
			}
		})
	}
}
