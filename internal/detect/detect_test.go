package detect

import (
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"strings"
	"testing"
)

func TestRulesPositiveAndNegative(t *testing.T) {
	tests := []struct{ name, input, rule string }{
		{"config positive", "global:\n  security:\n    allowInsecureImages: TRUE\n", "DSD-CFG-001"}, {"config negative", "global:\n  security:\n    allowInsecureImages: 'true'\n", ""},
		{"legacy positive", "image: bitnamilegacy/redis:7\n", "DSD-IMG-001"}, {"legacy negative", "image: example/redis:7\n", ""},
		{"version positive", "image: bitnami/redis:7\n", "DSD-IMG-002"}, {"version negative latest", "image: bitnami/redis:latest\n", "DSD-IMG-003"},
		{"community positive", "image: bitnamisecure/redis\n", "DSD-IMG-003"}, {"community negative", "image: redis:latest\n", ""},
		{"chart positive", "dependencies:\n- name: redis\n  repository: https://charts.bitnami.com/bitnami\n", "DSD-CHT-001"}, {"chart negative", "dependencies:\n- repository: https://example.com/charts\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("input.yaml", []byte(tt.input))
			if tt.rule == "" {
				if len(got.Findings) != 0 {
					t.Fatalf("source docs/spec/v0.1.md section 2.1: %#v", got.Findings)
				}
				return
			}
			if len(got.Findings) != 1 || got.Findings[0].RuleID != tt.rule {
				t.Fatalf("source docs/spec/v0.1.md section 2.1: %#v", got.Findings)
			}
		})
	}
}
func TestConfidenceAndUnresolved(t *testing.T) {
	tests := []struct {
		name, input string
		confidence  diag.Confidence
		diagnostic  bool
	}{
		{"mirror", "image: mirror.example/bitnami/redis:7\n", diag.ConfidenceInferred, false}, {"templated tag", "image: 'bitnami/redis:{{ .Values.tag }}'\n", diag.ConfidenceUnresolved, false}, {"fully templated", "image: '{{ .Values.image }}'\n", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("input.yaml", []byte(tt.input))
			if tt.diagnostic {
				if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-003" {
					t.Fatalf("source docs/spec/v0.1.md section 2.2: %#v", got)
				}
				return
			}
			if len(got.Findings) != 1 || got.Findings[0].Confidence != tt.confidence {
				t.Fatalf("source docs/spec/v0.1.md section 2.2: %#v", got.Findings)
			}
		})
	}
}
func TestRedactionAndSecret(t *testing.T) {
	got := YAML("input.yaml", []byte("kind: Secret\nstringData:\n  image: user:pass@host/bitnami/redis:{{ .Values.secret }}\n"))
	if len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 6: leaked Secret")
	}
	got = YAML("input.yaml", []byte("image: 'bitnami/redis:{{ .Values.secret }}'\n"))
	if strings.Contains(got.Findings[0].Reference, "secret") || strings.Contains(got.Findings[0].Original, "secret") {
		t.Fatal("source docs/spec/v0.1.md section 6: template body leaked")
	}
}
func TestDockerfileLimit(t *testing.T) {
	got := Dockerfile("Dockerfile", []byte(strings.Repeat("#", maxDockerfileLine+1)))
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}
