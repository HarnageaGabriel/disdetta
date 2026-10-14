package detect

import (
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// Source: FIWARE/data-space-connector@4f3a596 charts/data-space-connector/templates/otel-restart-job.yaml
// and docs/spec/v0.1.md section 9.1.
func TestTemplateScanner(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantRules  []string
		wantDiags  []string
		wantConfid diag.Confidence
	}{
		{"static image", "          image: bitnami/kubectl:latest\n", []string{"DSD-IMG-003"}, []string{"DSD-SCN-007"}, ""},
		{"default literal", "{{ .Values.x | default \"bitnami/kubectl:1.30\" }}\n", []string{"DSD-IMG-002"}, []string{"DSD-SCN-007"}, diag.ConfidenceInferred},
		{"quoted image scalar", "image: \"bitnami/redis:7\"\n", []string{"DSD-IMG-002"}, []string{"DSD-SCN-007"}, ""},
		{"fully templated", "image: \"{{ .Values.image.registry }}/{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n", nil, []string{"DSD-SCN-003", "DSD-SCN-007"}, ""},
		{"repository triple", "          repository: bitnamilegacy/os-shell\n", []string{"DSD-IMG-001"}, []string{"DSD-SCN-007"}, ""},
		{"comment hash ignored", "# image: bitnami/not-real:1\n", nil, []string{"DSD-SCN-007"}, ""},
		{"comment template ignored", "{{/* image: bitnami/not-real:1 */}}\n", nil, []string{"DSD-SCN-007"}, ""},
		{"mount path negative", "            - mountPath: /opt/bitnami/postgresql\n", nil, []string{"DSD-SCN-007"}, ""},
		{"data dir negative", "          postgresqlDataDir: /bitnami/postgresql/data\n", nil, []string{"DSD-SCN-007"}, ""},
		{"command list negative", "          command: [\"cp\", \"/opt/bitnami/kubectl/bin\"]\n", nil, []string{"DSD-SCN-007"}, ""},
		{"github url negative", "          url: https://github.com/bitnami/charts\n", nil, []string{"DSD-SCN-007"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Template("templates/job.yaml", []byte(tt.input))
			if !equalStrings(ruleIDs(got), tt.wantRules) {
				t.Fatalf("source docs/spec/v0.1.md section 9.1: rules %v", ruleIDs(got))
			}
			if !equalStrings(diagnosticCodes(got), tt.wantDiags) {
				t.Fatalf("source docs/spec/v0.1.md section 9.1: diagnostics %v", diagnosticCodes(got))
			}
			if tt.wantConfid != "" && got.Findings[0].Confidence != tt.wantConfid {
				t.Fatalf("source docs/spec/v0.1.md section 9.1: confidence %s", got.Findings[0].Confidence)
			}
		})
	}
}

// One DSD-SCN-007 per file: template text is scanned, not reported malformed.
func TestTemplateMarkerHelpers(t *testing.T) {
	malformed := YAML("job.yaml", []byte("image: [\n"))
	if HasTemplateMarkers([]byte("image: [\n")) || !Malformed(malformed) {
		t.Fatal("source docs/spec/v0.1.md section 9.1: helpers")
	}
	if !HasTemplateMarkers([]byte("image: {{ .Values.x }}\n")) {
		t.Fatal("source docs/spec/v0.1.md section 9.1: template marker not detected")
	}
}

func TestTemplateRedactsBody(t *testing.T) {
	got := Template("templates/job.yaml", []byte("image: \"bitnami/redis:{{ .Values.secretTag }}\"\n"))
	if len(got.Findings) != 1 || got.Findings[0].Reference != "docker.io/bitnami/redis:{{\u2026}}" {
		t.Fatalf("source docs/spec/v0.1.md section 6: %#v", got.Findings)
	}
}

func FuzzTemplateLineScanner(f *testing.F) {
	f.Add([]byte("image: bitnami/kubectl:latest\n"))
	f.Add([]byte("image: {{ .Values.x | default \"bitnami/kubectl:1.30\" }}\n"))
	f.Add([]byte("{{/* c */}}\n# x\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = Template("templates/x.yaml", b) })
}
