package imageref

import (
	"strings"
	"testing"
)

func TestParseAndRedact(t *testing.T) {
	tests := []struct{ name, input, want, class string }{
		{"literal", "bitnami/redis:7", "docker.io/bitnami/redis:7", "bitnami"},
		{"partial template", "bitnami/redis:{{ .Values.secretTag }}", "docker.io/bitnami/redis:{{…}}", "bitnami"},
		{"full template", "{{ .Values.image }}", "{{…}}", "unresolved"},
		{"userinfo", "user:pass@registry.example/bitnami/redis:7", "registry.example/bitnami/redis:7", "bitnami"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Parse(tt.input)
			if r.Safe != tt.want || string(r.Classification) != tt.class {
				t.Fatalf("source docs/spec/v0.1.md sections 2.2,6: got %q/%s", r.Safe, r.Classification)
			}
			if strings.Contains(r.SafeOriginal, "secretTag") || strings.Contains(r.SafeOriginal, "pass@") {
				t.Fatalf("unsafe original %q", r.SafeOriginal)
			}
		})
	}
}
func TestExcludedProjects(t *testing.T) {
	for _, v := range []string{"bitnami/sealed-secrets-controller:1", "bitnami/minideb:latest", "bitnami/charts-syncer:1"} {
		if !Parse(v).IsExcluded() {
			t.Errorf("source docs/spec/v0.1.md section 2.1: %s not excluded", v)
		}
	}
}
func FuzzParse(f *testing.F) {
	for _, v := range []string{"bitnami/redis:7", "{{ value }}"} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v string) {
		r := Parse(v)
		if r.Original != strings.TrimSpace(v) {
			t.Fatal("not trimmed")
		}
	})
}
