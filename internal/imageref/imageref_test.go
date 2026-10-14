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

// Source: docs/spec/v0.1.md sections 2.1 (DSD-IMG-004) and 9. The Bitnami
// namespace is recognized as any path segment; a filesystem path, shell
// fragment or prose scalar never classifies as an image.
func TestNamespaceAnyPathSegment(t *testing.T) {
	tests := []struct{ input, class string }{
		{"ghcr.io/acme/bitnami/redis:7", "bitnami"},
		{"registry.example.internal/mirror/bitnamilegacy/redis:7.2", "bitnamilegacy"},
		{"ghcr.io/acme/bitnamisecure/redis:7", "bitnamisecure"},
		{"/opt/bitnami/postgresql/conf", "other"},
		{"cp -a /opt/bitnami/keycloak/conf/* /config", "other"},
		{"see bitnami/redis docs", "other"},
		{"https://github.com/bitnami/charts/tree/main/bitnami/postgresql", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := string(Parse(tt.input).Classification); got != tt.class {
				t.Fatalf("source docs/spec/v0.1.md section 2.1: %q -> %s", tt.input, got)
			}
		})
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

// review 02 F13: a }} inside a quoted string of a template action must not end
// the redaction early and leak the template tail (spec section 6).
func TestTemplateRedactionKeepsQuotedBraces(t *testing.T) {
	r := Parse(`bitnami/redis:{{ printf "%s}}" .Values.tag }}`)
	if r.Safe != "docker.io/bitnami/redis:{{…}}" {
		t.Fatalf("review 02 F13: safe=%q", r.Safe)
	}
	if strings.Contains(r.SafeOriginal, "Values") || strings.Contains(r.SafeOriginal, "printf") {
		t.Fatalf("review 02 F13: leaked template body %q", r.SafeOriginal)
	}
}

// Join and the dollar-template forms round out the reference parser.
func TestJoinAndDollarTemplates(t *testing.T) {
	r := Join("registry.example", "bitnami/redis", "${TAG}")
	if !r.Templated || r.Safe != "registry.example/bitnami/redis:{{…}}" {
		t.Fatalf("source docs/spec/v0.1.md section 2.2: %q", r.Safe)
	}
	if r := Parse("bitnami/redis@{{ .Values.digest }}"); r.Safe != "docker.io/bitnami/redis@{{…}}" {
		t.Fatalf("source docs/spec/v0.1.md section 2.2: %q", r.Safe)
	}
	if r := Parse("bitnami/redis@sha256:abc"); r.SafeOriginal != "bitnami/redis@sha256:abc" || r.Digest != "sha256:abc" || r.Classification != Bitnami {
		t.Fatalf("source docs/spec/v0.1.md section 2.2: %#v", r)
	}
	if r := Parse(""); r.Safe != "" || r.Classification != Other {
		t.Fatalf("source docs/spec/v0.1.md section 2.2: %#v", r)
	}
}
