package imageref

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, input, source string
		want                Reference
	}{
		{"implicit", "bitnami/redis:7", "RESEARCH-NOTES section 3", Reference{Original: "bitnami/redis:7", Registry: "docker.io", Repository: "bitnami/redis", Tag: "7", Classification: Bitnami}},
		{"alias and digest", "index.docker.io/bitnamilegacy/postgresql:16@sha256:abc", "RESEARCH-NOTES section 3", Reference{Original: "index.docker.io/bitnamilegacy/postgresql:16@sha256:abc", Registry: "docker.io", Repository: "bitnamilegacy/postgresql", Tag: "16", Digest: "sha256:abc", Classification: BitnamiLegacy}},
		{"registry port", "mirror.local:5000/bitnamisecure/keycloak:latest", "RESEARCH-NOTES section 3", Reference{Original: "mirror.local:5000/bitnamisecure/keycloak:latest", Registry: "mirror.local:5000", Repository: "bitnamisecure/keycloak", Tag: "latest", Classification: BitnamiSecure}},
		{"library", "docker.io/library/redis:7", "RESEARCH-NOTES section 3", Reference{Original: "docker.io/library/redis:7", Registry: "docker.io", Repository: "redis", Tag: "7", Classification: Other}},
		{"template", "{{ .Values.image }}", "RESEARCH-NOTES section 3", Reference{Original: "{{ .Values.image }}", Classification: Unresolved, Redacted: true}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, Parse(tt.input)); diff != "" {
				t.Errorf("source %s (-want +got):\n%s", tt.source, diff)
			}
		})
	}
}

func TestSafeReferenceOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, source, input, want string
	}{
		{"unresolved tag", "review finding 2", "bitnami/redis:{{ .Values.token }}", "docker.io/bitnami/redis"},
		{"credential tag", "review finding 2", "bitnami/redis:super-secret-token", "docker.io/bitnami/redis"},
		{"userinfo", "review finding 2", "user:password@registry.example/bitnami/redis:7", "registry.example/bitnami/redis"},
		{"control tag", "review finding 2", "bitnami/redis:bad\x1btag", "docker.io/bitnami/redis"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Parse(tt.input).String(); got != tt.want {
				t.Errorf("source %s: got %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestJoin(t *testing.T) {
	t.Parallel()
	want := "registry-1.docker.io/bitnami/kafka:3"
	if got := Join("registry-1.docker.io", "bitnami/kafka", "3").Original; got != want {
		t.Errorf("source RESEARCH-NOTES section 3: got %q, want %q", got, want)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"bitnami/redis:7", "host:5000/repo@sha256:abc", "{{ value }}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		r := Parse(input)
		if r.Original != strings.TrimSpace(input) {
			t.Fatalf("original was not trimmed")
		}
		_ = r.String()
	})
}
