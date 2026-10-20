package detect

import (
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// yamlDefaultValues is the values-like document of a public repository: a
// configuration finding and two image triples.
const yamlDefaultValues = "global:\n" +
	"  security:\n" +
	"    allowInsecureImages: true\n" +
	"image:\n" +
	"  repository: bitnamilegacy/postgresql\n" +
	"volumePermissions:\n" +
	"  enabled: true\n" +
	"  image:\n" +
	"    repository: bitnamilegacy/os-shell\n"

// findingAt is the position and the rule of one finding, the part the name of
// the file must not change.
type findingAt struct {
	rule       string
	confidence diag.Confidence
	line       int
	column     int
}

func findingsAt(r diag.Report) []findingAt {
	out := make([]findingAt, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, findingAt{rule: f.RuleID, confidence: f.Confidence, line: f.Location.Line, column: f.Location.Column})
	}
	return out
}

// Source: docs/spec/v0.1.md section 9 (values files are any *.yaml/*.yml). The
// image triples of a document are reported whatever the name of the file is.
func TestDefaultCaseScansLikeAValuesFile(t *testing.T) {
	paths := []string{"postgresql.yaml", "config.yaml", "deploy/anything.yml"}
	baseline := findingsAt(YAML(paths[0], []byte(yamlDefaultValues)))
	if len(baseline) != 3 {
		t.Fatalf("source docs/spec/v0.1.md section 9: got %d findings: %#v", len(baseline), baseline)
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			got := YAML(path, []byte(yamlDefaultValues))
			at := findingsAt(got)
			if len(at) != len(baseline) {
				t.Fatalf("source docs/spec/v0.1.md section 9: got %#v, want %#v", at, baseline)
			}
			for j := range at {
				if at[j] != baseline[j] {
					t.Fatalf("source docs/spec/v0.1.md section 9: finding %d is %#v, want %#v", j, at[j], baseline[j])
				}
			}
		})
	}
	got := YAML(paths[0], []byte(yamlDefaultValues))
	rules := []string{"DSD-CFG-001", "DSD-IMG-001", "DSD-IMG-001"}
	for i, rule := range rules {
		if got.Findings[i].RuleID != rule {
			t.Fatalf("source docs/spec/v0.1.md section 9: finding %d is %#v, want %s", i, got.Findings[i], rule)
		}
	}
	if got.Findings[1].Reference != "docker.io/bitnamilegacy/postgresql" || got.Findings[2].Reference != "docker.io/bitnamilegacy/os-shell" {
		t.Fatalf("source docs/spec/v0.1.md section 9: %#v", got.Findings)
	}
}

// Source: docs/spec/v0.1.md section 6. Nothing under a Secret is read, in any
// file, whatever the name of the file is.
func TestDefaultCaseNeverReadsASecret(t *testing.T) {
	tests := []struct {
		name, source, input string
	}{
		{"nested secret", "docs/spec/v0.1.md section 6", "kind: ConfigMap\ndata:\n  credentials:\n    kind: Secret\n    image:\n      repository: bitnamilegacy/postgresql\n"},
		{"secret document", "docs/spec/v0.1.md section 6", "kind: Secret\nstringData:\n  image: bitnamilegacy/postgresql\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("config.yaml", []byte(tt.input))
			if len(got.Findings) != 0 {
				t.Fatalf("source %s: %#v", tt.source, got.Findings)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9 (only a Bitnami namespace is reported).
func TestDefaultCaseIgnoresNonBitnamiImages(t *testing.T) {
	input := "image:\n  repository: example/tool\n  tag: \"1.0\"\n"
	got := YAML("config.yaml", []byte(input))
	if len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9: %#v", got.Findings)
	}
}

// Source: docs/spec/v0.1.md section 9 (one scalar is never counted twice). A
// file that matches no specific case is scanned for image triples and by the
// whole-scalar fallback, and the two never report the same reference twice.
func TestDefaultCaseReportsAReferenceOnce(t *testing.T) {
	tests := []struct {
		name, source, path, input, rule string
		confidence                      diag.Confidence
		want                            int
	}{
		{name: "image triple", source: "docs/spec/v0.1.md section 9", path: "ci.yaml", input: "image:\n  repository: bitnamilegacy/redis\n", rule: "DSD-IMG-001", confidence: diag.ConfidenceConfirmed, want: 1},
		{name: "whole scalar under an unknown key", source: "docs/spec/v0.1.md section 9", path: "ci.yaml", input: "kubectl: bitnamilegacy/kubectl:latest\n", rule: "DSD-IMG-001", confidence: diag.ConfidenceInferred, want: 1},
		// A file a specific case recognizes keeps its own sources: the GitLab
		// CI detector reads `image` and `services`, not image triples.
		{name: "recognized ci file keeps its own sources", source: "docs/spec/v0.1.md section 9", path: ".gitlab-ci.yml", input: "image:\n  repository: bitnamilegacy/redis\n", want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			if len(got.Findings) != tt.want {
				t.Fatalf("source %s: got %d findings: %#v", tt.source, len(got.Findings), got.Findings)
			}
			if tt.want == 0 {
				return
			}
			f := got.Findings[0]
			if f.RuleID != tt.rule || f.Confidence != tt.confidence {
				t.Fatalf("source %s: %#v", tt.source, f)
			}
		})
	}
}
