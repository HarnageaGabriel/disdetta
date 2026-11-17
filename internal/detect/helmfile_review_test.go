package detect

import (
	"sort"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// helmfileReviewWant is one expected finding of the review regressions: the
// rule, the confidence and the position.
type helmfileReviewWant struct {
	rule       string
	confidence diag.Confidence
	line       int
	column     int
}

// TestHelmfileSetReviewRegressions pins the defects an independent review
// found in the set and inline values handling of the Helmfile detector: each
// case runs in the YAML path and in the line-based gotmpl path where the
// content is valid in both.
func TestHelmfileSetReviewRegressions(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	const release = "releases:\n  - name: app\n    chart: acme/app\n"
	both := []string{"helmfile.yaml", "helmfile.yaml.gotmpl"}
	tests := []struct {
		name  string
		paths []string
		input string
		want  []helmfileReviewWant
	}{
		{
			// A set entry whose name is not an image key path is not an
			// image, whatever its value looks like.
			name:  "nameOverride is not an image",
			paths: both,
			input: release + "    set:\n      - name: nameOverride\n        value: bitnami/redis\n",
			want:  nil,
		},
		{
			// The set entry overrides the inline value: one effective image
			// is one finding, at the overriding set value.
			name:  "set repeats an inline image",
			paths: []string{"helmfile.yaml"},
			input: release + "    values:\n      - image:\n          repository: bitnami/redis\n    set:\n      - name: image.repository\n        value: bitnami/redis\n",
			want:  []helmfileReviewWant{{"DSD-IMG-003", diag.ConfidenceConfirmed, 9, 16}},
		},
		{
			// A different image in the set entry does not hide the inline one.
			name:  "set names another image than the inline values",
			paths: []string{"helmfile.yaml"},
			input: release + "    values:\n      - image:\n          repository: bitnami/redis\n    set:\n      - name: image.repository\n        value: bitnami/postgresql\n",
			want: []helmfileReviewWant{
				{"DSD-IMG-003", diag.ConfidenceConfirmed, 6, 23},
				{"DSD-IMG-003", diag.ConfidenceConfirmed, 9, 16},
			},
		},
		{
			// The guard only counts under global.security.
			name:  "allowInsecureImages outside global.security",
			paths: both,
			input: release + "    values:\n      - unrelated:\n          allowInsecureImages: true\n",
			want:  nil,
		},
		{
			name:  "allowInsecureImages under global.security",
			paths: both,
			input: release + "    values:\n      - global:\n          security:\n            allowInsecureImages: true\n",
			want:  []helmfileReviewWant{{"DSD-CFG-001", diag.ConfidenceConfirmed, 7, 34}},
		},
		{
			// A sibling mapping of global.security does not count either.
			name:  "allowInsecureImages under a sibling of security",
			paths: both,
			input: release + "    values:\n      - global:\n          other:\n            allowInsecureImages: true\n",
			want:  nil,
		},
		{
			name:  "flow style values on the key line",
			paths: both,
			input: release + "    values: [{global: {security: {allowInsecureImages: true}}}]\n",
			want:  []helmfileReviewWant{{"DSD-CFG-001", diag.ConfidenceConfirmed, 4, 56}},
		},
		{
			name:  "flow style values in a list item",
			paths: both,
			input: release + "    values:\n      - {global: {security: {allowInsecureImages: true}}}\n",
			want:  []helmfileReviewWant{{"DSD-CFG-001", diag.ConfidenceConfirmed, 5, 51}},
		},
		{
			name:  "flow style value of a key",
			paths: both,
			input: release + "    values:\n      - global:\n          security: {allowInsecureImages: true}\n",
			want:  []helmfileReviewWant{{"DSD-CFG-001", diag.ConfidenceConfirmed, 6, 43}},
		},
		{
			name:  "flow style guard that is not true",
			paths: both,
			input: release + "    values: [{global: {security: {allowInsecureImages: false}}}]\n",
			want:  nil,
		},
		{
			// The columns of a block scalar are the ones of the file.
			name:  "block scalar columns",
			paths: []string{"helmfile.yaml"},
			input: release + "    values:\n      - |\n        image:\n          repository: bitnamilegacy/minio\n",
			want:  []helmfileReviewWant{{"DSD-IMG-001", diag.ConfidenceConfirmed, 7, 23}},
		},
		{
			// An indented template action keeps the set block open.
			name:  "indented template action in a set block",
			paths: []string{"helmfile.yaml.gotmpl"},
			input: release + "    set:\n      {{- if .Values.pin }}\n      - name: image.tag\n        value: 1.2.3\n      {{- end }}\n      - name: image.repository\n        value: bitnami/redis\n",
			want:  []helmfileReviewWant{{"DSD-IMG-002", diag.ConfidenceConfirmed, 10, 16}},
		},
		{
			// The names of the set entries may be quoted.
			name:  "quoted set entry names",
			paths: both,
			input: release + "    set:\n      - name: \"image.repository\"\n        value: \"bitnami/redis\"\n",
			want:  []helmfileReviewWant{{"DSD-IMG-003", diag.ConfidenceConfirmed, 6, 16}},
		},
	}
	for _, tt := range tests {
		for _, path := range tt.paths {
			t.Run(tt.name+"/"+path, func(t *testing.T) {
				got := helmfileScan(path, tt.input)
				sort.Slice(got.Findings, func(i, j int) bool {
					if got.Findings[i].Location.Line == got.Findings[j].Location.Line {
						return got.Findings[i].Location.Column < got.Findings[j].Location.Column
					}
					return got.Findings[i].Location.Line < got.Findings[j].Location.Line
				})
				if len(got.Findings) != len(tt.want) {
					t.Fatalf("source %s: got %d findings, want %d: %#v", source, len(got.Findings), len(tt.want), got.Findings)
				}
				for i, w := range tt.want {
					f := got.Findings[i]
					if f.RuleID != w.rule || f.Confidence != w.confidence || f.Location.Line != w.line || f.Location.Column != w.column {
						t.Fatalf("source %s: finding %d = %s %s %d:%d, want %s %s %d:%d", source, i,
							f.RuleID, f.Confidence, f.Location.Line, f.Location.Column, w.rule, w.confidence, w.line, w.column)
					}
				}
			})
		}
	}
}
