package detect

import (
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

func TestHelmfileYAMLSources(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	tests := []struct {
		name  string
		path  string
		input string
		want  []string
	}{
		{"chart alias and inline values map", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n    values:\n      - image: {repository: bitnamilegacy/postgresql}\n", []string{"DSD-CHT-001", "DSD-IMG-001"}},
		{"release before repositories", "helmfile.yaml", "releases:\n  - name: db\n    chart: bitnami/postgresql\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		// The repositories and the releases of a file are resolved together:
		// the order of the documents never changes the result.
		{"release in an earlier document", "helmfile.yaml", "releases:\n  - name: db\n    chart: bitnami/postgresql\n---\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"repositories in an earlier document", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n---\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n", []string{"DSD-CHT-001"}},
		// A release resolves against every declaration with the same name.
		{"duplicate repository names", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n", []string{"DSD-CHT-001"}},
		{"chart without repository slash", "helmfile.yaml", "repositories: []\nreleases:\n  - name: db\n    chart: postgresql\n", nil},
		{"oci registry style repository", "helmfile.yaml", "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n", []string{"DSD-CHT-001"}},
		{"oci scheme with oci flag", "helmfile.yaml", "repositories:\n  - name: oci\n    url: oci://registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n", []string{"DSD-CHT-001"}},
		{"repository used by two releases", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n", []string{"DSD-CHT-001", "DSD-CHT-001"}},
		{"unused repository keeps URL finding", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"release alias absent from this file", "helmfile.yaml", "releases:\n  - name: db\n    chart: missing/postgresql\n", nil},
		// An include is not read: an alias declared in another file is
		// unknown here, so the release is not a finding.
		{"included file is not followed", "helmfile.yaml", "helmfiles:\n  - path: ../other/helmfile.yaml\nbases:\n  - ../base\nrepositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n", nil},
		{"nested inline values", "helmfile.yaml", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: stable/postgresql\n    values:\n      - podAnnotations:\n          nested:\n            image:\n              repository: bitnamilegacy/postgresql\n", []string{"DSD-IMG-001"}},
		{"stable repository is negative", "helmfile.yaml", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: web\n    chart: stable/nginx\n", nil},
		{"bitnami name with unrelated url is negative", "helmfile.yaml", "repositories:\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n", nil},
		{"local chart path is negative", "helmfile.yaml", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: ../charts/postgresql\n", nil},
		{"string values path is negative", "helmfile.yaml", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: stable/nginx\n    values:\n      - values/bitnami.yaml\n", nil},
		{"alias values", "helmfile.yaml", "releaseValues: &releaseValues\n  image:\n    repository: bitnamilegacy/postgresql\nrepositories: []\nreleases:\n  - name: db\n    chart: local/postgresql\n    values: *releaseValues\n", []string{"DSD-IMG-001"}},
		{"merge values", "helmfile.yaml", "defaults: &defaults\n  image:\n    repository: bitnamilegacy/postgresql\nrepositories: []\nreleases:\n  - name: db\n    chart: local/postgresql\n    values:\n      - <<: *defaults\n", []string{"DSD-IMG-001"}},
		{"comment mention is negative", "helmfile.yaml", "# bitnami chart repository\nrepositories: []\nreleases: []\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.want...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i, want := range wantRules {
				if rules[i] != want {
					t.Fatalf("source %s: finding %d = %s, want %s", source, i, rules[i], want)
				}
			}
		})
	}
}

// helmfileWant is one expected Helmfile finding.
type helmfileWant struct {
	rule       string
	line       int
	column     int
	component  string
	impact     diag.Impact
	confidence diag.Confidence
	reference  string
	original   string
}

// helmfileScan scans a Helmfile source the way the repository scanner does:
// a `.gotmpl` file is template text, every other Helmfile file is YAML.
func helmfileScan(path, input string) diag.Report {
	if strings.HasSuffix(path, ".gotmpl") {
		return Template(path, []byte(input))
	}
	return YAML(path, []byte(input))
}

// assertHelmfileFindings checks the findings of a Helmfile scan against the
// expected ones, in source order.
func assertHelmfileFindings(t *testing.T, source string, got diag.Report, want []helmfileWant) {
	t.Helper()
	sort.Slice(got.Findings, func(i, j int) bool {
		if got.Findings[i].Location.Line == got.Findings[j].Location.Line {
			return got.Findings[i].Location.Column < got.Findings[j].Location.Column
		}
		return got.Findings[i].Location.Line < got.Findings[j].Location.Line
	})
	if len(got.Findings) != len(want) {
		t.Fatalf("source %s: got %#v", source, got.Findings)
	}
	for i, w := range want {
		gotFinding := got.Findings[i]
		if gotFinding.RuleID != w.rule || gotFinding.Location.Line != w.line ||
			gotFinding.Location.Column != w.column || gotFinding.Component != w.component ||
			gotFinding.Impact != w.impact || gotFinding.Confidence != w.confidence ||
			gotFinding.Reference != w.reference || gotFinding.Original != w.original {
			t.Fatalf("source %s: finding %d = %#v, want %#v", source, i, gotFinding, w)
		}
	}
}

// TestHelmfileFindingPlacement checks where a Helmfile finding is reported:
// one dependency is one finding, on the release that uses it.
func TestHelmfileFindingPlacement(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	tests := []struct {
		name  string
		input string
		want  []helmfileWant
	}{
		{
			name:  "used repository is reported at chart line",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "release before repositories remains at chart line",
			input: "releases:\n  - name: db\n    chart: bitnami/postgresql\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "two releases have two chart findings and no URL finding",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n",
			want: []helmfileWant{
				{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"},
				{"DSD-CHT-001", 8, 12, "redis", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/redis"},
			},
		},
		{
			name:  "unused repository keeps URL line",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 10, "", "unknown", "confirmed", "https://charts.bitnami.com/bitnami", "https://charts.bitnami.com/bitnami"}},
		},
		{
			name:  "duplicate names resolve every declaration",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 8, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			// The repository is declared in an earlier document: the release
			// is the only finding, the repository URL is not a second one.
			name:  "repository in an earlier document is not a second finding",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n---\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 7, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "release in an earlier document is the only finding",
			input: "releases:\n  - name: db\n    chart: bitnami/postgresql\n---\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "two releases in a later document have two findings",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n---\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n",
			want: []helmfileWant{
				{"DSD-CHT-001", 7, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"},
				{"DSD-CHT-001", 9, 12, "redis", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/redis"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("helmfile.yaml", []byte(tt.input))
			assertHelmfileFindings(t, source, got, tt.want)
		})
	}
}

// TestHelmfileOrderIndependentResolution checks that a release resolves
// against the repositories of its file whatever their order (review 2).
func TestHelmfileOrderIndependentResolution(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	const repositories = "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n"
	const releases = "releases:\n  - name: db\n    chart: bitnami/postgresql\n"
	tests := []struct {
		name  string
		input string
		line  int
	}{
		{"repositories first", repositories + releases, 6},
		{"releases first", releases + repositories, 3},
		{"repositories in a later document", releases + "---\n" + repositories, 3},
		{"releases in a later document", repositories + "---\n" + releases, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("helmfile.yaml", []byte(tt.input))
			if len(got.Findings) != 1 {
				t.Fatalf("source %s: got %#v", source, got.Findings)
			}
			finding := got.Findings[0]
			if finding.RuleID != "DSD-CHT-001" || finding.Location.Line != tt.line ||
				finding.Component != "postgresql" || finding.Reference != "https://charts.bitnami.com/bitnami" {
				t.Fatalf("source %s: got %#v", source, finding)
			}
		})
	}
}

// TestHelmfileDuplicateRepositoryNames checks that a name declared more than
// once is the Bitnami repository when any declaration is (review 3).
func TestHelmfileDuplicateRepositoryNames(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	const bitnami = "https://charts.bitnami.com/bitnami"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "bitnami declaration first",
			input: "repositories:\n  - name: bitnami\n    url: " + bitnami + "\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []string{"DSD-CHT-001"},
		},
		{
			name:  "bitnami declaration last",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.example.com/stable\n  - name: bitnami\n    url: " + bitnami + "\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []string{"DSD-CHT-001"},
		},
		{
			name:  "bitnami declaration in a later document",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n---\nrepositories:\n  - name: bitnami\n    url: " + bitnami + "\n",
			want:  []string{"DSD-CHT-001"},
		},
		{
			name:  "no bitnami declaration",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.example.com/stable\n  - name: bitnami\n    url: https://charts.example.com/other\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("helmfile.yaml", []byte(tt.input))
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.want...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i := range rules {
				if rules[i] != wantRules[i] {
					t.Fatalf("source %s: rules = %#v, want %#v", source, rules, wantRules)
				}
			}
			if len(tt.want) == 0 {
				return
			}
			finding := got.Findings[0]
			if finding.Reference != bitnami || finding.Component != "postgresql" {
				t.Fatalf("source %s: got %#v", source, finding)
			}
		})
	}
}

// TestHelmfileIncludesAreNotFollowed checks that a repository declared in
// another Helmfile is not resolved: an include is not read (review 4).
func TestHelmfileIncludesAreNotFollowed(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "helmfiles include is not followed",
			input: "helmfiles:\n  - path: ../other/helmfile.yaml\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  nil,
		},
		{
			name:  "bases include is not followed",
			input: "bases:\n  - ../base\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  nil,
		},
		{
			name:  "alias declared in this file is resolved",
			input: "helmfiles:\n  - path: ../other/helmfile.yaml\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []string{"DSD-CHT-001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("helmfile.yaml", []byte(tt.input))
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.want...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i := range rules {
				if rules[i] != wantRules[i] {
					t.Fatalf("source %s: rules = %#v, want %#v", source, rules, wantRules)
				}
			}
		})
	}
}

func TestHelmfileTemplatedChartAndURL(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	staticURL := "https://charts.bitnami.com/bitnami"
	tests := []struct {
		name      string
		path      string
		chart     string
		url       string
		wantRules []string
		wantLine  int
	}{
		{"yaml templated chart", "helmfile.yaml", "\"{{ .Release.Name }}/postgresql\"", staticURL, []string{"DSD-CHT-001"}, 3},
		{"yaml templated URL", "helmfile.yaml", "bitnami/postgresql", "{{ .Values.repoURL }}", nil, 0},
		{"yaml templated chart and URL", "helmfile.yaml", "\"{{ .Release.Name }}/postgresql\"", "{{ .Values.repoURL }}", nil, 0},
		{"gotmpl templated chart", "helmfile.yaml.gotmpl", "{{ .Release.Name }}/postgresql", staticURL, []string{"DSD-CHT-001"}, 3},
		{"gotmpl templated URL", "helmfile.yaml.gotmpl", "bitnami/postgresql", "{{ .Values.repoURL }}", nil, 0},
		{"gotmpl templated chart and URL", "helmfile.yaml.gotmpl", "{{ .Release.Name }}/postgresql", "{{ .Values.repoURL }}", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "repositories:\n  - name: bitnami\n    url: " + tt.url + "\nreleases:\n  - name: db\n    chart: " + tt.chart + "\n"
			var got diag.Report
			if strings.HasSuffix(tt.path, ".gotmpl") {
				got = Template(tt.path, []byte(input))
			} else {
				got = YAML(tt.path, []byte(input))
			}
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
				if strings.Contains(finding.Original, "{{") || strings.Contains(finding.Reference, "{{") {
					t.Fatalf("source %s: template body leaked in %#v", source, finding)
				}
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.wantRules...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i := range rules {
				if rules[i] != wantRules[i] {
					t.Fatalf("source %s: rules = %#v, want %#v", source, rules, wantRules)
				}
			}
			if tt.wantLine != 0 {
				if len(got.Findings) != 1 || got.Findings[0].Location.Line != tt.wantLine {
					t.Fatalf("source %s: got findings %#v, want URL line %d", source, got.Findings, tt.wantLine)
				}
			}
		})
	}
}

// TestHelmfileTemplatedValues checks that a templated value is never a
// certain finding: it is a diagnostic, never a wrong finding (review 5).
func TestHelmfileTemplatedValues(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	tests := []struct {
		name           string
		path           string
		input          string
		wantRules      []string
		wantDiagnostic []string
	}{
		{
			name: "gotmpl templated chart version and values",
			path: "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
				"releases:\n  - name: db\n    chart: {{ .Values.chart }}\n    version: {{ .Values.version }}\n" +
				"    values:\n      - image:\n          repository: {{ .Values.image }}\n",
			wantRules:      []string{"DSD-CHT-001"},
			wantDiagnostic: []string{"DSD-SCN-003", "DSD-SCN-007"},
		},
		{
			name: "yaml templated chart version and values",
			path: "helmfile.yaml",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
				"releases:\n  - name: db\n    chart: \"{{ .Values.chart }}\"\n    version: \"{{ .Values.version }}\"\n" +
				"    values:\n      - image:\n          repository: \"{{ .Values.image }}\"\n",
			wantRules:      []string{"DSD-CHT-001"},
			wantDiagnostic: []string{"DSD-SCN-003"},
		},
		{
			// An unquoted template action is not valid YAML: the file is
			// malformed, never a certain finding.
			name:           "yaml unquoted template is malformed",
			path:           "helmfile.yaml",
			input:          "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: {{ .Release.Name }}/postgresql\n",
			wantRules:      nil,
			wantDiagnostic: []string{"DSD-SCN-001"},
		},
		{
			// A template action alone parses as a YAML mapping: it names no
			// repository alias, so it is never a chart finding.
			name:           "yaml template action is not a chart",
			path:           "helmfile.yaml",
			input:          "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: {{ .Values.chart }}\n",
			wantRules:      []string{"DSD-CHT-001"},
			wantDiagnostic: nil,
		},
		{
			name: "gotmpl templated chart keeps the repository finding",
			path: "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
				"releases:\n  - name: db\n    chart: {{ .Values.chart }}\n",
			wantRules:      []string{"DSD-CHT-001"},
			wantDiagnostic: []string{"DSD-SCN-007"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got diag.Report
			if strings.HasSuffix(tt.path, ".gotmpl") {
				got = Template(tt.path, []byte(tt.input))
			} else {
				got = YAML(tt.path, []byte(tt.input))
			}
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
				if strings.Contains(finding.Original, "{{") || strings.Contains(finding.Reference, "{{") ||
					strings.Contains(finding.Component, "{{") {
					t.Fatalf("source %s: template body leaked in %#v", source, finding)
				}
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.wantRules...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i := range rules {
				if rules[i] != wantRules[i] {
					t.Fatalf("source %s: rules = %#v, want %#v", source, rules, wantRules)
				}
			}
			codes := make([]string, 0, len(got.Diagnostics))
			for _, diagnostic := range got.Diagnostics {
				codes = append(codes, diagnostic.Code)
			}
			sort.Strings(codes)
			wantCodes := append([]string(nil), tt.wantDiagnostic...)
			sort.Strings(wantCodes)
			if len(codes) != len(wantCodes) {
				t.Fatalf("source %s: diagnostics %#v, want %#v", source, codes, wantCodes)
			}
			for i := range codes {
				if codes[i] != wantCodes[i] {
					t.Fatalf("source %s: diagnostics = %#v, want %#v", source, codes, wantCodes)
				}
			}
		})
	}
}

func TestHelmfileGotmplResolutionSources(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"release before repositories", "releases:\n  - name: db\n    chart: bitnami/postgresql\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		// A gotmpl release also resolves against every same-name declaration.
		{"duplicate repository names", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n", []string{"DSD-CHT-001"}},
		{"chart without repository slash", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: postgresql\n", []string{"DSD-CHT-001"}},
		{"oci scheme with oci flag", "repositories:\n  - name: oci\n    url: oci://registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n", []string{"DSD-CHT-001"}},
		{"bare OCI registry with oci flag", "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n", []string{"DSD-CHT-001"}},
		{"repository used by two releases", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n", []string{"DSD-CHT-001", "DSD-CHT-001"}},
		{"unused repository keeps URL finding", "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n", []string{"DSD-CHT-001"}},
		{"stable repository is negative", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: web\n    chart: stable/nginx\n", nil},
		{"local chart path is negative", "repositories:\n  - name: stable\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: ../charts/postgresql\n", nil},
		{"comment mention is negative", "# bitnami chart repository\nrepositories: []\nreleases: []\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Template("helmfile.yaml.gotmpl", []byte(tt.input))
			rules := make([]string, 0, len(got.Findings))
			for _, finding := range got.Findings {
				rules = append(rules, finding.RuleID)
			}
			sort.Strings(rules)
			wantRules := append([]string(nil), tt.want...)
			sort.Strings(wantRules)
			if len(rules) != len(wantRules) {
				t.Fatalf("source %s: got findings %#v", source, got.Findings)
			}
			for i := range rules {
				if rules[i] != wantRules[i] {
					t.Fatalf("source %s: rules = %#v, want %#v", source, rules, wantRules)
				}
			}
		})
	}
}

// TestHelmfileGotmplOrderIndependentResolution checks that a gotmpl release
// resolves against the repositories of the file whatever their order
// (review 2).
func TestHelmfileGotmplOrderIndependentResolution(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	const repositories = "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n"
	const releases = "releases:\n  - name: db\n    chart: bitnami/postgresql\n"
	tests := []struct {
		name  string
		input string
		line  int
	}{
		{"repositories first", repositories + releases, 6},
		{"releases first", releases + repositories, 3},
		{"repositories in a later document", releases + "---\n" + repositories, 3},
		{"releases in a later document", repositories + "---\n" + releases, 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Template("helmfile.yaml.gotmpl", []byte(tt.input))
			if len(got.Findings) != 1 {
				t.Fatalf("source %s: got %#v", source, got.Findings)
			}
			finding := got.Findings[0]
			if finding.RuleID != "DSD-CHT-001" || finding.Location.Line != tt.line ||
				finding.Component != "postgresql" || finding.Reference != "https://charts.bitnami.com/bitnami" {
				t.Fatalf("source %s: got %#v", source, finding)
			}
		})
	}
}

func TestHelmfileChartImpactAndLocation(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	input := "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n"
	got := YAML("helmfile.yaml", []byte(input))
	var line int
	var impact diag.Impact
	for _, candidate := range got.Findings {
		if candidate.RuleID == "DSD-CHT-001" && candidate.Component == "postgresql" {
			line = candidate.Location.Line
			impact = candidate.Impact
			break
		}
	}
	if line != 6 || impact != "high" {
		t.Fatalf("source %s: chart finding %#v", source, got.Findings)
	}
}

func TestHelmfileTemplateSources(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	input := "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n    values:\n      - image: {repository: bitnamilegacy/postgresql}\n# bitnami comment\n"
	got := Template("helmfile.yaml.gotmpl", []byte(input))
	rules := make([]string, 0, len(got.Findings))
	for _, candidate := range got.Findings {
		rules = append(rules, candidate.RuleID)
	}
	sort.Strings(rules)
	if len(rules) != 2 || rules[0] != "DSD-CHT-001" || rules[1] != "DSD-IMG-001" {
		t.Fatalf("source %s: got %#v", source, got)
	}
	if len(got.Diagnostics) == 0 || got.Diagnostics[0].Code != "DSD-SCN-007" {
		t.Fatalf("source %s: diagnostics %#v", source, got.Diagnostics)
	}
	for _, candidate := range got.Findings {
		if strings.Contains(candidate.Original, "{{") {
			t.Fatalf("source %s: template body leaked", source)
		}
	}
}

func TestHelmfileTemplateOCIAlias(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md sections 9 and 9.1"
	input := "releases:\n  - name: cache\n    chart: oci/redis\nrepositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\n"
	got := Template("helmfile.yaml.gotmpl", []byte(input))
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "DSD-CHT-001" || got.Findings[0].Component != "redis" {
		t.Fatalf("source %s: got %#v", source, got)
	}
}

// TestHelmfileDirectOCIChart checks that a chart naming the Bitnami OCI
// chart repository directly is a finding, in YAML and in gotmpl files: it
// names no repository alias (review finding 2).
func TestHelmfileDirectOCIChart(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	const reference = "oci://registry-1.docker.io/bitnamicharts"
	tests := []struct {
		name  string
		path  string
		input string
		want  []helmfileWant
	}{
		{
			name:  "yaml direct oci chart",
			path:  "helmfile.yaml",
			input: "releases:\n  - name: db\n    chart: oci://registry-1.docker.io/bitnamicharts/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "postgresql", "high", "confirmed", reference, "oci://registry-1.docker.io/bitnamicharts/postgresql"}},
		},
		{
			name:  "gotmpl direct oci chart",
			path:  "helmfile.yaml.gotmpl",
			input: "releases:\n  - name: db\n    chart: oci://registry-1.docker.io/bitnamicharts/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "postgresql", "high", "confirmed", reference, "oci://registry-1.docker.io/bitnamicharts/postgresql"}},
		},
		{
			name:  "yaml direct oci chart on docker hub",
			path:  "helmfile.yaml",
			input: "releases:\n  - name: cache\n    chart: oci://docker.io/bitnamicharts/redis\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "redis", "high", "confirmed", "oci://docker.io/bitnamicharts", "oci://docker.io/bitnamicharts/redis"}},
		},
		{
			name:  "gotmpl direct oci chart on docker hub",
			path:  "helmfile.yaml.gotmpl",
			input: "releases:\n  - name: cache\n    chart: oci://docker.io/bitnamicharts/redis\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "redis", "high", "confirmed", "oci://docker.io/bitnamicharts", "oci://docker.io/bitnamicharts/redis"}},
		},
		{
			// The component is the last path segment of the reference.
			name:  "yaml direct oci chart with a nested path",
			path:  "helmfile.yaml",
			input: "releases:\n  - name: db\n    chart: oci://registry-1.docker.io/bitnamicharts/bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "postgresql", "high", "confirmed", reference, "oci://registry-1.docker.io/bitnamicharts/bitnami/postgresql"}},
		},
		{
			// A templated chart name is never certain.
			name:  "yaml templated direct oci chart",
			path:  "helmfile.yaml",
			input: "releases:\n  - name: db\n    chart: oci://registry-1.docker.io/bitnamicharts/{{ .Values.chart }}\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "", "unknown", "unresolved", reference, reference}},
		},
		{
			name:  "gotmpl templated direct oci chart",
			path:  "helmfile.yaml.gotmpl",
			input: "releases:\n  - name: db\n    chart: oci://registry-1.docker.io/bitnamicharts/{{ .Values.chart }}\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 12, "", "unknown", "unresolved", reference, reference}},
		},
		{
			// Another registry is not the Bitnami chart repository.
			name:  "yaml direct oci chart of another registry",
			path:  "helmfile.yaml",
			input: "releases:\n  - name: db\n    chart: oci://ghcr.io/acme/charts/postgresql\n",
			want:  nil,
		},
		{
			name:  "gotmpl direct oci chart of another registry",
			path:  "helmfile.yaml.gotmpl",
			input: "releases:\n  - name: db\n    chart: oci://ghcr.io/acme/charts/postgresql\n",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helmfileScan(tt.path, tt.input)
			for _, finding := range got.Findings {
				if strings.Contains(finding.Original, "{{") || strings.Contains(finding.Reference, "{{") {
					t.Fatalf("source %s: template body leaked in %#v", source, finding)
				}
			}
			assertHelmfileFindings(t, source, got, tt.want)
		})
	}
}

// TestHelmfileUnusedOCIRepository checks that a Bitnami OCI repository that no
// release uses is reported on its url entry, in YAML and in gotmpl files: the
// `oci://` form and the bare registry form are both Bitnami repositories
// (review finding 3).
func TestHelmfileUnusedOCIRepository(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	tests := []struct {
		name  string
		path  string
		input string
		want  []helmfileWant
	}{
		{
			name:  "yaml bare oci repository",
			path:  "helmfile.yaml",
			input: "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 10, "", "unknown", "confirmed", "registry-1.docker.io/bitnamicharts", "registry-1.docker.io/bitnamicharts"}},
		},
		{
			name:  "gotmpl bare oci repository",
			path:  "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 10, "", "unknown", "confirmed", "registry-1.docker.io/bitnamicharts", "registry-1.docker.io/bitnamicharts"}},
		},
		{
			name:  "yaml oci scheme repository",
			path:  "helmfile.yaml",
			input: "repositories:\n  - name: oci\n    url: oci://registry-1.docker.io/bitnamicharts\n    oci: true\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 10, "", "unknown", "confirmed", "oci://registry-1.docker.io/bitnamicharts", "oci://registry-1.docker.io/bitnamicharts"}},
		},
		{
			name:  "gotmpl oci scheme repository",
			path:  "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: oci\n    url: oci://registry-1.docker.io/bitnamicharts\n    oci: true\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 10, "", "unknown", "confirmed", "oci://registry-1.docker.io/bitnamicharts", "oci://registry-1.docker.io/bitnamicharts"}},
		},
		{
			// A release that uses the repository is the only finding.
			name:  "yaml used oci repository",
			path:  "helmfile.yaml",
			input: "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n",
			want:  []helmfileWant{{"DSD-CHT-001", 7, 12, "redis", "high", "confirmed", "registry-1.docker.io/bitnamicharts", "oci/redis"}},
		},
		{
			name:  "gotmpl used oci repository",
			path:  "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: oci\n    url: registry-1.docker.io/bitnamicharts\n    oci: true\nreleases:\n  - name: cache\n    chart: oci/redis\n",
			want:  []helmfileWant{{"DSD-CHT-001", 7, 12, "redis", "high", "confirmed", "registry-1.docker.io/bitnamicharts", "oci/redis"}},
		},
		{
			// Another registry is not a Bitnami repository.
			name:  "yaml other oci repository",
			path:  "helmfile.yaml",
			input: "repositories:\n  - name: oci\n    url: ghcr.io/acme/charts\n    oci: true\n",
			want:  nil,
		},
		{
			name:  "gotmpl other oci repository",
			path:  "helmfile.yaml.gotmpl",
			input: "repositories:\n  - name: oci\n    url: ghcr.io/acme/charts\n    oci: true\n",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helmfileScan(tt.path, tt.input)
			assertHelmfileFindings(t, source, got, tt.want)
		})
	}
}

// TestHelmfileGotmplColumnZeroList checks that a YAML list written at column
// zero is a list of the current section, in a gotmpl file (review finding 4).
func TestHelmfileGotmplColumnZeroList(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	tests := []struct {
		name  string
		input string
		want  []helmfileWant
	}{
		{
			name:  "column zero list with a release",
			input: "repositories:\n- name: bitnami\n  url: https://charts.bitnami.com/bitnami\nreleases:\n- name: db\n  chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 6, 10, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "column zero list with an unused repository",
			input: "repositories:\n- name: bitnami\n  url: https://charts.bitnami.com/bitnami\n",
			want:  []helmfileWant{{"DSD-CHT-001", 3, 8, "", "unknown", "confirmed", "https://charts.bitnami.com/bitnami", "https://charts.bitnami.com/bitnami"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Template("helmfile.yaml.gotmpl", []byte(tt.input))
			assertHelmfileFindings(t, source, got, tt.want)
		})
	}
}

// TestHelmfileGotmplTemplateActionKeepsSection checks that a template action
// line does not end the section of a gotmpl file: a release that follows it
// is still a release (review finding 4).
func TestHelmfileGotmplTemplateActionKeepsSection(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	input := "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
		"releases:\n  - name: db\n    chart: bitnami/postgresql\n" +
		"{{- if .Values.extra }}\n  - name: cache\n    chart: bitnami/redis\n{{- end }}\n"
	want := []helmfileWant{
		{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"},
		{"DSD-CHT-001", 9, 12, "redis", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/redis"},
	}
	got := Template("helmfile.yaml.gotmpl", []byte(input))
	assertHelmfileFindings(t, source, got, want)
}

// TestHelmfileGotmplTemplateComment checks that the body of a Go template
// comment is not read as YAML: the entries of a comment that spans several
// lines are ignored, and the entries that follow it are still read (spec
// section 9.1: comments are ignored).
func TestHelmfileGotmplTemplateComment(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	const repositories = "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n"
	tests := []struct {
		name  string
		input string
		want  []helmfileWant
	}{
		{
			// The commented entries are not repositories and not releases:
			// the real release is the only finding.
			name:  "multi-line comment is ignored",
			input: repositories + "{{/*\nrepositories:\n  - name: fake\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: fake\n    chart: bitnami/redis\n*/}}\n" + "releases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 14, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "multi-line comment with trim markers is ignored",
			input: repositories + "{{- /*\nrepositories:\n  - name: fake\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: fake\n    chart: bitnami/redis\n*/ -}}\n" + "releases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 14, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "comment inside a release is ignored",
			input: repositories + "releases:\n  - name: db\n    {{/*\n    chart: bitnami/redis\n    */}}\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 9, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			// A single-line comment is still ignored, and it does not end
			// the section of the file.
			name:  "single-line comment keeps the section",
			input: repositories + "{{/* a comment */}}\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 7, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "single-line comment in a release is ignored",
			input: repositories + "releases:\n  - name: db\n    {{/* chart: bitnami/redis */}}\n    chart: bitnami/postgresql\n",
			want:  []helmfileWant{{"DSD-CHT-001", 7, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Template("helmfile.yaml.gotmpl", []byte(tt.input))
			assertHelmfileFindings(t, source, got, tt.want)
		})
	}
}

// TestHelmfileGotmplNestedChartIsNotARelease checks that a chart key nested
// in the values of a release is not a release chart (review finding 5).
func TestHelmfileGotmplNestedChartIsNotARelease(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	input := "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
		"releases:\n  - name: db\n    chart: bitnami/postgresql\n    values:\n      - some:\n          chart: bitnami/redis\n"
	want := []helmfileWant{{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}}
	got := Template("helmfile.yaml.gotmpl", []byte(input))
	assertHelmfileFindings(t, source, got, want)
}

// TestHelmfileGotmplImageColumn checks that the inline image of a gotmpl
// release is reported at the first character of its value, as the YAML driver
// reports it (review finding 6).
func TestHelmfileGotmplImageColumn(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9.1"
	input := "releases:\n  - name: db\n    chart: stable/nginx\n    values:\n      - image: {repository: bitnamilegacy/postgresql}\n"
	for _, path := range []string{"helmfile.yaml", "helmfile.yaml.gotmpl"} {
		t.Run(path, func(t *testing.T) {
			got := helmfileScan(path, input)
			if len(got.Findings) != 1 {
				t.Fatalf("source %s: got %#v", source, got.Findings)
			}
			finding := got.Findings[0]
			if finding.RuleID != "DSD-IMG-001" || finding.Location.Line != 5 || finding.Location.Column != 29 {
				t.Fatalf("source %s: got %#v", source, finding)
			}
		})
	}
}

// TestHelmfileCRLFInput checks that a Helmfile with Windows line endings is
// scanned like any other: the tests run on Linux, Windows and macOS.
func TestHelmfileCRLFInput(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	input := "repositories:\r\n  - name: bitnami\r\n    url: https://charts.bitnami.com/bitnami\r\n" +
		"releases:\r\n  - name: db\r\n    chart: bitnami/postgresql\r\n"
	want := []helmfileWant{{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}}
	for _, path := range []string{"helmfile.yaml", "helmfile.yaml.gotmpl"} {
		t.Run(path, func(t *testing.T) {
			got := helmfileScan(path, input)
			assertHelmfileFindings(t, source, got, want)
		})
	}
}

// TestHelmfileConcurrentScans checks that two scans of the same Helmfile
// never share their state: the state of a file belongs to one scan
// (review finding 8).
func TestHelmfileConcurrentScans(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	input := "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n" +
		"releases:\n  - name: db\n    chart: bitnami/postgresql\n"
	want := []helmfileWant{{"DSD-CHT-001", 6, 12, "postgresql", "high", "confirmed", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}}
	reports := make([]diag.Report, 8)
	var wg sync.WaitGroup
	for i := range reports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i] = YAML("helmfile.yaml", []byte(input))
		}()
	}
	wg.Wait()
	for _, got := range reports {
		assertHelmfileFindings(t, source, got, want)
	}
}
