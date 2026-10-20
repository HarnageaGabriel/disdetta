package detect

import (
	"sort"
	"strings"
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

// TestHelmfileFindingPlacement checks where a Helmfile finding is reported:
// one dependency is one finding, on the release that uses it.
func TestHelmfileFindingPlacement(t *testing.T) {
	const source = "https://helmfile.readthedocs.io and docs/spec/v0.1.md section 9"
	type wantFinding struct {
		rule      string
		line      int
		column    int
		component string
		impact    diag.Impact
		reference string
		original  string
	}
	tests := []struct {
		name  string
		input string
		want  []wantFinding
	}{
		{
			name:  "used repository is reported at chart line",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []wantFinding{{"DSD-CHT-001", 6, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "release before repositories remains at chart line",
			input: "releases:\n  - name: db\n    chart: bitnami/postgresql\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []wantFinding{{"DSD-CHT-001", 3, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "two releases have two chart findings and no URL finding",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n",
			want: []wantFinding{
				{"DSD-CHT-001", 6, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"},
				{"DSD-CHT-001", 8, 12, "redis", "high", "https://charts.bitnami.com/bitnami", "bitnami/redis"},
			},
		},
		{
			name:  "unused repository keeps URL line",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []wantFinding{{"DSD-CHT-001", 3, 10, "", "unknown", "https://charts.bitnami.com/bitnami", "https://charts.bitnami.com/bitnami"}},
		},
		{
			name:  "duplicate names resolve every declaration",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n  - name: bitnami\n    url: https://charts.example.com/stable\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []wantFinding{{"DSD-CHT-001", 8, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			// The repository is declared in an earlier document: the release
			// is the only finding, the repository URL is not a second one.
			name:  "repository in an earlier document is not a second finding",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n---\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n",
			want:  []wantFinding{{"DSD-CHT-001", 7, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "release in an earlier document is the only finding",
			input: "releases:\n  - name: db\n    chart: bitnami/postgresql\n---\nrepositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n",
			want:  []wantFinding{{"DSD-CHT-001", 3, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"}},
		},
		{
			name:  "two releases in a later document have two findings",
			input: "repositories:\n  - name: bitnami\n    url: https://charts.bitnami.com/bitnami\n---\nreleases:\n  - name: db\n    chart: bitnami/postgresql\n  - name: cache\n    chart: bitnami/redis\n",
			want: []wantFinding{
				{"DSD-CHT-001", 7, 12, "postgresql", "high", "https://charts.bitnami.com/bitnami", "bitnami/postgresql"},
				{"DSD-CHT-001", 9, 12, "redis", "high", "https://charts.bitnami.com/bitnami", "bitnami/redis"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML("helmfile.yaml", []byte(tt.input))
			sort.Slice(got.Findings, func(i, j int) bool {
				if got.Findings[i].Location.Line == got.Findings[j].Location.Line {
					return got.Findings[i].Location.Column < got.Findings[j].Location.Column
				}
				return got.Findings[i].Location.Line < got.Findings[j].Location.Line
			})
			if len(got.Findings) != len(tt.want) {
				t.Fatalf("source %s: got %#v", source, got.Findings)
			}
			for i, want := range tt.want {
				gotFinding := got.Findings[i]
				if gotFinding.RuleID != want.rule || gotFinding.Location.Line != want.line ||
					gotFinding.Location.Column != want.column || gotFinding.Component != want.component ||
					gotFinding.Impact != want.impact || gotFinding.Reference != want.reference ||
					gotFinding.Original != want.original {
					t.Fatalf("source %s: finding %d = %#v, want %#v", source, i, gotFinding, want)
				}
			}
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
