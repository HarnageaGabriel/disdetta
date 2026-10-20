package detect

import (
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

func TestSection9YAMLSources(t *testing.T) {
	tests := []struct {
		name, path, input string
		want              int
	}{
		{"kubernetes containers", "deployment.yaml", "kind: Deployment\nspec:\n  template:\n    spec:\n      initContainers: [{image: bitnami/init:1}]\n      containers: [{image: bitnami/app:1}]\n      ephemeralContainers: [{image: bitnami/debug:1}]\n", 3},
		{"kubernetes unrelated image negative", "deployment.yaml", "kind: Deployment\nspec:\n  image: bitnami/not-a-container:1\n", 0},
		{"flux values and repository", "flux.yaml", "kind: HelmRepository\nspec: {url: https://charts.bitnami.com/bitnami}\n---\nkind: HelmRelease\nspec:\n  chart: {spec: {chart: redis}}\n  values: {image: bitnami/redis:7}\n", 2},
		{"flux unrelated negative", "flux.yaml", "kind: HelmRepository\nspec: {url: https://example.invalid/charts}\n", 0},
		{"argo sources", "argo.yaml", "kind: Application\nspec:\n  sources:\n  - repoURL: https://charts.bitnami.com/bitnami\n    chart: redis\n    helm:\n      values: 'image: bitnami/redis:7'\n      valuesObject: {sidecar: {image: bitnami/nginx:1}}\n", 3},
		{"argo unrelated negative", "argo.yaml", "kind: ApplicationSet\nspec: {template: {spec: {source: {repoURL: https://example.invalid, chart: redis}}}}\n", 0},
		{"kustomize", "kustomization.yaml", "images:\n- name: old\n  newName: bitnami/redis\n  newTag: '7'\n- name: bitnamilegacy/nginx\n  digest: sha256:abc\n", 2},
		{"kustomize extensionless", "Kustomization", "images:\n- name: old\n  newName: bitnami/redis\n  newTag: '7'\n", 1},
		{"kustomize negative", "kustomization.yaml", "images: [{name: example/app, newName: example/new}]\n", 0},
		{"compose", "docker-compose.dev.yml", "services: {db: {image: bitnami/postgresql:16}}\n", 1},
		{"compose unrelated negative", "compose.yaml", "x: {image: bitnami/not-service:1}\n", 0},
		{"actions", ".github/workflows/ci.yml", "jobs:\n  test:\n    container: {image: bitnami/go:1}\n    services: {db: {image: bitnami/postgresql:1}}\n    steps: [{uses: 'docker://bitnami/kubectl:1'}]\n", 3},
		{"actions unrelated negative", ".github/workflows/ci.yml", "env: {image: bitnami/not-container:1}\n", 0},
		{"gitlab", "local.gitlab-ci.yml", "image: {name: bitnami/base:1}\nservices: [bitnami/redis:1, {name: bitnami/nginx:1}]\ndefault: {image: bitnami/default:1}\nbuild: {image: bitnami/job:1}\n", 5},
		{"gitlab unrelated negative", ".gitlab-ci.yml", "variables: {image: bitnami/not-container:1}\n", 0},
		{"azure", "azure-pipelines-ci.yml", "container: bitnami/root:1\nresources: {containers: [{image: bitnami/resource:1}]}\njobs:\n- job: build\n  container: {image: bitnami/job:1}\n  services: {db: bitnami/service:1}\n", 4},
		{"azure unrelated negative", "azure-pipelines.yml", "variables: {image: bitnami/not-container:1}\n", 0},
		{"values variable evidence", "values.yaml", "image: '${REGISTRY}/bitnami/redis:${TAG}'\n", 1},
		{"unrelated yaml negative", "tool.yaml", "settings: {image: bitnami/not-container:1}\n", 0},
		// review 02 F12: an anchor and its alias uses are one finding at the anchor.
		{"alias anchor", "values.yaml", "common: &common\n  image: bitnami/redis:7\nfirst: *common\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := YAML(tt.path, []byte(tt.input))
			if len(got.Findings) != tt.want {
				t.Fatalf("source docs/spec/v0.1.md section 9: got %d findings: %#v", len(got.Findings), got)
			}
		})
	}
}

func TestKustomizeHelmCharts(t *testing.T) {
	type expectedFinding struct {
		rule              string
		line, column      int
		component, impact string
	}
	tests := []struct {
		name, path, input string
		want              []expectedFinding
	}{
		{
			name: "standalone generator dispatches top-level fields",
			path: "helm-chart-inflation-generator.yaml",
			input: "apiVersion: builtin\n" +
				"kind: HelmChartInflationGenerator\n" +
				"metadata: {name: pg}\n" +
				"name: postgresql\n" +
				"repo: https://charts.bitnami.com/bitnami\n" +
				"version: 12.5.6\n" +
				"valuesInline:\n" +
				"  image:\n" +
				"    repository: bitnamilegacy/postgresql\n" +
				"    tag: 16.4.0\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 5, column: 7, component: "postgresql", impact: string(diag.ImpactHigh)},
				{rule: "DSD-IMG-001", line: 9, column: 17, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "bitnami https repo and inline image",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami\n" +
				"    version: 12.5.6\n" +
				"    valuesInline:\n" +
				"      image:\n" +
				"        repository: bitnamilegacy/postgresql\n" +
				"        tag: 16.4.0\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
				{rule: "DSD-IMG-001", line: 7, column: 21, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "bitnami oci repo",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: oci://registry-1.docker.io/bitnamicharts\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "repo with trailing slash",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami/\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "standalone generator without name",
			path: "generator.yaml",
			input: "kind: HelmChartInflationGenerator\n" +
				"repo: https://charts.bitnami.com/bitnami\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 2, column: 7, component: "", impact: string(diag.ImpactUnknown)},
			},
		},
		{
			name: "multiple helmCharts entries",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami\n" +
				"  - name: nginx\n" +
				"    repo: oci://registry-1.docker.io/bitnamicharts\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
				{rule: "DSD-CHT-001", line: 5, column: 11, component: "nginx", impact: string(diag.ImpactLow)},
			},
		},
		{
			name: "image triple nested under non-image key",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami\n" +
				"    valuesInline:\n" +
				"      primary:\n" +
				"        repository: bitnamilegacy/postgresql\n" +
				"        tag: 16.4.0\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
				{rule: "DSD-IMG-001", line: 6, column: 21, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "anchor and alias in valuesInline",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami\n" +
				"    valuesInline:\n" +
				"      base: &pg\n" +
				"        repository: bitnamilegacy/postgresql\n" +
				"        tag: 16.4.0\n" +
				"      primary: *pg\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
				{rule: "DSD-IMG-001", line: 6, column: 21, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
		{
			name: "non-bitnami generator negative",
			path: "generator.yaml",
			input: "kind: HelmChartInflationGenerator\n" +
				"name: postgresql\n" +
				"repo: https://charts.example.invalid/postgresql\n",
		},
		{
			name: "other kind uses generic chart fallback only",
			path: "generator.yaml",
			input: "kind: NotTheGenerator\n" +
				"name: postgresql\n" +
				"repo: https://charts.bitnami.com/bitnami\n" +
				"valuesInline:\n" +
				"  image: bitnamilegacy/postgresql:16.4.0\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 7, component: "", impact: string(diag.ImpactUnknown)},
			},
		},
		{
			name: "commented generator fields negative",
			path: "generator.yaml",
			input: "kind: HelmChartInflationGenerator\n" +
				"name: postgresql\n" +
				"# repo: https://charts.bitnami.com/bitnami\n",
		},
		{
			name: "non-bitnami repo negative",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.example.invalid/postgresql\n",
		},
		{
			name: "local chart without repo negative",
			input: "helmCharts:\n" +
				"  - name: local-app\n",
		},
		{
			name: "commented repo negative",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    # repo: https://charts.bitnami.com/bitnami\n",
		},
		{
			name: "inline values without images",
			input: "helmCharts:\n" +
				"  - name: postgresql\n" +
				"    repo: https://charts.bitnami.com/bitnami\n" +
				"    valuesInline: {replicaCount: 1}\n",
			want: []expectedFinding{
				{rule: "DSD-CHT-001", line: 3, column: 11, component: "postgresql", impact: string(diag.ImpactHigh)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if path == "" {
				path = "kustomization.yaml"
			}
			got := YAML(path, []byte(tt.input))
			if len(got.Findings) != len(tt.want) {
				t.Fatalf("got %d findings, want %d: %#v", len(got.Findings), len(tt.want), got.Findings)
			}
			for _, want := range tt.want {
				found := false
				for _, finding := range got.Findings {
					if finding.RuleID == want.rule &&
						finding.Location.Path == path &&
						finding.Location.Line == want.line &&
						finding.Location.Column == want.column &&
						finding.Component == want.component &&
						string(finding.Impact) == want.impact {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing %#v in %#v", want, got.Findings)
				}
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 (the valuesFile references a
// document declares).
func TestValuesFileRefs(t *testing.T) {
	tests := []struct {
		name, path, input string
		want              []string
	}{
		{"helm chart entry", "kustomization.yaml", "helmCharts:\n- name: postgresql\n  valuesFile: overrides.yaml\n", []string{"overrides.yaml"}},
		{"extensionless kustomization", "Kustomization", "helmCharts:\n- name: postgresql\n  valuesFile: overrides.yaml\n", []string{"overrides.yaml"}},
		{"generator", "generator.yaml", "kind: HelmChartInflationGenerator\nvaluesFile: overrides.yaml\n", []string{"overrides.yaml"}},
		{"helm charts outside a kustomization are no reference", "app.yaml", "helmCharts:\n- name: postgresql\n  valuesFile: overrides.yaml\n", nil},
		{"no values file", "kustomization.yaml", "helmCharts:\n- name: postgresql\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValuesFileRefs(tt.path, []byte(tt.input)).All()
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("source docs/spec/v0.1.md section 9.2: got %v, want %v", got, tt.want)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 (a values file is scanned as chart
// values whatever its name).
func TestHelmValues(t *testing.T) {
	got := HelmValues("overrides.yaml", []byte("image:\n  repository: bitnamilegacy/postgresql\n  tag: '16.4.0'\n"))
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "DSD-IMG-001" {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}
}

func TestDockerfileSources(t *testing.T) {
	input := "ARG REG=docker.io/bitnami\n" +
		"FROM --platform=linux/amd64 ${REG}/redis:7 AS build\n" +
		"COPY --from=bitnami/nginx:1 /x /x\n" +
		"COPY --from=build /x /x\n" +
		"FROM \\\n bitnamilegacy/postgresql:16 AS final\n"
	got := Dockerfile("Dockerfile", []byte(input))
	if len(got.Findings) != 3 {
		t.Fatalf("source https://docs.docker.com/reference/dockerfile/: %#v", got)
	}
	negative := Dockerfile("Dockerfile", []byte("# FROM bitnami/nope:1\nFROM alpine AS bitnami\nCOPY --from=bitnami /x /x\n"))
	if len(negative.Findings) != 0 {
		t.Fatalf("source https://docs.docker.com/reference/dockerfile/: %#v", negative)
	}
}

func FuzzDockerfile(f *testing.F) {
	f.Add([]byte("ARG R=bitnami\nFROM ${R}/redis:7\\\n AS x\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = Dockerfile("Dockerfile", b) })
}
func FuzzYAMLAliasResolver(f *testing.F) {
	f.Add([]byte("x: &x {image: bitnami/redis:7}\ny: *x\n"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = YAML("values.yaml", b) })
}
