package detect

import (
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// Source: docs/spec/v0.1.md section 9.2, benjsicam/nestjs-graphql-microservices
// microservices/posts-svc/.gitlab-ci.yml:120, and
// https://docs.docker.com/reference/cli/docker/container/run/.
func TestShellImageCommands(t *testing.T) {
	tests := []struct {
		name, script  string
		wantRule      string
		wantRef       string
		wantConf      diag.Confidence
		wantComponent string
		wantImpact    diag.Impact
		wantLine      int
		wantColumn    int
	}{
		{
			name:     "corpus docker run with consuming volume option",
			script:   `docker run --rm -v /builds/${CI_PROJECT_PATH}/config:/.kube/config bitnami/kubectl:1.17.4 set image deployment/api api=bitnami/kubectl:1.17.4`,
			wantRule: "DSD-IMG-002", wantRef: "docker.io/bitnami/kubectl:1.17.4",
			wantConf: diag.ConfidenceInferred, wantComponent: "kubectl",
			wantImpact: diag.ImpactLow, wantLine: 120, wantColumn: 68,
		},
		{
			name: "docker image option", script: "docker run --rm --image bitnami/kubectl:1",
			wantRule: "DSD-IMG-002", wantRef: "docker.io/bitnami/kubectl:1",
			wantConf: diag.ConfidenceInferred, wantComponent: "kubectl",
			wantImpact: diag.ImpactLow, wantLine: 1, wantColumn: 25,
		},
		{
			name: "docker build from", script: "docker build --from bitnami/kubectl:1 .",
			wantRule: "DSD-IMG-002", wantRef: "docker.io/bitnami/kubectl:1",
			wantConf: diag.ConfidenceInferred, wantComponent: "kubectl",
			wantImpact: diag.ImpactLow, wantLine: 1, wantColumn: 21,
		},
		{
			name: "templated static namespace stays unresolved", script: "podman run bitnami/kubectl:${TAG}",
			wantRule: "DSD-IMG-002", wantRef: "docker.io/bitnami/kubectl:{{\u2026}}",
			wantConf: diag.ConfidenceUnresolved, wantComponent: "kubectl",
			wantImpact: diag.ImpactLow, wantLine: 1, wantColumn: 12,
		},
		{
			name: "docker run tty flag takes no value", script: "docker run -t bitnami/redis",
			wantRule: "DSD-IMG-003", wantRef: "docker.io/bitnami/redis",
			wantConf: diag.ConfidenceInferred, wantComponent: "redis",
			wantImpact: diag.ImpactHigh, wantLine: 1, wantColumn: 15,
		},
		{
			name: "docker run device option takes a value", script: "docker run --device /dev/fuse bitnami/redis",
			wantRule: "DSD-IMG-003", wantRef: "docker.io/bitnami/redis",
			wantConf: diag.ConfidenceInferred, wantComponent: "redis",
			wantImpact: diag.ImpactHigh, wantLine: 1, wantColumn: 31,
		},
		{
			name: "docker run security option takes a value", script: "docker run --security-opt label=disable bitnami/redis",
			wantRule: "DSD-IMG-003", wantRef: "docker.io/bitnami/redis",
			wantConf: diag.ConfidenceInferred, wantComponent: "redis",
			wantImpact: diag.ImpactHigh, wantLine: 1, wantColumn: 41,
		},
		{
			name: "docker exec env option takes a value", script: "docker exec --env FOO=bar bitnami/redis",
			wantRule: "DSD-IMG-003", wantRef: "docker.io/bitnami/redis",
			wantConf: diag.ConfidenceInferred, wantComponent: "redis",
			wantImpact: diag.ImpactHigh, wantLine: 1, wantColumn: 27,
		},
		{
			name: "docker pull platform option takes a value", script: "docker pull --platform linux/amd64 bitnami/redis",
			wantRule: "DSD-IMG-003", wantRef: "docker.io/bitnami/redis",
			wantConf: diag.ConfidenceInferred, wantComponent: "redis",
			wantImpact: diag.ImpactHigh, wantLine: 1, wantColumn: 36,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings(".gitlab-ci.yml", tt.script, shellOrigin{line: tt.wantLine, column: 1}, nil)
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			if f.RuleID != tt.wantRule || f.Reference != tt.wantRef || f.Confidence != tt.wantConf ||
				f.Component != tt.wantComponent || f.Impact != tt.wantImpact ||
				f.Location.Line != tt.wantLine || f.Location.Column != tt.wantColumn {
				t.Fatalf("source docs/spec/v0.1.md sections 2.1,2.2,9.2: got %#v", f)
			}
			if strings.Contains(f.Reference, "docker run") || strings.Contains(f.Original, "docker run") {
				t.Fatalf("source docs/spec/v0.1.md section 6: command line leaked: %#v", f)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2, SKorolchuk/dpio-platform
// local-baremetal/core/azure-pipelines.yml:24,72, and
// https://helm.sh/docs/helm/helm_repo_add/.
func TestShellHelmCommands(t *testing.T) {
	repoScript := "true && helm repo add bitnami https://charts.bitnami.com/bitnami"
	repoFindings, declared := shellCommandFindings("azure-pipelines.yml", repoScript, shellOrigin{line: 24, column: 1}, nil)
	if len(repoFindings) != 1 || !declared["bitnami"] {
		t.Fatalf("source https://helm.sh/docs/helm/helm_repo_add/: findings=%#v aliases=%v", repoFindings, declared)
	}
	repo := repoFindings[0]
	if repo.RuleID != "DSD-CHT-001" || repo.Confidence != diag.ConfidenceInferred ||
		repo.Reference != "https://charts.bitnami.com/bitnami" ||
		repo.Location.Line != 24 || repo.Location.Column != 31 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", repo)
	}

	upgradeFindings, _ := shellCommandFindings("azure-pipelines.yml",
		"helm upgrade metrics-server-1617042143 bitnami/metrics-server", shellOrigin{line: 72, column: 1},
		map[string]bool{"bitnami": true})
	if len(upgradeFindings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", upgradeFindings)
	}
	upgrade := upgradeFindings[0]
	if upgrade.RuleID != "DSD-CHT-001" || upgrade.Component != "metrics-server" ||
		upgrade.Impact != diag.ImpactMedium || upgrade.Confidence != diag.ConfidenceInferred ||
		upgrade.Reference != "bitnami/metrics-server" || upgrade.Location.Line != 72 {
		t.Fatalf("source docs/spec/v0.1.md sections 2.3,9.2: %#v", upgrade)
	}

	oci, _ := shellCommandFindings("Dockerfile", "helm install db oci://registry-1.docker.io/bitnamicharts/postgresql", shellOrigin{line: 3, column: 5}, nil)
	if len(oci) != 1 || oci[0].RuleID != "DSD-CHT-001" || oci[0].Component != "postgresql" {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", oci)
	}

	setImage, _ := shellCommandFindings("ci.yml", "helm upgrade db bitnami/postgresql --set image.repository=bitnamilegacy/postgresql:16", shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
	if len(setImage) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", setImage)
	}
	found := map[string]bool{}
	for _, f := range setImage {
		found[f.RuleID] = true
	}
	if !found["DSD-CHT-001"] || !found["DSD-IMG-001"] {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", setImage)
	}

	setGuard, _ := shellCommandFindings("ci.yml", "helm upgrade db bitnami/postgresql --set global.security.allowInsecureImages=true", shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
	if len(setGuard) != 2 || !hasRule(setGuard, "DSD-CFG-001") {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", setGuard)
	}

	description, _ := shellCommandFindings("ci.yml", "helm upgrade --description x db bitnami/postgresql", shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
	if len(description) != 1 || description[0].RuleID != "DSD-CHT-001" ||
		description[0].Component != "postgresql" || description[0].Location.Column != 33 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", description)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a pull names the chart first, and a
// global flag before the subcommand does not hide the repository alias.
func TestShellHelmPullAndGlobalFlags(t *testing.T) {
	pull, _ := shellCommandFindings("ci.yml", "helm pull bitnami/postgresql bitnami/redis", shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
	if len(pull) != 1 || pull[0].RuleID != "DSD-CHT-001" || pull[0].Component != "postgresql" {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", pull)
	}

	_, declared := shellCommandFindings("ci.yml", "helm --namespace x repo add bitnami https://charts.bitnami.com/bitnami", shellOrigin{line: 1, column: 1}, nil)
	if !declared["bitnami"] {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: aliases=%v", declared)
	}
}

// Source: docs/spec/v0.1.md section 9.2 negative cases and
// https://docs.docker.com/reference/cli/docker/container/run/.
func TestShellNegativeCommands(t *testing.T) {
	tests := []struct{ name, script string }{
		{"prose after image argument", "docker run busybox echo bitnami/kubectl"},
		{"build tag", "docker build -t bitnami/mycustom ."},
		{"comment", "# docker run bitnami/kubectl"},
		{"echo arguments", `echo "helm repo add bitnami https://charts.bitnami.com/bitnami"`},
		{"printf arguments", `printf '%s\n' "docker run bitnami/kubectl"`},
		{"environment value", "docker run --rm -e BITNAMI_FOO=bitnami/x alpine"},
		{"unproven helm alias", "helm install db bitnami/postgresql"},
		{"non-bitnami chart repository", "helm repo add bitnami https://example.com/charts"},
		{"unknown option value remains non-option", "docker run --unknown-option bitnami-image"},
		{"command substitution is not evaluated", `true $(docker run bitnami/kubectl)`},
		{"backticks are not evaluated", "true `docker run bitnami/kubectl`"},
		{"heredoc body is ignored", "cat <<EOF\ndocker run bitnami/kubectl:1\nEOF\n"},
		{"kubectl run pod name is not an image", "kubectl run bitnami/pod"},
		{"docker build context is not pulled", "docker build bitnami/context"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, nil)
			if len(got) != 0 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2: the tokenizer handles POSIX-like line
// continuations, command separators, quoted arguments and CRLF scripts.
func TestShellScriptShapes(t *testing.T) {
	tests := []struct {
		name, script string
		wantCount    int
		wantLine     int
		wantColumn   int
	}{
		{
			name: "backslash continuation", script: "docker run --rm \\\nbitnami/redis:7",
			wantCount: 1, wantLine: 2, wantColumn: 1,
		},
		{
			name: "semicolon separator", script: "echo hi; docker run bitnami/redis:7",
			wantCount: 1, wantLine: 1, wantColumn: 21,
		},
		{
			name: "pipe separator", script: "cat | docker run bitnami/redis:7",
			wantCount: 1, wantLine: 1, wantColumn: 18,
		},
		{
			name: "double pipe separator", script: "false || docker run bitnami/redis:7",
			wantCount: 1, wantLine: 1, wantColumn: 21,
		},
		{
			name: "double quoted argument", script: `docker run "bitnami/redis:7"`,
			wantCount: 1, wantLine: 1, wantColumn: 12,
		},
		{
			name: "single quoted argument", script: `docker run 'bitnami/redis:7'`,
			wantCount: 1, wantLine: 1, wantColumn: 12,
		},
		{
			name: "crlf script", script: "docker run bitnami/redis:7\r\ndocker run bitnami/redis:8",
			wantCount: 2, wantLine: 1, wantColumn: 12,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, nil)
			if len(got) != tt.wantCount {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
				f.Location.Line != tt.wantLine || f.Location.Column != tt.wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
			}
		})
	}
}

// Source: docs/spec/v0.1.md sections 9,9.2: the shell detector handles the
// script scalars of a CI file only. Any other scalar of the same file still
// falls back to the whole-scalar rule.
func TestShellCIFileKeepsFallbackForOtherScalars(t *testing.T) {
	data := []byte("env:\n  IMAGE: bitnami/kubectl:1\njobs:\n  test:\n    steps:\n      - run: echo hello\n")
	got := YAML(".github/workflows/ci.yml", data)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md sections 9,9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Location.Line != 2 || f.Location.Column != 10 {
		t.Fatalf("source docs/spec/v0.1.md sections 9,9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a block scalar's finding column is
// the first content column of the block, not the column of its | or > marker.
func TestShellBlockScalarOriginColumn(t *testing.T) {
	data := []byte("jobs:\n  test:\n    steps:\n      - run: |\n          docker run bitnami/redis:7\n")
	got := YAML(".github/workflows/ci.yml", data)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	if f := got.Findings[0]; f.Location.Line != 5 || f.Location.Column != 22 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	continued := []byte("jobs:\n  test:\n    steps:\n      - run: |\n          docker run \\\n            bitnami/redis:7\n")
	got = YAML(".github/workflows/ci.yml", continued)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	if f := got.Findings[0]; f.Location.Line != 6 || f.Location.Column != 13 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://docs.docker.com/reference/dockerfile/#run: the BuildKit flags of a
// RUN instruction are not part of the command.
func TestDockerfileRunFlagsAreStripped(t *testing.T) {
	got := Dockerfile("Dockerfile", []byte("RUN --mount=type=cache,target=/x docker run bitnami/redis:7\n"))
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	if f := got.Findings[0]; f.RuleID != "DSD-IMG-002" || f.Location.Line != 1 || f.Location.Column != 45 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	spaced := Dockerfile("Dockerfile", []byte("RUN --mount type=cache,target=/x docker run bitnami/redis:7\n"))
	if len(spaced.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", spaced)
	}
	if f := spaced.Findings[0]; f.Location.Line != 1 || f.Location.Column != 45 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	network := Dockerfile("Dockerfile", []byte("RUN --network=none docker run bitnami/redis:7\n"))
	if len(network.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", network)
	}
	if f := network.Findings[0]; f.Location.Line != 1 || f.Location.Column != 31 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md sections 6,9.2. A script scalar is marked before
// fallback scanning, so ignored prose never becomes a partial-match finding.
func TestShellScriptYAMLWiringAndRedaction(t *testing.T) {
	inline := `.github/workflows/ci.yml`
	data := []byte("jobs:\n  test:\n    steps:\n      - run: docker run bitnami/kubectl:1\n")
	got := YAML(inline, data)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	if f := got.Findings[0]; f.Location.Line != 4 || f.Location.Column != 25 ||
		f.Confidence != diag.ConfidenceInferred || strings.Contains(f.Reference, "run:") {
		t.Fatalf("source docs/spec/v0.1.md sections 6,9.2: %#v", f)
	}

	blocked := `.github/workflows/ci.yml`
	negative := []byte("jobs:\n  test:\n    steps:\n      - run: |\n          # docker run bitnami/kubectl:1\n          echo \"helm repo add bitnami https://charts.bitnami.com/bitnami\"\n          docker run busybox echo bitnami/kubectl\n")
	if report := YAML(blocked, negative); len(report.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", report)
	}
}

// Source: docs/spec/v0.1.md section 9.2 file-wide Helm alias proof.
func TestShellFileWideHelmAlias(t *testing.T) {
	data := []byte(`steps:
- script: "helm repo add bitnami https://charts.bitnami.com/bitnami"
- script: "helm upgrade release bitnami/postgresql"
`)
	got := YAML("azure-pipelines.yml", data)
	if len(got.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	if got.Findings[0].RuleID != "DSD-CHT-001" || got.Findings[1].RuleID != "DSD-CHT-001" ||
		got.Findings[1].Component != "postgresql" {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}
	if got.Findings[0].Location.Column != 34 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2 exact inline column: %#v", got.Findings[0])
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://docs.docker.com/reference/cli/docker/container/run/.
func TestDockerfileRunShellCommands(t *testing.T) {
	got := Dockerfile("Dockerfile", []byte("RUN docker run --rm bitnami/kubectl:1.17.4\n"))
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred ||
		f.Location.Line != 1 || f.Location.Column != 21 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	negative := Dockerfile("Dockerfile", []byte("RUN docker build -t bitnami/mycustom .\n# RUN docker run bitnami/kubectl:1\n"))
	if len(negative.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", negative)
	}
}

func hasRule(findings []diag.Finding, rule string) bool {
	for _, f := range findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func FuzzShellTokenizer(f *testing.F) {
	f.Add("docker run --rm -v /src:/dst bitnami/kubectl:1")
	f.Add("helm repo add bitnami https://charts.bitnami.com/bitnami")
	f.Add("echo \"docker run bitnami/kubectl\" && cat <<EOF\nbitnami/x\nEOF\n")
	f.Add("`docker run bitnami/kubectl`")
	f.Fuzz(func(t *testing.T, script string) {
		tokens := tokenizeShell(script)
		if len(tokens) > 2*len(script)+2 {
			t.Fatalf("tokenizer output is not linearly bounded: input=%d tokens=%d", len(script), len(tokens))
		}
		valueBytes := 0
		for _, token := range tokens {
			valueBytes += len(token.value)
			if token.line < 1 || token.column < 1 {
				t.Fatalf("invalid token position: %#v", token)
			}
		}
		if valueBytes > len(script)+len(tokens) {
			t.Fatalf("tokenizer memory is not bounded by input: input=%d values=%d", len(script), valueBytes)
		}
	})
}
