package detect

import (
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"gopkg.in/yaml.v3"
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

// Source: docs/spec/v0.1.md section 9.2: the text of a block scalar is
// rebuilt exactly as YAML folds it, so the position of every character of the
// script is exact.
func TestShellBlockContentMatchesYAML(t *testing.T) {
	cases := []string{
		"key: |\n  line1\n  line2\n",
		"key: |-\n  line1\n  line2\n",
		"key: |+\n  line1\n\n",
		"key: |\n  line1\n\n  line2\n",
		"key: |\n  line1\n  line2",
		"key: |\r\n  line1\r\n",
		"key: >\n  line1\n  line2\n",
		"key: >-\n  line1\n  line2\n",
		"key: >\n  line1\n\n  line2\n",
		"key: >-\n  line1\n    more\n  line2\n",
		"key: >-\n  line1\n  line2\n  line3\n",
		"key: >2\n  line1\n  line2\n",
		"key: |2-\n  line1\n",
		"key: |2\n    more\n  normal\n",
		"key: >2\n    more\n  normal\n",
		"key: >+2\n    more\n  normal\n\n",
		"steps:\n- script: |2\n      more\n    normal\n",
		"steps:\n- script: >2\n      more\n    normal\n",
		"key:\n  sub: |\n    line1\n",
		"key: >- # comment\n  line1\n",
	}
	for _, data := range cases {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(data), &doc); err != nil {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %q: %v", data, err)
		}
		var target *yaml.Node
		var walk func(n *yaml.Node)
		walk = func(n *yaml.Node) {
			if n.Kind == yaml.ScalarNode && (n.Style == yaml.LiteralStyle || n.Style == yaml.FoldedStyle) {
				target = n
			}
			for _, child := range n.Content {
				walk(child)
			}
		}
		walk(doc.Content[0])
		if target == nil {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %q: no block scalar", data)
		}
		scan := &shellScriptScan{data: []byte(data)}
		text, positions, ok := scan.blockContent(target)
		if !ok {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %q: no reconstruction", data)
		}
		if text != target.Value {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %q: got %q want %q", data, text, target.Value)
		}
		if len(positions) != len(text) {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %q: %d positions for %d characters", data, len(positions), len(text))
		}
	}
}

// Source: docs/spec/v0.1.md section 9.2: a folded block scalar replaces the
// line breaks of the source by spaces, so the finding must land on the line
// and the column of the token in the source, not on the first line of the
// folded text. Shape source: SKorolchuk/dpio-platform
// local-baremetal/core/azure-pipelines.yml:24.
func TestShellFoldedBlockScalarPosition(t *testing.T) {
	data := []byte("steps:\n- script: >-\n    set -e\n    set -x\n    true && helm repo add bitnami https://charts.bitnami.com/bitnami\n")
	got := YAML("azure-pipelines.yml", data)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-CHT-001" || f.Reference != "https://charts.bitnami.com/bitnami" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	// The URL is on the fifth line of the file, at the thirty-fifth column.
	if f.Location.Line != 5 || f.Location.Column != 35 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a literal block scalar keeps the
// line breaks of the source, so its findings keep their line.
func TestShellLiteralBlockScalarPosition(t *testing.T) {
	data := []byte("steps:\n- script: |\n    set -e\n    true && helm repo add bitnami https://charts.bitnami.com/bitnami\n")
	got := YAML("azure-pipelines.yml", data)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-CHT-001" || f.Reference != "https://charts.bitnami.com/bitnami" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 4 || f.Location.Column != 35 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a column counts the characters of a
// line, not its bytes, like the rest of the scanner, so a multibyte character
// before a token does not shift its column.
func TestShellMultibyteColumns(t *testing.T) {
	folded := []byte("steps:\n- script: >-\n    echo \"héllo\" && docker run bitnami/redis:7\n")
	got := YAML("azure-pipelines.yml", folded)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	// The token is on the third line, at the thirty-second column: the
	// accented letter is one character, not two bytes.
	if f.Location.Line != 3 || f.Location.Column != 32 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	literal := []byte("steps:\n- script: |\n    echo \"héllo\" && docker run bitnami/redis:7\n")
	got = YAML("azure-pipelines.yml", literal)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 3 || f.Location.Column != 32 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: an explicit indentation indicator
// fixes the indentation of a block scalar to the indentation of its parent
// node plus the indicator, so a first line that is more indented than the
// block does not end it.
func TestShellBlockIndicatorIndent(t *testing.T) {
	literal := []byte("steps:\n- script: |2\n      set -e\n    docker run bitnami/redis:7\n")
	got := YAML("azure-pipelines.yml", literal)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	// The block is indented by four columns, so the token is at the
	// sixteenth column of the fourth line.
	if f.Location.Line != 4 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	folded := []byte("steps:\n- script: >2\n      set -e\n    docker run bitnami/redis:7\n")
	got = YAML("azure-pipelines.yml", folded)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 4 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a plain, single-quoted or
// double-quoted scalar has no position table, so every one of its tokens is
// reported on the line of the scalar.
func TestShellFlatScalarPositions(t *testing.T) {
	quoted := []byte("steps:\n- script: \"docker run bitnami/redis:7\\ndocker run bitnami/redis:8\"\n")
	got := YAML("azure-pipelines.yml", quoted)
	if len(got.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	for _, f := range got.Findings {
		if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
		}
		// The second command is on the second line of the scalar, but the
		// scalar has no position table: both are on the line of the scalar.
		if f.Location.Line != 2 || f.Location.Column != 23 {
			t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
		}
	}

	plain := []byte("steps:\n- script: docker run\n    bitnami/redis:7\n")
	got = YAML("azure-pipelines.yml", plain)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 2 || f.Location.Column != 22 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	single := []byte("steps:\n- script: 'docker run\n    bitnami/redis:7'\n")
	got = YAML("azure-pipelines.yml", single)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 2 || f.Location.Column != 23 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: the whitespace of a block scalar is
// part of its content, so it never moves the position of a token.
func TestShellBlockScalarWhitespace(t *testing.T) {
	trailing := []byte("steps:\n- script: |\n    docker run bitnami/redis:7   \n")
	got := YAML("azure-pipelines.yml", trailing)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 3 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	tab := []byte("steps:\n- script: |\n    docker run\tbitnami/redis:7\n")
	got = YAML("azure-pipelines.yml", tab)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 3 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	keep := []byte("steps:\n- script: >+2\n      set -e\n    docker run bitnami/redis:7\n\n")
	got = YAML("azure-pipelines.yml", keep)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 4 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a CRLF script keeps the position of
// every command.
func TestShellCRLFPositions(t *testing.T) {
	script := "docker run bitnami/redis:7\r\ndocker run bitnami/redis:8"
	got, _ := shellCommandFindings("ci.yml", script, shellOrigin{line: 1, column: 1}, nil)
	if len(got) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	first := got[0]
	if first.RuleID != "DSD-IMG-002" || first.Reference != "docker.io/bitnami/redis:7" ||
		first.Confidence != diag.ConfidenceInferred ||
		first.Location.Line != 1 || first.Location.Column != 12 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", first)
	}
	second := got[1]
	if second.RuleID != "DSD-IMG-002" || second.Reference != "docker.io/bitnami/redis:8" ||
		second.Confidence != diag.ConfidenceInferred ||
		second.Location.Line != 2 || second.Location.Column != 12 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", second)
	}

	data := []byte("steps:\r\n- script: |\r\n    docker run bitnami/redis:7\r\n")
	block := YAML("azure-pipelines.yml", data)
	if len(block.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", block)
	}
	f := block.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 3 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://helm.sh/docs/helm/helm_install/: a value-taking flag consumes its
// value, a boolean flag does not, so the chart behind it is still found.
func TestShellHelmValueFlags(t *testing.T) {
	tests := []struct {
		name, script string
		wantRef      string
		wantComp     string
	}{
		{name: "values file", script: "helm install -f values.yaml db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "values flag", script: "helm install --values values.yaml db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "namespace", script: "helm install --namespace prod db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "namespace short", script: "helm install -n prod db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube context", script: "helm install --kube-context ctx db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kubeconfig", script: "helm install --kubeconfig /tmp/kube db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "description", script: "helm upgrade --description release db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "timeout", script: "helm install --timeout 5m db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "version", script: "helm pull bitnami/postgresql --version 1.2.3", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "repo", script: "helm pull bitnami/postgresql --repo https://charts.bitnami.com/bitnami", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "set", script: "helm install --set image.tag=1 db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "set string", script: "helm install --set-string image.tag=1 db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "post renderer", script: "helm install --post-renderer ./render.sh db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "ca file", script: "helm install --ca-file /tmp/ca.pem db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "cert file", script: "helm install --cert-file /tmp/cert.pem db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "key file", script: "helm install --key-file /tmp/key.pem db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "keyring", script: "helm install --keyring /tmp/ring db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "destination", script: "helm pull bitnami/postgresql --destination /tmp", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "name template", script: "helm install --name-template generated db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "name template upgrade", script: "helm upgrade --name-template generated db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "name template template", script: "helm template --name-template generated db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "username", script: "helm repo add --username helm bitnami https://charts.bitnami.com/bitnami", wantRef: "https://charts.bitnami.com/bitnami"},
		{name: "password", script: "helm repo add --password secret bitnami https://charts.bitnami.com/bitnami", wantRef: "https://charts.bitnami.com/bitnami"},
		{name: "atomic flag", script: "helm install --atomic db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "create namespace flag", script: "helm install --create-namespace db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "wait flag", script: "helm install --wait db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "devel flag", script: "helm pull bitnami/postgresql --devel", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "take ownership flag", script: "helm upgrade --take-ownership db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			wantColumn := strings.Index(tt.script, tt.wantRef) + 1
			if f.RuleID != "DSD-CHT-001" || f.Reference != tt.wantRef || f.Component != tt.wantComp ||
				f.Confidence != diag.ConfidenceInferred ||
				f.Location.Line != 1 || f.Location.Column != wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v want column %d", f, wantColumn)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2: a shell variable is never resolved,
// so a Bitnami reference that is only reachable through a variable is not
// reported by this detector.
func TestShellVariablesAreNotResolved(t *testing.T) {
	tests := []struct{ name, script string }{
		{"variable", "IMAGE=bitnami/kubectl:1.17.4\ndocker run $IMAGE"},
		{"braced variable", "IMAGE=bitnami/kubectl:1.17.4\ndocker run ${IMAGE}"},
		{"command substitution", "IMAGE=$(echo bitnami/kubectl:1)\ndocker run $IMAGE"},
		{"function", "image() { echo bitnami/kubectl:1; }\ndocker run $IMAGE"},
		{"alias", "alias IMAGE='bitnami/kubectl:1'\ndocker run $IMAGE"},
		{"single quoted variable", "docker run '$IMAGE'"},
		{"not a bitnami literal", "IMAGE=alpine:3\ndocker run $IMAGE"},
		{"used before the assignment", "docker run $IMAGE\nIMAGE=bitnami/kubectl:1"},
		{"stale value", "IMAGE=bitnami/kubectl:1\nIMAGE=alpine:3\ndocker run $IMAGE"},
		{"chart variable", "CHART=bitnami/postgresql\nhelm install db $CHART"},
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

// Source: docs/spec/v0.1.md section 9.2: a reference that is literally present
// is still reported, and the whole-scalar fallback does not report a script
// scalar.
func TestShellLiteralReferenceIsStillReported(t *testing.T) {
	got, _ := shellCommandFindings("ci.yml", "IMAGE=bitnami/kubectl:1\ndocker run bitnami/redis:7", shellOrigin{line: 1, column: 1}, nil)
	if len(got) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
		f.Confidence != diag.ConfidenceInferred || f.Location.Line != 2 || f.Location.Column != 12 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	fallback := []byte("jobs:\n  test:\n    steps:\n      - run: bitnami/kubectl:1.17.4\n")
	if report := YAML(".github/workflows/ci.yml", fallback); len(report.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md sections 9,9.2: %#v", report.Findings)
	}
}

// Source: docs/spec/v0.1.md section 9.2: only the positions the CI system
// defines hold scripts, so an input named run is never a script.
func TestShellCollectPositions(t *testing.T) {
	withRun := []byte("jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          run: docker run bitnami/kubectl:1\n")
	if got := YAML(".github/workflows/ci.yml", withRun); len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	rootRun := []byte("run: docker run bitnami/kubectl:1\njobs:\n  test:\n    steps:\n      - run: echo hello\n")
	if got := YAML(".github/workflows/ci.yml", rootRun); len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	nested := []byte("variables:\n  script: docker run bitnami/kubectl:1\nbuild:\n  script:\n    - docker run bitnami/kubectl:1\n")
	got := YAML(".gitlab-ci.yml", nested)
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 5 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	gitlab := []byte("build:\n  before_script:\n    - docker run bitnami/kubectl:1\n  after_script:\n    - docker run bitnami/kubectl:2\n")
	got = YAML(".gitlab-ci.yml", gitlab)
	if len(got.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	azure := []byte("steps:\n  - bash: docker run bitnami/kubectl:1\n  - powershell: docker run bitnami/kubectl:2\n  - pwsh: docker run bitnami/kubectl:3\n")
	got = YAML("azure-pipelines.yml", azure)
	if len(got.Findings) != 3 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	azureJobs := []byte("jobs:\n  - job: build\n    steps:\n      - script: docker run bitnami/kubectl:1\n")
	got = YAML("azure-pipelines.yml", azureJobs)
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 4 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}
}

// Source: docs/spec/v0.1.md section 9.2: a standard Azure Pipelines file
// nests its steps in stages and jobs, and a YAML alias to a steps list or to
// a script is resolved.
func TestShellAzureStagesAndAliases(t *testing.T) {
	stages := []byte("stages:\n- stage: build\n  jobs:\n  - job: test\n    steps:\n    - script: docker run bitnami/kubectl:1\n")
	got := YAML("azure-pipelines.yml", stages)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/kubectl:1" ||
		f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 6 || f.Location.Column != 26 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	aliasSteps := []byte("common: &common\n  - script: docker run bitnami/kubectl:1\nsteps: *common\n")
	got = YAML("azure-pipelines.yml", aliasSteps)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	if f.Location.Line != 2 || f.Location.Column != 24 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	aliasScript := []byte("steps:\n- script: &s docker run bitnami/kubectl:1\n- script: *s\n")
	got = YAML("azure-pipelines.yml", aliasScript)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	// The anchor is at the eleventh column, like every column of the
	// scanner, and the token is the eleventh character of the command.
	if f.Location.Line != 2 || f.Location.Column != 22 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}

	gitlabAlias := []byte("common: &common\n  - docker run bitnami/kubectl:1\njob:\n  script: *common\n")
	got = YAML(".gitlab-ci.yml", gitlabAlias)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got)
	}
	f = got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Confidence != diag.ConfidenceInferred {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
	// The alias and its anchor are one logical reference, reported once at
	// the anchor (spec section 5).
	if f.Location.Line != 2 || f.Location.Column != 16 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://docs.docker.com/reference/cli/docker/container/run/: a value-taking
// option consumes its value, a boolean option does not, so the image behind
// it is still found.
func TestShellDockerValueFlags(t *testing.T) {
	tests := []struct{ name, script string }{
		{"attach", "docker run --attach stdout bitnami/redis:7"},
		{"attach short", "docker run -a stdout bitnami/redis:7"},
		{"cpu shares", "docker run --cpu-shares 512 bitnami/redis:7"},
		{"cpu shares short", "docker run -c 512 bitnami/redis:7"},
		{"memory", "docker run --memory 512m bitnami/redis:7"},
		{"memory short", "docker run -m 512m bitnami/redis:7"},
		{"cgroupns", "docker run --cgroupns private bitnami/redis:7"},
		{"detach keys", "docker run --detach-keys ctrl-p bitnami/redis:7"},
		{"domainname", "docker run --domainname example.com bitnami/redis:7"},
		{"label file", "docker run --label-file labels.txt bitnami/redis:7"},
		{"memory swappiness", "docker run --memory-swappiness 0 bitnami/redis:7"},
		{"network alias", "docker run --net host bitnami/redis:7"},
		{"ip", "docker run --ip 10.0.0.1 bitnami/redis:7"},
		{"ip6", "docker run --ip6 ::1 bitnami/redis:7"},
		{"health start period", "docker run --health-start-period 30s bitnami/redis:7"},
		{"health start interval", "docker run --health-start-interval 5s bitnami/redis:7"},
		{"isolation", "docker run --isolation default bitnami/redis:7"},
		{"rm flag", "docker run --rm bitnami/redis:7"},
		{"detach flag", "docker run -d bitnami/redis:7"},
		{"interactive flag", "docker run -i bitnami/redis:7"},
		{"tty flag", "docker run -t bitnami/redis:7"},
		{"init flag", "docker run --init bitnami/redis:7"},
		{"read only flag", "docker run --read-only bitnami/redis:7"},
		{"privileged flag", "docker run --privileged bitnami/redis:7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, nil)
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			wantColumn := strings.Index(tt.script, "bitnami/redis:7") + 1
			if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
				f.Confidence != diag.ConfidenceInferred ||
				f.Location.Line != 1 || f.Location.Column != wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v want column %d", f, wantColumn)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2: an anchor that references itself
// ends the traversal: the scan terminates and reports nothing, instead of
// overflowing the stack.
func TestShellAzureCycleTerminates(t *testing.T) {
	jobCycle := []byte("jobs: &jobs\n  - job: loop\n    jobs: *jobs\n")
	got := YAML("azure-pipelines.yml", jobCycle)
	if len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	stageCycle := []byte("stages: &stages\n  - stage: loop\n    stages: *stages\n")
	got = YAML("azure-pipelines.yml", stageCycle)
	if len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	stepCycle := []byte("steps: &steps\n  - script: docker run bitnami/redis:7\n    steps: *steps\n")
	got = YAML("azure-pipelines.yml", stepCycle)
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 2 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}

	jobStageCycle := []byte("stages:\n- stage: loop\n  jobs: &jobs\n  - job: loop\n    jobs: *jobs\n")
	got = YAML("azure-pipelines.yml", jobStageCycle)
	if len(got.Findings) != 0 {
		t.Fatalf("source docs/spec/v0.1.md section 9.2: %#v", got.Findings)
	}
}

// Source: docs/spec/v0.1.md sections 5,9.2: a script a job inherits through a
// merge key is the anchored script: one finding, at the anchor.
func TestShellGitLabMergeKeyScript(t *testing.T) {
	one := []byte(".base: &base\n  script: docker run bitnami/redis:7\njob:\n  <<: *base\n")
	got := YAML(".gitlab-ci.yml", one)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md sections 5,9.2: %#v", got.Findings)
	}
	f := got.Findings[0]
	if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" {
		t.Fatalf("source docs/spec/v0.1.md sections 5,9.2: %#v", f)
	}
	// The script is the anchored one, at the second line and at the
	// column of the image, not at the position of the merge key.
	if f.Location.Line != 2 || f.Location.Column != 22 {
		t.Fatalf("source docs/spec/v0.1.md sections 5,9.2: %#v", f)
	}

	two := []byte(".base: &base\n  script: docker run bitnami/redis:7\none:\n  <<: *base\ntwo:\n  <<: *base\n")
	got = YAML(".gitlab-ci.yml", two)
	if len(got.Findings) != 1 {
		t.Fatalf("source docs/spec/v0.1.md sections 5,9.2: %#v", got.Findings)
	}
	f = got.Findings[0]
	if f.Location.Line != 2 || f.Location.Column != 22 {
		t.Fatalf("source docs/spec/v0.1.md sections 5,9.2: %#v", f)
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://docs.docker.com/reference/cli/docker/container/run/: every
// value-taking option of `docker run` and `docker create` consumes its value,
// so the image behind it is still found.
func TestShellDockerValueFlagsComplete(t *testing.T) {
	tests := []struct{ name, script string }{
		{"cpu rt period", "docker run --cpu-rt-period 100000 bitnami/redis:7"},
		{"cpu rt runtime", "docker run --cpu-rt-runtime 950000 bitnami/redis:7"},
		{"device read bps", "docker run --device-read-bps 10m bitnami/redis:7"},
		{"device read iops", "docker run --device-read-iops 100 bitnami/redis:7"},
		{"device write bps", "docker run --device-write-bps 10m bitnami/redis:7"},
		{"device write iops", "docker run --device-write-iops 100 bitnami/redis:7"},
		{"umask", "docker run --umask 0022 bitnami/redis:7"},
		{"io maxbandwidth", "docker run --io-maxbandwidth 1m bitnami/redis:7"},
		{"io maxiops", "docker run --io-maxiops 100 bitnami/redis:7"},
		{"volume driver", "docker run --volume-driver local bitnami/redis:7"},
		{"blkio weight", "docker run --blkio-weight 300 bitnami/redis:7"},
		{"blkio weight device", "docker run --blkio-weight-device /dev/sda:300 bitnami/redis:7"},
		{"cidfile", "docker run --cidfile /tmp/id bitnami/redis:7"},
		{"cpu quota", "docker run --cpu-quota 50000 bitnami/redis:7"},
		{"cgroup parent", "docker run --cgroup-parent /docker bitnami/redis:7"},
		{"cap add", "docker run --cap-add NET_ADMIN bitnami/redis:7"},
		{"dns search", "docker run --dns-search example.com bitnami/redis:7"},
		{"expose", "docker run --expose 6379 bitnami/redis:7"},
		{"group add", "docker run --group-add 1000 bitnami/redis:7"},
		{"health retries", "docker run --health-retries 3 bitnami/redis:7"},
		{"health timeout", "docker run --health-timeout 5s bitnami/redis:7"},
		{"link local ip", "docker run --link-local-ip 169.254.1.1 bitnami/redis:7"},
		{"log opt", "docker run --log-opt max-size=10m bitnami/redis:7"},
		{"mac address", "docker run --mac-address 02:42:ac:11:00:02 bitnami/redis:7"},
		{"memory reservation", "docker run --memory-reservation 128m bitnami/redis:7"},
		{"memory swap", "docker run --memory-swap 1g bitnami/redis:7"},
		{"oom score adj", "docker run --oom-score-adj 500 bitnami/redis:7"},
		{"pids limit", "docker run --pids-limit 100 bitnami/redis:7"},
		{"stop signal", "docker run --stop-signal SIGTERM bitnami/redis:7"},
		{"stop timeout", "docker run --stop-timeout 30 bitnami/redis:7"},
		{"sysctl", "docker run --sysctl net.core.somaxconn=1024 bitnami/redis:7"},
		{"ulimit", "docker run --ulimit nofile=1024:1024 bitnami/redis:7"},
		{"volumes from", "docker run --volumes-from other bitnami/redis:7"},
		{"create with options", "docker create --cpu-rt-period 100000 bitnami/redis:7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, nil)
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			wantColumn := strings.Index(tt.script, "bitnami/redis:7") + 1
			if f.RuleID != "DSD-IMG-002" || f.Reference != "docker.io/bitnami/redis:7" ||
				f.Confidence != diag.ConfidenceInferred ||
				f.Location.Line != 1 || f.Location.Column != wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v want column %d", f, wantColumn)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 and
// https://docs.docker.com/reference/cli/docker/container/run/: a boolean
// option never consumes a value, and an option that is in neither table
// consumes a number, so the image behind it is still found.
func TestShellDockerBooleanAndUnknownOptions(t *testing.T) {
	tests := []struct {
		name, script string
		wantCount    int
	}{
		{"no healthcheck", "docker run --no-healthcheck bitnami/redis:7", 1},
		{"publish all", "docker run --publish-all bitnami/redis:7", 1},
		{"oom kill disable", "docker run --oom-kill-disable bitnami/redis:7", 1},
		{"sig proxy", "docker run --sig-proxy bitnami/redis:7", 1},
		{"disable content trust", "docker run --disable-content-trust bitnami/redis:7", 1},
		{"quiet", "docker run -q bitnami/redis:7", 1},
		{"unknown option with a number", "docker run --future-option 100000 bitnami/redis:7", 1},
		{"unknown option with a unit", "docker run --future-option 100m bitnami/redis:7", 1},
		{"unknown option with a word", "docker run --future-option value bitnami/redis:7", 0},
		{"boolean option keeps no value", "docker run --rm 100000 bitnami/redis:7", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, nil)
			if len(got) != tt.wantCount {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 and https://helm.sh/docs/helm/: every
// value-taking option of the helm commands consumes its value, a boolean one
// does not, so the chart behind it is still found.
func TestShellHelmValueFlagsComplete(t *testing.T) {
	tests := []struct {
		name, script string
		wantRef      string
		wantComp     string
	}{
		{name: "history max", script: "helm upgrade --history-max 10 db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube apiserver", script: "helm upgrade --kube-apiserver https://api.example.com db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube token", script: "helm upgrade --kube-token secret db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube as user", script: "helm upgrade --kube-as-user alice db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube as group", script: "helm upgrade --kube-as-group dev db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube ca file", script: "helm upgrade --kube-ca-file /tmp/ca.pem db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "kube tls server name", script: "helm upgrade --kube-tls-server-name api db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "output short", script: "helm template -o yaml db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "labels short", script: "helm template -l team=infra db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "repository cache", script: "helm template --repository-cache /tmp/cache db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "repository cache global", script: "helm --repository-cache /tmp/cache template db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "dry run with a mode", script: "helm upgrade --dry-run server db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "dry run without a mode", script: "helm upgrade --dry-run db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "show only short", script: "helm template -s templates/deployment.yaml db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "api versions short", script: "helm template -a apps/v1 db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "boolean before the release name", script: "helm upgrade --atomic db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "release name flag", script: "helm template --release-name db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "boolean install", script: "helm install -i db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
		{name: "global debug flag", script: "helm --debug template db bitnami/postgresql", wantRef: "bitnami/postgresql", wantComp: "postgresql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			wantColumn := strings.Index(tt.script, tt.wantRef) + 1
			if f.RuleID != "DSD-CHT-001" || f.Reference != tt.wantRef || f.Component != tt.wantComp ||
				f.Confidence != diag.ConfidenceInferred ||
				f.Location.Line != 1 || f.Location.Column != wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v want column %d", f, wantColumn)
			}
		})
	}
}

// Source: docs/spec/v0.1.md section 9.2 and https://helm.sh/docs/helm/: the
// template and the install commands have their own options, and a boolean
// one never consumes a value.
func TestShellHelmCommandOptions(t *testing.T) {
	tests := []struct {
		name, script string
		wantRef      string
	}{
		{name: "template include crds", script: "helm template --include-crds db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "template validate", script: "helm template --validate db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "template is upgrade", script: "helm template --is-upgrade db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "template kube version", script: "helm template --kube-version 1.29.0 db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "template output dir", script: "helm template --output-dir /tmp/out db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "install dependency update", script: "helm install --dependency-update db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "install cleanup on fail", script: "helm install --cleanup-on-fail db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "install enable dns", script: "helm install --enable-dns db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "install hide notes", script: "helm install --hide-notes db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "upgrade reuse values", script: "helm upgrade --reuse-values db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "upgrade reset then reuse", script: "helm upgrade --reset-then-reuse-values db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "upgrade render subchart notes", script: "helm upgrade --render-subchart-notes db bitnami/postgresql", wantRef: "bitnami/postgresql"},
		{name: "upgrade pass credentials", script: "helm upgrade --pass-credentials db bitnami/postgresql", wantRef: "bitnami/postgresql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := shellCommandFindings("ci.yml", tt.script, shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
			if len(got) != 1 {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v", got)
			}
			f := got[0]
			wantColumn := strings.Index(tt.script, tt.wantRef) + 1
			if f.RuleID != "DSD-CHT-001" || f.Reference != tt.wantRef ||
				f.Location.Line != 1 || f.Location.Column != wantColumn {
				t.Fatalf("source docs/spec/v0.1.md section 9.2: got %#v want column %d", f, wantColumn)
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
	f.Add("docker run --cpu-rt-period 100000 bitnami/redis:7")
	f.Add("docker run --umask 0022 --device-read-bps 10m bitnami/redis:7")
	f.Add("helm upgrade --atomic --history-max 10 db bitnami/postgresql")
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
		// The analyzer of a command line never panics and never loops on
		// the options it does not know.
		findings, _ := shellCommandFindings("ci.yml", script, shellOrigin{line: 1, column: 1}, map[string]bool{"bitnami": true})
		for _, finding := range findings {
			if finding.Location.Line < 1 || finding.Location.Column < 1 {
				t.Fatalf("invalid finding position: %#v", finding)
			}
		}
	})
}
