package detect

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

const providerDocs = "https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release"

// terraformWant is one expected finding. at is the text whose position the
// finding must carry: the reference itself, so the expectation states the
// position without counting columns by hand.
type terraformWant struct {
	rule       string
	severity   diag.Severity
	confidence diag.Confidence
	at         string
}

// terraformWantDiagnostic is one expected diagnostic.
type terraformWantDiagnostic struct {
	code string
	at   string
}

// terraformPosition returns the one-based line and column of the first
// occurrence of needle in source.
func terraformPosition(t *testing.T, source, needle string) (int, int) {
	t.Helper()
	index := strings.Index(source, needle)
	if index < 0 {
		t.Fatalf("source %s: %q not found in the scanned text", providerDocs, needle)
	}
	line := strings.Count(source[:index], "\n") + 1
	column := index - strings.LastIndex(source[:index], "\n")
	return line, column
}

// terraformFindings returns the findings of a report, ordered by position.
func terraformFindings(r diag.Report) []terraformFinding {
	out := make([]terraformFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, terraformFinding{rule: f.RuleID, severity: f.Severity, confidence: f.Confidence, line: f.Location.Line, column: f.Location.Column})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		if out[i].column != out[j].column {
			return out[i].column < out[j].column
		}
		return out[i].rule < out[j].rule
	})
	return out
}

type terraformFinding struct {
	rule       string
	severity   diag.Severity
	confidence diag.Confidence
	line       int
	column     int
}

func TestTerraformHelmRelease(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		findings    []terraformWant
		diagnostics []terraformWantDiagnostic
	}{
		{
			name:  "repository literal",
			input: "resource \"helm_release\" \"db\" {\n  repository = \"https://charts.bitnami.com/bitnami\"\n  chart      = \"postgresql\"\n}",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceConfirmed, at: "\"https://charts.bitnami.com/bitnami"},
			},
		},
		{
			name:  "oci chart literal",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/bitnamicharts/redis\" }",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceConfirmed, at: "\"oci://registry-1.docker.io/bitnamicharts/redis"},
			},
		},
		{
			name:  "oci chart literal with a tag",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/bitnamicharts/redis:1.2.3\" }",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceConfirmed, at: "\"oci://registry-1.docker.io/bitnamicharts/redis:1.2.3"},
			},
		},
		{
			name:  "oci chart of another project is not a Bitnami chart",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/my-bitnamicharts-fork/redis\" }",
		},
		{
			name:  "yamlencode image",
			input: "resource \"helm_release\" \"db\" { values = [yamlencode({ image = { repository = \"bitnamilegacy/postgresql\" } })] }",
			findings: []terraformWant{
				{rule: "DSD-IMG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "\"bitnamilegacy/postgresql"},
			},
		},
		{
			name:  "heredoc image",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    image:\n      repository: bitnamilegacy/postgresql\n  EOT\n]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "bitnamilegacy/postgresql"},
			},
		},
		{
			name:  "set image",
			input: "resource \"helm_release\" \"db\" {\n  set {\n    name  = \"image.repository\"\n    value = \"bitnamilegacy/postgresql\"\n  }\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "\"bitnamilegacy/postgresql"},
			},
		},
		{
			name:  "set allow insecure",
			input: "resource \"helm_release\" \"db\" {\n  set {\n    name  = \"global.security.allowInsecureImages\"\n    value = \"true\"\n  }\n}",
			findings: []terraformWant{
				{rule: "DSD-CFG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "\"true\""},
			},
		},
		{
			name:  "non-bitnami repository",
			input: "resource \"helm_release\" \"db\" {\n  repository = \"https://charts.example.invalid\"\n  chart      = \"postgresql\"\n}",
		},
		{
			name:  "local chart without repository",
			input: "resource \"helm_release\" \"db\" { chart = \"postgresql\" }",
		},
		{
			name:        "repository variable is unresolved",
			input:       "resource \"helm_release\" \"db\" {\n  repository = var.chart_repository\n  chart      = \"postgresql\"\n}",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-003", at: "var.chart_repository"}},
		},
		{
			name:  "comment is ignored",
			input: "# repository = \"https://charts.bitnami.com/bitnami\"\n",
		},
		{
			name:  "prose image values are not images",
			input: "resource \"helm_release\" \"db\" {\n  chart  = \"local\"\n  values = [\"note: see bitnami/redis docs\"]\n}",
		},
		{
			name:  "yamlencode bool leaf is a configuration finding",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({ global = { security = { allowInsecureImages = true } } })]\n}",
			findings: []terraformWant{
				{rule: "DSD-CFG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "true"},
			},
		},
		{
			name:  "yamlencode numeric leaf keeps the sibling image finding",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    replicaCount = 3\n    image = {\n      repository = \"bitnami/redis\"\n      tag        = \"7.2.0\"\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "\"bitnami/redis\""},
			},
		},
		{
			name:  "yamlencode triple with a mirror registry",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    global = {\n      imageRegistry = \"mirror.example.com\"\n    }\n    image = {\n      repository = \"bitnami/redis\"\n      tag        = \"7.2.0\"\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-004", severity: diag.SeverityLow, confidence: diag.ConfidenceInferred, at: "\"bitnami/redis\""},
			},
		},
		{
			name:  "embedded yaml triple is reported once",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    image:\n      repository: bitnami/redis\n      tag: \"7.2.0\"\n  EOT\n  ]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "bitnami/redis"},
			},
		},
		{
			name:  "embedded yaml secret is skipped",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    apiVersion: v1\n    kind: Secret\n    data:\n      password: bitnami/redis\n  EOT\n  ]\n}",
		},
		{
			name:  "yamlencode secret is skipped",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    kind = \"Secret\"\n    data = {\n      password = \"bitnami/redis\"\n    }\n  })]\n}",
		},
		{
			name:        "malformed embedded values are reported",
			input:       "resource \"helm_release\" \"db\" {\n  values = [\"a: b\\n  c: d\"]\n}",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-001", at: "\"a: b"}},
		},
		{
			name:  "templated repository with Bitnami evidence",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    image = {\n      repository = \"${var.registry}/bitnami/redis\"\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceUnresolved, at: "\"${var.registry}/bitnami/redis\""},
			},
		},
		{
			name:  "yamlencode triple with a dynamic tag",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    image = {\n      repository = \"bitnami/redis\"\n      tag        = var.tag\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceUnresolved, at: "\"bitnami/redis\""},
			},
		},
		{
			name:  "yamlencode triple with a dynamic registry",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    image = {\n      registry   = var.registry\n      repository = \"bitnami/redis\"\n      tag        = \"7.2.0\"\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceUnresolved, at: "\"bitnami/redis\""},
			},
		},
		{
			name:  "yamlencode triple with a dynamic digest",
			input: "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    image = {\n      repository = \"bitnami/redis\"\n      digest     = var.digest\n    }\n  })]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceUnresolved, at: "\"bitnami/redis\""},
			},
		},
		{
			name:        "dynamic component of another image is unresolved",
			input:       "resource \"helm_release\" \"db\" {\n  values = [yamlencode({\n    image = {\n      repository = \"acme/redis\"\n      tag        = var.tag\n    }\n  })]\n}",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-003", at: "var.tag"}},
		},
		{
			name:        "dynamic leaf is unresolved",
			input:       "resource \"helm_release\" \"db\" {\n  values = [yamlencode({ replicaCount = var.count })]\n}",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-003", at: "var.count"}},
		},
		{
			name:        "malformed hcl is reported",
			input:       "resource \"helm_release\" \"db\" {\n  chart =\n}\n",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-001"}},
		},
		{
			name:  "chart repository with a template is an unresolved chart",
			input: "resource \"helm_release\" \"db\" {\n  repository = \"https://charts.bitnami.com/bitnami/${var.sub}\"\n  chart      = \"postgresql\"\n}",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceUnresolved, at: "\"https://charts.bitnami.com/bitnami/${var.sub}"},
			},
		},
		{
			name:  "oci chart path with extra segments is an unresolved chart",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/bitnamicharts/sub/redis\" }",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceUnresolved, at: "\"oci://registry-1.docker.io/bitnamicharts/sub/redis"},
			},
		},
		{
			name:  "templated oci chart is an unresolved chart",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/bitnamicharts/${var.name}\" }",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceUnresolved, at: "\"oci://registry-1.docker.io/bitnamicharts/${var.name}"},
			},
		},
		{
			name:  "templated oci chart with a static name is an unresolved chart",
			input: "resource \"helm_release\" \"db\" { chart = \"oci://registry-1.docker.io/bitnamicharts/redis:${var.tag}\" }",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceUnresolved, at: "\"oci://registry-1.docker.io/bitnamicharts/redis:${var.tag}"},
			},
		},
		{
			name:  "templated oci repository is an unresolved chart",
			input: "resource \"helm_release\" \"db\" {\n  repository = \"oci://registry-1.docker.io/bitnamicharts/${var.name}\"\n  chart      = \"postgresql\"\n}",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceUnresolved, at: "\"oci://registry-1.docker.io/bitnamicharts/${var.name}"},
			},
		},
		{
			name:        "templated chart is unresolved",
			input:       "resource \"helm_release\" \"db\" { chart = \"${var.chart}\" }",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-003", at: "\"${var.chart}\""}},
		},
		{
			name:  "embedded values scalar is an image",
			input: "resource \"helm_release\" \"db\" {\n  values = [\"bitnami/redis\"]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-003", severity: diag.SeverityMedium, confidence: diag.ConfidenceInferred, at: "bitnami/redis"},
			},
		},
		{
			name:  "embedded values chart repository is a chart",
			input: "resource \"helm_release\" \"db\" {\n  values = [\"repository: https://charts.bitnami.com/bitnami\"]\n}",
			findings: []terraformWant{
				{rule: "DSD-CHT-001", severity: diag.SeverityMedium, confidence: diag.ConfidenceConfirmed, at: "https://charts.bitnami.com/bitnami"},
			},
		},
		{
			name:  "embedded values allow insecure images is a configuration finding",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    global:\n      security:\n        allowInsecureImages: true\n  EOT\n  ]\n}",
			findings: []terraformWant{
				{rule: "DSD-CFG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "true"},
			},
		},
		{
			name:  "embedded values sequence is scanned",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    - bitnami/redis\n  EOT\n  ]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-003", severity: diag.SeverityMedium, confidence: diag.ConfidenceInferred, at: "bitnami/redis"},
			},
		},
		{
			name:  "embedded values triple with a registry and a digest",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    image:\n      registry: docker.io\n      repository: bitnami/redis\n      digest: sha256:abc\n  EOT\n  ]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "bitnami/redis"},
			},
		},
		{
			name:  "embedded values global image registry is the fallback",
			input: "resource \"helm_release\" \"db\" {\n  values = [<<-EOT\n    global:\n      imageRegistry: mirror.example.com\n    image:\n      repository: bitnami/redis\n      tag: \"7.2.0\"\n  EOT\n  ]\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-004", severity: diag.SeverityLow, confidence: diag.ConfidenceInferred, at: "bitnami/redis"},
			},
		},
		{
			name:  "set list and set sensitive blocks are scanned",
			input: "resource \"helm_release\" \"db\" {\n  set_list {\n    name  = \"extra\"\n    value = [\"a\", \"b\"]\n  }\n  set_sensitive {\n    name  = \"image.repository\"\n    value = \"bitnamilegacy/postgresql\"\n  }\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-001", severity: diag.SeverityHigh, confidence: diag.ConfidenceConfirmed, at: "\"bitnamilegacy/postgresql"},
			},
		},
		{
			name:  "set block with another name is not an image",
			input: "resource \"helm_release\" \"db\" {\n  set {\n    name  = \"extra\"\n    value = \"bitnami/redis\"\n  }\n}",
		},
		{
			name:  "set block with a templated value keeps the static part",
			input: "resource \"helm_release\" \"db\" {\n  set {\n    name  = \"image.repository\"\n    value = \"${var.registry}/bitnami/redis\"\n  }\n}",
			findings: []terraformWant{
				{rule: "DSD-IMG-002", severity: diag.SeverityHigh, confidence: diag.ConfidenceUnresolved, at: "\"${var.registry}/bitnami/redis"},
			},
		},
		{
			name:  "file call is ignored",
			input: "resource \"helm_release\" \"db\" {\n  values = [file(\"values.yaml\")]\n}",
		},
		{
			name:        "yamlencode of a variable is unresolved",
			input:       "resource \"helm_release\" \"db\" {\n  values = [yamlencode(var.values)]\n}",
			diagnostics: []terraformWantDiagnostic{{code: "DSD-SCN-003", at: "var.values"}},
		},
		{
			name:  "empty values text is not a finding",
			input: "resource \"helm_release\" \"db\" {\n  values = [\"\"]\n}",
		},
		{
			name:  "other resources are scanned without a chart",
			input: "resource \"kubernetes_secret\" \"db\" {\n  data = \"bitnami/redis\"\n}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Terraform("main.tf", []byte(tt.input))
			want := make([]terraformFinding, 0, len(tt.findings))
			for _, f := range tt.findings {
				line, column := terraformPosition(t, tt.input, f.at)
				want = append(want, terraformFinding{rule: f.rule, severity: f.severity, confidence: f.confidence, line: line, column: column})
			}
			sort.Slice(want, func(i, j int) bool {
				if want[i].line != want[j].line {
					return want[i].line < want[j].line
				}
				if want[i].column != want[j].column {
					return want[i].column < want[j].column
				}
				return want[i].rule < want[j].rule
			})
			have := terraformFindings(got)
			if len(have) != len(want) {
				t.Fatalf("source %s: got findings %+v diagnostics %+v, want %+v", providerDocs, have, got.Diagnostics, want)
			}
			for i := range want {
				if have[i] != want[i] {
					t.Fatalf("source %s: finding %d got %+v, want %+v (all %+v)", providerDocs, i, have[i], want[i], have)
				}
			}
			if len(got.Diagnostics) != len(tt.diagnostics) {
				t.Fatalf("source %s: got diagnostics %+v, want %d", providerDocs, got.Diagnostics, len(tt.diagnostics))
			}
			for i, d := range tt.diagnostics {
				line, column := 0, 0
				if d.at != "" {
					line, column = terraformPosition(t, tt.input, d.at)
				}
				have := got.Diagnostics[i]
				if have.Code != d.code || have.Location.Line != line || have.Location.Column != column {
					t.Fatalf("source %s: diagnostic %d got %+v, want %s at %d:%d", providerDocs, i, have, d.code, line, column)
				}
			}
		})
	}
}

func TestTerraformUnresolvedAndLimits(t *testing.T) {
	got := Terraform("main.tf", []byte("resource \"helm_release\" \"db\" {\n  repository = var.chart_repository\n  chart      = \"postgresql\"\n}"))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-003" {
		t.Fatalf("source docs/spec/v0.1.md section 2.2: %#v", got)
	}
	got = Terraform("main.tf", make([]byte, maxTerraformBytes+1))
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-008" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
	got = Terraform("main.tf", []byte{0xff, 0xfe})
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-001" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}

// TestTerraformHCLDepthLimit checks that a file deeper than the HCL limit is
// reported once and never scanned (spec section 3).
func TestTerraformHCLDepthLimit(t *testing.T) {
	deep := strings.Repeat("{ a = ", maxTerraformDepth+2) + "1" + strings.Repeat(" }", maxTerraformDepth+2)
	got := Terraform("main.tf", []byte("resource \"helm_release\" \"db\" { values = "+deep+" }"))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}

// TestTerraformBlockDepthLimit checks the depth limit of the block walk:
// nested resources are reported, not scanned (spec section 3).
func TestTerraformBlockDepthLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("resource \"helm_release\" \"a\" {\n")
	for i := 0; i < maxTerraformDepth; i++ {
		b.WriteString(strings.Repeat(" ", i*2) + "resource \"helm_release\" \"b\" {\n")
	}
	for i := maxTerraformDepth; i > 0; i-- {
		b.WriteString(strings.Repeat(" ", (i-1)*2) + "}\n")
	}
	b.WriteString("}\n")
	got := Terraform("main.tf", []byte(b.String()))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}

// TestTerraformNodeLimit checks the node budget: an oversized file is
// reported once and the scan stops (spec section 3).
func TestTerraformNodeLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("resource \"helm_release\" \"db\" {\n")
	for i := 0; i <= maxTerraformNodes; i++ {
		b.WriteString("  block {}\n")
	}
	b.WriteString("}\n")
	got := Terraform("main.tf", []byte(b.String()))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}

// TestTerraformEmbeddedValuesDepthLimit checks that an embedded values
// document deeper than the YAML limit is reported, not dropped (spec
// section 3).
func TestTerraformEmbeddedValuesDepthLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxYAMLDepth+2; i++ {
		b.WriteString(strings.Repeat(" ", i*2) + "a:\n")
	}
	b.WriteString(strings.Repeat(" ", (maxYAMLDepth+2)*2) + "b: bitnami/redis")
	source := "resource \"helm_release\" \"db\" {\n  values = [" + strconv.Quote(b.String()) + "]\n}"
	got := Terraform("main.tf", []byte(source))
	if len(got.Findings) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("source docs/spec/v0.1.md section 3: %#v", got)
	}
}

func FuzzTerraform(f *testing.F) {
	f.Add([]byte(`resource "helm_release" "db" { values = [yamlencode({ image = { repository = "bitnami/redis" } })] }`))
	f.Add([]byte{0xff, 0x00, 0x7b})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxTerraformBytes {
			return
		}
		_ = Terraform("fuzz.tf", data)
	})
}
