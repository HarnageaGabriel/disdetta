package detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// review 02 F1: a malformed embedded Argo helm.values is an error diagnostic;
// it must never vanish and leave the scan looking complete (spec section 3).
func TestMalformedEmbeddedValuesIsError(t *testing.T) {
	input := "apiVersion: argoproj.io/v1alpha1\n" +
		"kind: Application\n" +
		"spec:\n" +
		"  source:\n" +
		"    repoURL: https://charts.bitnami.com/bitnami\n" +
		"    helm:\n" +
		"      values: |\n" +
		"        image: [\n"
	got := YAML("app.yaml", []byte(input))
	for _, d := range got.Diagnostics {
		if d.Code == "DSD-SCN-001" {
			if d.Level != diag.LevelError || d.Location.Line != 8 {
				t.Fatalf("review 02 F1: %#v", d)
			}
			return
		}
	}
	t.Fatalf("review 02 F1: no error diagnostic in %#v", got.Diagnostics)
}

// review 02 F2: only alias expansions consume the budget, so an ordinary large
// values file is scanned to the end without truncation (spec section 3).
func TestLargeNestedValuesIsFullyScanned(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&b, "k%05d:\n  value: %d\n", i, i)
	}
	b.WriteString("image:\n  repository: bitnami/redis\n  tag: 7\n")
	got := YAML("values.yaml", []byte(b.String()))
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "DSD-IMG-002" {
		t.Fatalf("review 02 F2: %#v", got.Findings)
	}
	for _, d := range got.Diagnostics {
		if d.Code == "DSD-SCN-005" {
			t.Fatalf("review 02 F2: unexpected limit diagnostic %#v", d)
		}
	}
}

// review 02 F2: hitting the alias expansion limit is reported, never silent.
func TestAliasExpansionLimitIsReported(t *testing.T) {
	var b strings.Builder
	b.WriteString("a0: &a0 [x, x]\n")
	for i := 1; i < 15; i++ {
		fmt.Fprintf(&b, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
	}
	got := YAML("values.yaml", []byte(b.String()))
	if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "DSD-SCN-005" {
		t.Fatalf("review 02 F2: %#v", got.Diagnostics)
	}
}

// review 02 F4: a reference embedded in an Argo helm.values block keeps its own
// line, not the values: marker line (spec section 5).
func TestEmbeddedValuesLineNumbers(t *testing.T) {
	block := "apiVersion: argoproj.io/v1alpha1\n" +
		"kind: Application\n" +
		"spec:\n" +
		"  source:\n" +
		"    repoURL: https://charts.bitnami.com/bitnami\n" +
		"    helm:\n" +
		"      values: |\n" +
		"        image:\n" +
		"          repository: bitnamilegacy/redis\n" +
		"          tag: 7\n"
	got := YAML("app.yaml", []byte(block))
	var image *diag.Finding
	for i := range got.Findings {
		if got.Findings[i].RuleID == "DSD-IMG-001" {
			image = &got.Findings[i]
		}
	}
	if image == nil {
		t.Fatalf("review 02 F4: %#v", got.Findings)
	}
	if image.Location.Line != 9 || image.Location.Column != 15 {
		t.Fatalf("review 02 F4: line=%d column=%d", image.Location.Line, image.Location.Column)
	}
	flow := "kind: Application\n" +
		"spec:\n" +
		"  source:\n" +
		"    helm:\n" +
		"      values: 'image: bitnami/redis:7'\n"
	got = YAML("app.yaml", []byte(flow))
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 5 {
		t.Fatalf("review 02 F4: %#v", got.Findings)
	}
}

// review 02 F5: ARG expansion parses variable tokens, so it neither depends on
// map order nor rewrites a name inside a longer one (spec section 10).
func TestDockerArgExpansionIsTokenAware(t *testing.T) {
	prefix := "ARG A=bitnami\nARG AB=redis\n"
	for i := 0; i < 50; i++ {
		got := Dockerfile("Dockerfile", []byte(prefix+"FROM $AB/redis:7\n"))
		if len(got.Findings) != 0 {
			t.Fatalf("review 02 F5: run %d: %#v", i, got.Findings)
		}
	}
	got := Dockerfile("Dockerfile", []byte("ARG REDIS=bitnami/redis\nFROM $REDIS_CLUSTER:7\n"))
	if len(got.Findings) != 0 {
		t.Fatalf("review 02 F5: substring rewrite: %#v", got.Findings)
	}
}

// review 02 F6: bitnamisecure is the community tier for any tag, and annotation
// images carry the mirror attribute or stay unresolved (spec sections 2.1, 2.2).
func TestBitnamiSecureAndAnnotationConfidence(t *testing.T) {
	got := YAML("values.yaml", []byte("image: bitnamisecure/redis:7\n"))
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "DSD-IMG-003" || got.Findings[0].Severity != diag.SeverityMedium {
		t.Fatalf("review 02 F6: %#v", got.Findings)
	}
	mirror := "name: postgresql\n" +
		"annotations:\n" +
		"  images: |\n" +
		"    - name: postgresql\n" +
		"      image: registry.example.internal/mirror/bitnami/postgresql:17\n"
	got = YAML("Chart.yaml", []byte(mirror))
	if len(got.Findings) != 1 || got.Findings[0].Confidence != diag.ConfidenceInferred || !equalStrings(got.Findings[0].Attributes, []string{"chart", "mirror"}) {
		t.Fatalf("review 02 F6: %#v", got.Findings)
	}
	templated := "name: postgresql\n" +
		"annotations:\n" +
		"  images: |\n" +
		"    - name: postgresql\n" +
		"      image: 'bitnami/postgresql:{{ .Values.tag }}'\n"
	got = YAML("Chart.yaml", []byte(templated))
	if len(got.Findings) != 1 || got.Findings[0].Confidence != diag.ConfidenceUnresolved {
		t.Fatalf("review 02 F6: %#v", got.Findings)
	}
}

// review 02 F8: a UTF-8 BOM must not hide the first instruction or key.
func TestUTF8BOMIsStripped(t *testing.T) {
	const bom = "\ufeff"
	if got := Dockerfile("Dockerfile", []byte(bom+"FROM bitnami/redis:7\n")); len(got.Findings) != 1 {
		t.Fatalf("review 02 F8: dockerfile %#v", got.Findings)
	}
	if got := YAML("values.yaml", []byte(bom+"image: bitnami/redis:7\n")); len(got.Findings) != 1 {
		t.Fatalf("review 02 F8: yaml %#v", got.Findings)
	}
	if got := Template("templates/job.yaml", []byte(bom+"image: bitnami/kubectl:latest\n")); len(got.Findings) != 1 {
		t.Fatalf("review 02 F8: template %#v", got.Findings)
	}
}

// review 02 F9: Dockerfile heredoc bodies are content, not instructions.
func TestDockerfileHeredocBodiesAreSkipped(t *testing.T) {
	input := "FROM bitnami/nginx:1 AS base\n" +
		"RUN <<EOF\n" +
		"FROM bitnami/redis:latest\n" +
		"COPY --from=bitnami/evil:1 /x /x\n" +
		"EOF\n" +
		"RUN <<-'END'\n" +
		"\tFROM bitnamilegacy/postgresql:16\n" +
		"\tEND\n" +
		"COPY <<\"FILE\" /dest\n" +
		"image: bitnami/redis:7\n" +
		"FILE\n" +
		"FROM bitnami/redis:8\n"
	got := Dockerfile("Dockerfile", []byte(input))
	if len(got.Findings) != 2 {
		t.Fatalf("review 02 F9: %#v", got.Findings)
	}
}

// review 02 F10: nothing under a Secret is scanned, at any depth or key.
func TestSecretsSkippedAtAnyDepth(t *testing.T) {
	list := "kind: List\n" +
		"items:\n" +
		"- kind: Secret\n" +
		"  data:\n" +
		"    image: bitnami/redis:7\n" +
		"- kind: Pod\n" +
		"  spec:\n" +
		"    containers:\n" +
		"    - image: bitnami/nginx:1\n"
	got := YAML("input.yaml", []byte(list))
	if len(got.Findings) != 1 || got.Findings[0].Reference != "docker.io/bitnami/nginx:1" {
		t.Fatalf("review 02 F10: %#v", got.Findings)
	}
	nested := "helper:\n  kind: Secret\n  payload: bitnamilegacy/redis:7\n"
	if got := YAML("values.yaml", []byte(nested)); len(got.Findings) != 0 {
		t.Fatalf("review 02 F10: %#v", got.Findings)
	}
}

// review 02 F12: an anchor and every alias use are one finding at the anchor.
func TestAliasReportsOnceAtAnchor(t *testing.T) {
	scalar := "common: &common\n  image: bitnami/redis:7\nfirst: *common\nsecond: *common\n"
	got := YAML("values.yaml", []byte(scalar))
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 2 {
		t.Fatalf("review 02 F12: %#v", got.Findings)
	}
	triple := "base: &base\n  repository: bitnami/redis\n  tag: 7\none:\n  image: *base\ntwo:\n  image: *base\n"
	got = YAML("values.yaml", []byte(triple))
	if len(got.Findings) != 1 || got.Findings[0].Location.Line != 2 {
		t.Fatalf("review 02 F12: %#v", got.Findings)
	}
}
