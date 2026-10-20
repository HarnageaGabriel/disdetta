package detect

import (
	"fmt"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/imageref"
)

func BenchmarkImageRefParse(b *testing.B) {
	refs := []string{
		"bitnami/redis:7",
		"docker.io/bitnami/postgresql:16",
		"registry.example/team/app:2026.10",
		"ghcr.io/acme/bitnami/redis@sha256:0123456789abcdef",
		"bitnami/kubectl:{{ .Values.imageTag }}",
	}
	var last imageref.Reference
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, ref := range refs {
			last = imageref.Parse(ref)
		}
	}
	if last.Safe == "" {
		b.Fatal("image parser returned an empty reference")
	}
}

func BenchmarkDetectValues(b *testing.B) {
	data := makeBigValues(4 * 1024 * 1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got := YAML("values.yaml", data)
		if got.Summary.FilesScanned != 0 && got.Summary.FilesScanned != 1 {
			b.Fatalf("unexpected file count %d", got.Summary.FilesScanned)
		}
	}
}

func BenchmarkTemplateText(b *testing.B) {
	data := makeBigTemplate(4 * 1024 * 1024)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		got := Template("templates/large.yaml", data)
		if len(got.Diagnostics) == 0 {
			b.Fatal("template scan produced no diagnostics")
		}
	}
}

func makeBigValues(target int) []byte {
	var out strings.Builder
	out.Grow(target)
	out.WriteString("config:\n")
	for i := 0; out.Len()+96 < target; i++ {
		fmt.Fprintf(&out, "  - name: bench-%07d\n    value: deterministic-value-%07d\n", i, i)
	}
	out.WriteString("  - name: bitnami-redis\n    image: bitnami/redis:7\n")
	return []byte(out.String())
}

func makeBigTemplate(target int) []byte {
	var out strings.Builder
	out.Grow(target)
	for i := 0; out.Len()+220 < target; i++ {
		fmt.Fprintf(&out, `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bench-%07d
spec:
  template:
    spec:
      containers:
        - name: app
          image: "bitnami/redis:{{ .Values.imageTag }}"
`, i)
	}
	return []byte(out.String())
}
