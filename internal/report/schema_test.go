package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestReportSchema validates every JSON golden (real scan output) against
// schemas/report-v1.json. Source: docs/spec/v0.1.md section 8.
func TestReportSchema(t *testing.T) {
	root := filepath.Join("..", "..")
	c := jsonschema.NewCompiler()
	schema, err := c.Compile(filepath.Join(root, "schemas", "report-v1.json"))
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	goldens, err := filepath.Glob(filepath.Join(root, "testdata", "repos", "*", "scan.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	clusterGoldens, err := filepath.Glob(filepath.Join(root, "testdata", "cluster", "*", "scan.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	goldens = append(goldens, clusterGoldens...)
	if len(goldens) == 0 {
		t.Fatalf("no JSON goldens found")
	}
	for _, g := range goldens {
		t.Run(filepath.Base(filepath.Dir(g)), func(t *testing.T) {
			b, err := os.ReadFile(g)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
			if err != nil {
				t.Fatalf("parse %s: %v", g, err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s does not match schemas/report-v1.json: %v", g, err)
			}
		})
	}
}
