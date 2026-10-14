package plan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEmbeddedCatalogSchemaAndRegistry(t *testing.T) {
	catalogs, err := EmbeddedCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalogs) == 0 {
		t.Fatal("no embedded catalogs")
	}
	root := filepath.Join("..", "..")
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(filepath.Join(root, "schemas", "catalog-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "catalog", "routes", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ParseCatalog(b)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, m := range c.Mappings {
			if !strings.HasPrefix(m.Source.URL, "https://") || m.Source.Verified != "2026-10-14" {
				t.Fatalf("unverified mapping %#v", m)
			}
			if m.Kind == "transform" && !RegisteredTransform(m.Transform) {
				t.Fatalf("unknown transform %s", m.Transform)
			}
		}
	}
}

func TestPlanJSONGoldensMatchSchema(t *testing.T) {
	root := filepath.Join("..", "..")
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(filepath.Join(root, "schemas", "plan-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "testdata", "plan", "postgresql", "*", "plan.json.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("got %d plan JSON goldens", len(files))
	}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s: %v", file, err)
		}
	}
}

func TestRouteOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plan", "catalog", "route-only.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	c, r, err := SelectCatalog([]Catalog{c}, "fake", "1.2.0", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Build(Input{"x", "fake", "1.2.0", map[string]any{"value": true}}, c, r)
	if err != nil {
		t.Fatal(err)
	}
	if p.Maturity != "route-only" || len(p.Unmapped) != 1 || p.Unmapped[0].Kind != "unknown" {
		t.Fatalf("plan=%#v", p)
	}
}

func TestSecretsNeverRendered(t *testing.T) {
	catalogs, err := EmbeddedCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	c, r, err := SelectCatalog(catalogs, "postgresql", "16.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	secret := "PLANTED-secret-token-123"
	p, err := Build(Input{"pg", "postgresql", "16.2.1", map[string]any{"architecture": "standalone", "auth": map[string]any{"database": "app", "username": "app", "password": secret, "postgresPassword": secret, "existingSecret": secret}}}, c, r)
	if err != nil {
		t.Fatal(err)
	}
	j, _ := JSON(p)
	table, _ := Table(p)
	target, _ := TargetYAML(p)
	for name, b := range map[string][]byte{"json": j, "table": table, "target": target, "checklist": ChecklistMarkdown(p)} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("secret leaked in %s", name)
		}
	}
}
