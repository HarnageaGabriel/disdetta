// Package catalog provides the embedded migration-impact component table.
package catalog

import (
	_ "embed"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"gopkg.in/yaml.v3"
	"strings"
)

//go:embed components.yaml
var componentData []byte

// Parse parses component YAML without performing I/O.
func Parse(data []byte) (map[string]diag.Impact, error) {
	var raw map[string]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse component catalog: %w", err)
	}
	out := make(map[string]diag.Impact, len(raw))
	for n, v := range raw {
		i := diag.Impact(v)
		if i != diag.ImpactHigh && i != diag.ImpactMedium && i != diag.ImpactLow {
			return nil, fmt.Errorf("component %q has invalid impact %q", n, v)
		}
		out[strings.ToLower(n)] = i
	}
	return out, nil
}

var components = func() map[string]diag.Impact {
	v, e := Parse(componentData)
	if e != nil {
		panic(e)
	}
	return v
}()

// Impact returns the migration impact for an image component.
func Impact(name string) diag.Impact {
	name = strings.ToLower(name)
	if v, ok := components[name]; ok {
		return v
	}
	if strings.HasSuffix(name, "-exporter") {
		return diag.ImpactLow
	}
	return diag.ImpactMedium
}

// Names returns all explicitly catalogued names.
func Names() []string {
	out := make([]string, 0, len(components))
	for n := range components {
		out = append(out, n)
	}
	return out
}
