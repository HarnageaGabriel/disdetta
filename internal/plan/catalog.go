// Package plan builds deterministic, read-only migration plans from explicitly
// configured Helm values and an embedded route catalog.
package plan

import (
	"fmt"
	"sort"
	"strings"

	catalogdata "github.com/HarnageaGabriel/disdetta/catalog"
	"gopkg.in/yaml.v3"
)

type Source struct {
	URL      string `yaml:"url" json:"url"`
	Verified string `yaml:"verified,omitempty" json:"verified,omitempty"`
}
type Target struct {
	Name       string `yaml:"name" json:"name"`
	Kind       string `yaml:"kind" json:"kind"`
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	Version    string `yaml:"version" json:"version"`
}
type Route struct {
	ID          string `yaml:"id" json:"id"`
	Target      Target `yaml:"target" json:"target"`
	Recommended bool   `yaml:"recommended" json:"recommended"`
	Migration   string `yaml:"migration" json:"migration"`
	Source      Source `yaml:"source" json:"source"`
}
type Mapping struct {
	From      string `yaml:"from" json:"from"`
	To        string `yaml:"to,omitempty" json:"to,omitempty"`
	Kind      string `yaml:"kind" json:"kind"`
	Transform string `yaml:"transform,omitempty" json:"transform,omitempty"`
	Note      string `yaml:"note,omitempty" json:"note,omitempty"`
	Source    Source `yaml:"source" json:"source"`
}
type CatalogChecklist struct {
	ID     string `yaml:"id" json:"id"`
	Text   string `yaml:"text" json:"text"`
	Source Source `yaml:"source" json:"source"`
}
type Catalog struct {
	SchemaVersion string             `yaml:"schemaVersion" json:"schemaVersion"`
	Chart         string             `yaml:"chart" json:"chart"`
	AppliesTo     string             `yaml:"appliesTo" json:"appliesTo"`
	Maturity      string             `yaml:"maturity" json:"maturity"`
	Routes        []Route            `yaml:"routes" json:"routes"`
	Mappings      []Mapping          `yaml:"mappings" json:"mappings"`
	Checklist     []CatalogChecklist `yaml:"checklist" json:"checklist"`
}

func ParseCatalog(data []byte) (Catalog, error) {
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse route catalog: %w", err)
	}
	if c.SchemaVersion != "1" || c.Chart == "" || len(c.Routes) == 0 {
		return c, fmt.Errorf("invalid route catalog")
	}
	for _, m := range c.Mappings {
		if !strings.HasPrefix(m.Source.URL, "https://") || m.Source.Verified == "" {
			return c, fmt.Errorf("mapping %q has unverified source", m.From)
		}
		if m.Kind == "transform" && !RegisteredTransform(m.Transform) {
			return c, fmt.Errorf("mapping %q names unknown transform %q", m.From, m.Transform)
		}
		if (m.Kind == "manual" || m.Kind == "unmapped") && m.Note == "" {
			return c, fmt.Errorf("mapping %q requires a note", m.From)
		}
	}
	return c, nil
}

func EmbeddedCatalogs() ([]Catalog, error) {
	entries, err := catalogdata.Routes.ReadDir("routes")
	if err != nil {
		return nil, err
	}
	var out []Catalog
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := catalogdata.Routes.ReadFile("routes/" + e.Name())
		if err != nil {
			return nil, err
		}
		c, err := ParseCatalog(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Chart < out[j].Chart })
	return out, nil
}

func SelectCatalog(catalogs []Catalog, chart, version, routeID string) (Catalog, Route, error) {
	for _, c := range catalogs {
		if c.Chart != chart {
			continue
		}
		if !applies(c.AppliesTo, version) {
			return Catalog{}, Route{}, fmt.Errorf("chart %s version %s is outside catalog range %s", chart, version, c.AppliesTo)
		}
		for _, r := range c.Routes {
			if routeID == "" && r.Recommended || r.ID == routeID {
				return c, r, nil
			}
		}
		return Catalog{}, Route{}, fmt.Errorf("route %q not found for chart %s", routeID, chart)
	}
	return Catalog{}, Route{}, fmt.Errorf("no catalog route for chart %s", chart)
}

func applies(expr, version string) bool {
	if version == "" {
		return false
	}
	for _, term := range strings.Fields(expr) {
		op, want := "=", term
		for _, p := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(term, p) {
				op, want = p, strings.TrimPrefix(term, p)
				break
			}
		}
		cmp, ok := compareVersions(version, want)
		if !ok {
			return false
		}
		if (op == ">=" && cmp < 0) || (op == "<=" && cmp > 0) || (op == ">" && cmp <= 0) || (op == "<" && cmp >= 0) || (op == "=" && cmp != 0) {
			return false
		}
	}
	return true
}

func compareVersions(a, b string) (int, bool) {
	parse := func(s string) ([3]int, bool) {
		var v [3]int
		s = strings.TrimPrefix(s, "v")
		s = strings.SplitN(s, "-", 2)[0]
		s = strings.SplitN(s, "+", 2)[0]
		n, err := fmt.Sscanf(s, "%d.%d.%d", &v[0], &v[1], &v[2])
		return v, n == 3 && err == nil
	}
	av, ok := parse(a)
	if !ok {
		return 0, false
	}
	bv, ok := parse(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return -1, true
		}
		if av[i] > bv[i] {
			return 1, true
		}
	}
	return 0, true
}
