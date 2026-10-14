package plan

import (
	"fmt"
	"sort"
	"strings"
)

type Input struct {
	Release, Chart, ChartVersion string
	Values                       map[string]any
}
type Unmapped struct {
	Path string `json:"path" yaml:"path"`
	Kind string `json:"kind" yaml:"kind"`
	Note string `json:"note" yaml:"note"`
}
type ChecklistItem struct {
	Text   string `json:"text" yaml:"text"`
	Source string `json:"source" yaml:"source"`
}
type Coverage struct {
	Mapped int `json:"mapped" yaml:"mapped"`
	Total  int `json:"total" yaml:"total"`
}
type Plan struct {
	SchemaVersion string          `json:"schemaVersion" yaml:"schemaVersion"`
	Release       string          `json:"release" yaml:"release"`
	Chart         string          `json:"chart" yaml:"chart"`
	ChartVersion  string          `json:"chartVersion" yaml:"chartVersion"`
	Route         string          `json:"route" yaml:"route"`
	Maturity      string          `json:"maturity" yaml:"maturity"`
	Target        map[string]any  `json:"target" yaml:"target"`
	Unmapped      []Unmapped      `json:"unmapped" yaml:"unmapped"`
	Checklist     []ChecklistItem `json:"checklist" yaml:"checklist"`
	Coverage      Coverage        `json:"coverage" yaml:"coverage"`
}

func Build(in Input, c Catalog, route Route) (Plan, error) {
	p := Plan{SchemaVersion: "1", Release: in.Release, Chart: in.Chart, ChartVersion: in.ChartVersion, Route: route.ID, Maturity: c.Maturity, Target: map[string]any{"apiVersion": route.Target.APIVersion, "kind": route.Target.Kind, "metadata": map[string]any{"name": in.Release}}, Unmapped: []Unmapped{}, Checklist: []ChecklistItem{}}
	for _, item := range c.Checklist {
		p.Checklist = append(p.Checklist, ChecklistItem{Text: item.Text, Source: item.Source.URL})
	}
	leaves := flatten(in.Values)
	consumed := map[string]bool{}
	for _, m := range c.Mappings {
		matched := matching(m.From, leaves)
		if !strings.HasSuffix(m.From, ".*") {
			if v, ok := lookup(in.Values, m.From); ok {
				matched = []string{m.From}
				leaves[m.From] = v
			}
		}
		for _, path := range matched {
			if path == "readReplicas.replicaCount" && m.Kind == "unmapped" {
				if arch, _ := lookup(in.Values, "architecture"); arch == "replication" {
					continue
				}
			}
			v := leaves[path]
			consumed[path] = true
			switch m.Kind {
			case "rename", "constant":
				if !secretPath(path) {
					set(p.Target, m.To, v)
					p.Coverage.Mapped++
				} else {
					p.Unmapped = append(p.Unmapped, Unmapped{path, "manual", "secret value must be supplied through a Kubernetes Secret"})
				}
			case "transform":
				tr, err := transforms[m.Transform](path, v, in.Values)
				if err != nil {
					return Plan{}, err
				}
				if !empty(tr.Value) {
					setMerge(p.Target, m.To, tr.Value)
				}
				p.Unmapped = append(p.Unmapped, tr.Dropped...)
				p.Checklist = append(p.Checklist, tr.Checklist...)
				p.Coverage.Mapped++
				if m.Transform == "instances-from-architecture" {
					if _, ok := lookup(in.Values, "readReplicas.replicaCount"); ok {
						consumed["readReplicas.replicaCount"] = true
						p.Coverage.Mapped++
					}
				}
			case "manual", "unmapped":
				p.Unmapped = append(p.Unmapped, Unmapped{path, m.Kind, m.Note})
			}
		}
	}
	for path := range leaves {
		if !covered(path, consumed) {
			p.Unmapped = append(p.Unmapped, Unmapped{path, "unknown", "no verified catalog mapping"})
		}
	}
	p.Coverage.Total = p.Coverage.Mapped + len(p.Unmapped)
	sort.Slice(p.Unmapped, func(i, j int) bool {
		if p.Unmapped[i].Path == p.Unmapped[j].Path {
			return p.Unmapped[i].Kind < p.Unmapped[j].Kind
		}
		return p.Unmapped[i].Path < p.Unmapped[j].Path
	})
	for _, u := range p.Unmapped {
		if u.Kind == "manual" {
			p.Checklist = append(p.Checklist, ChecklistItem{Text: fmt.Sprintf("Resolve %s: %s", u.Path, u.Note), Source: mappingSource(c, u.Path)})
		}
	}
	return p, nil
}

func mappingSource(c Catalog, path string) string {
	for _, m := range c.Mappings {
		if matchPattern(m.From, path) {
			return m.Source.URL
		}
	}
	return c.Routes[0].Source.URL
}
func secretPath(path string) bool {
	l := strings.ToLower(path)
	if path == "auth.username" || path == "auth.database" {
		return false
	}
	return strings.HasPrefix(l, "auth.") || strings.Contains(l, "password") || strings.Contains(l, "token") || strings.Contains(l, "secret")
}
func matching(pattern string, leaves map[string]any) []string {
	var out []string
	for p := range leaves {
		if matchPattern(pattern, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
func matchPattern(pattern, path string) bool {
	if strings.HasSuffix(pattern, ".*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == path
}
func covered(path string, c map[string]bool) bool {
	if c[path] {
		return true
	}
	for p := range c {
		if strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}
func flatten(m map[string]any) map[string]any {
	out := map[string]any{}
	var walk func(string, any)
	walk = func(p string, v any) {
		if mm, ok := v.(map[string]any); ok {
			if len(mm) == 0 {
				out[p] = v
			}
			for k, x := range mm {
				q := k
				if p != "" {
					q = p + "." + k
				}
				walk(q, x)
			}
			return
		}
		out[p] = v
	}
	for k, v := range m {
		walk(k, v)
	}
	return out
}
func lookup(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}
func set(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		n, ok := cur[p].(map[string]any)
		if !ok {
			n = map[string]any{}
			cur[p] = n
		}
		cur = n
	}
	cur[parts[len(parts)-1]] = v
}
func setMerge(m map[string]any, path string, v any) {
	if old, ok := lookup(m, path); ok {
		om, ok1 := old.(map[string]any)
		vm, ok2 := v.(map[string]any)
		if ok1 && ok2 {
			for k, x := range vm {
				om[k] = x
			}
			return
		}
	}
	set(m, path, v)
}
func empty(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case []string:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
