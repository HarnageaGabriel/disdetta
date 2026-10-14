// Package detect contains pure detectors over parsed YAML and Dockerfile text.
package detect

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
	"io"
	"sort"
	"strings"
)

const (
	maxYAMLDepth      = 256
	maxDockerfileLine = 1024 * 1024
)

// YAML inspects all YAML documents and retains one-based positions.
func YAML(path string, data []byte) diag.Report {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out diag.Report
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed YAML"))
			break
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if strings.EqualFold(findString(root, []string{"kind"}), "Secret") {
			continue
		}
		s := walkState{path: path, globalRegistry: findString(root, []string{"global", "imageRegistry"}), out: &out}
		s.scanDocument(root)
	}
	return out
}

type walkState struct {
	path            string
	keys            []string
	globalRegistry  string
	depthReported   bool
	templateComment bool
	out             *diag.Report
}

func (s *walkState) walk(n *yaml.Node, lineOffset, depth int, embedded bool) {
	if depth > maxYAMLDepth {
		if !s.depthReported {
			s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, n.Line+lineOffset, n.Column, "YAML depth limit reached"))
			s.depthReported = true
		}
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			s.keys = append(s.keys, k.Value)
			if pathEnds(s.keys, "global", "security", "allowInsecureImages") && v.Tag == "!!bool" {
				var enabled bool
				if v.Decode(&enabled) == nil && enabled {
					s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, v.Line+lineOffset, v.Column), Reference: "true", Original: "true", Attributes: []string{}})
				}
			}
			if k.Value == "image" {
				switch v.Kind {
				case yaml.ScalarNode:
					s.addImage(v.Value, v.Line+lineOffset, v.Column, embedded)
				case yaml.MappingNode:
					s.addSplitImage(v, lineOffset, embedded)
				}
			} else if v.Kind == yaml.MappingNode && isImageTriple(v) {
				s.addSplitImage(v, lineOffset, embedded)
			}
			if isChartKey(k.Value) && v.Kind == yaml.ScalarNode && isBitnamiChartSource(v.Value) {
				component := mappingString(n, "name")
				if component == "" {
					component = mappingString(n, "chart")
				}
				impact := diag.ImpactUnknown
				if component != "" {
					impact = catalog.Impact(component)
				}
				s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: impact, Component: component, Location: loc(s.path, v.Line+lineOffset, v.Column), Reference: strings.TrimSpace(v.Value), Original: strings.TrimSpace(v.Value), Attributes: []string{"chart"}})
			}
			if k.Value == "uses" && v.Kind == yaml.ScalarNode && strings.HasPrefix(v.Value, "docker://") {
				s.addImage(strings.TrimPrefix(v.Value, "docker://"), v.Line+lineOffset, v.Column, embedded)
			}
			if k.Value == "values" && v.Kind == yaml.ScalarNode && strings.TrimSpace(v.Value) != "" {
				var sub yaml.Node
				if err := yaml.Unmarshal([]byte(v.Value), &sub); err != nil {
					s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, s.path, v.Line+lineOffset+1, v.Column, "malformed embedded values"))
				} else if len(sub.Content) > 0 {
					s.walk(sub.Content[0], v.Line+lineOffset, depth+1, true)
				}
			}
			s.walk(v, lineOffset, depth+1, embedded)
			s.keys = s.keys[:len(s.keys)-1]
		}
		return
	}
	for _, c := range n.Content {
		s.walk(c, lineOffset, depth+1, embedded)
	}
}
func (s *walkState) addImage(v string, line, column int, embedded bool) {
	s.addRef(imageref.Parse(v), line, column, embedded)
}

// addSplitImage reports an image triple (spec section 9): a mapping that has an
// image-shaped repository, joined with its sibling registry, tag and digest.
func (s *walkState) addSplitImage(v *yaml.Node, lineOffset int, embedded bool) {
	repo := valueAt(v, "repository")
	if repo == "" {
		return
	}
	reg := valueAt(v, "registry")
	if reg == "" {
		reg = s.globalRegistry
	}
	ref := imageref.Join(reg, repo, valueAt(v, "tag"))
	if digest := valueAt(v, "digest"); digest != "" {
		ref = imageref.Parse(ref.Original + "@" + digest)
	}
	line, column := 0, 0
	if rn := nodeAt(v, "repository"); rn != nil {
		line, column = rn.Line, rn.Column
	}
	s.addRef(ref, line+lineOffset, column, embedded)
}
func (s *walkState) addRef(r imageref.Reference, line, column int, embedded bool) {
	s.addRefConfidence(r, line, column, embedded, false)
}

// addRefConfidence records a finding. forceInferred marks a reference found
// inside a template action, whose runtime value is not certain (section 9.1).
func (s *walkState) addRefConfidence(r imageref.Reference, line, column int, embedded bool, forceInferred bool) {
	if r.IsExcluded() {
		return
	}
	if r.Classification == imageref.Unresolved && !r.HasStaticEvidence {
		s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-003", diag.LevelInfo, s.path, line, column, "unresolved reference without Bitnami evidence"))
		return
	}
	if !r.HasStaticEvidence {
		return
	}
	rule := ""
	sev := diag.SeverityHigh
	attrs := []string{}
	switch r.Classification {
	case imageref.BitnamiLegacy:
		rule = "DSD-IMG-001"
	case imageref.Bitnami, imageref.BitnamiSecure:
		if r.Tag == "" && !r.Templated && r.Digest == "" || strings.EqualFold(r.Tag, "latest") {
			rule = "DSD-IMG-003"
			sev = diag.SeverityMedium
		} else {
			rule = "DSD-IMG-002"
			attrs = append(attrs, "pull-risk")
		}
	default:
		return
	}
	confidence := diag.ConfidenceConfirmed
	if r.Templated {
		confidence = diag.ConfidenceUnresolved
	} else if r.Registry != "docker.io" {
		confidence = diag.ConfidenceInferred
		attrs = append(attrs, "mirror")
	}
	if forceInferred && confidence == diag.ConfidenceConfirmed {
		confidence = diag.ConfidenceInferred
	}
	if embedded {
		attrs = append(attrs, "embedded-values")
	}
	sort.Strings(attrs)
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: rule, Severity: sev, Confidence: confidence, Impact: catalog.Impact(r.Component()), Component: r.Component(), Location: loc(s.path, line, column), Reference: r.Safe, Original: r.SafeOriginal, Attributes: attrs})
}

// scanConfig reports DSD-CFG-001 for global.security.allowInsecureImages at any
// depth (spec section 2.1), including under a subchart key such as keycloak.
func (s *walkState) scanConfig(root *yaml.Node) {
	s.scanConfigAt(root, 0)
}
func (s *walkState) scanConfigAt(n *yaml.Node, depth int) {
	if n == nil || depth > maxYAMLDepth {
		return
	}
	if n.Kind == yaml.MappingNode {
		if v := nodeAt(n, "global", "security", "allowInsecureImages"); v != nil && v.Tag == "!!bool" {
			var enabled bool
			if v.Decode(&enabled) == nil && enabled {
				s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, v.Line, v.Column), Reference: "true", Original: "true", Attributes: []string{}})
			}
		}
	}
	for _, c := range n.Content {
		s.scanConfigAt(c, depth+1)
	}
}

// Dockerfile detects image references in FROM and external COPY instructions.
func Dockerfile(path string, data []byte) diag.Report {
	var out diag.Report
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line, start := 0, 0
	s := walkState{path: path, out: &out}
	args, stages := map[string]string{}, map[string]bool{}
	seenFrom := false
	logical := ""
	for scanner.Scan() {
		line++
		part := strings.TrimSpace(scanner.Text())
		if logical == "" {
			start = line
		}
		continued := strings.HasSuffix(part, "\\")
		part = strings.TrimSpace(strings.TrimSuffix(part, "\\"))
		logical += " " + part
		if continued {
			continue
		}
		f := strings.Fields(strings.TrimSpace(logical))
		logical = ""
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if strings.EqualFold(f[0], "ARG") && len(f) >= 2 && !seenFrom {
			name, value, ok := strings.Cut(f[1], "=")
			if ok {
				args[name] = value
			}
			continue
		}
		if strings.EqualFold(f[0], "FROM") {
			seenFrom = true
			i := 1
			for i < len(f) && strings.HasPrefix(f[i], "--") {
				i++
			}
			if i < len(f) {
				ref := expandDockerArgs(f[i], args)
				s.addImage(ref, start, 1, false)
				for j := i + 1; j+1 < len(f); j++ {
					if strings.EqualFold(f[j], "AS") {
						stages[strings.ToLower(f[j+1])] = true
					}
				}
			}
			continue
		}
		if strings.EqualFold(f[0], "COPY") {
			for _, field := range f[1:] {
				if strings.HasPrefix(strings.ToLower(field), "--from=") {
					ref := strings.TrimSpace(field[len("--from="):])
					if !stages[strings.ToLower(ref)] {
						s.addImage(expandDockerArgs(ref, args), start, 1, false)
					}
				}
			}
		}
	}
	if scanner.Err() != nil {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, line+1, 1, "Dockerfile line length limit reached"))
	}
	return out
}

func expandDockerArgs(v string, args map[string]string) string {
	for name, value := range args {
		v = strings.ReplaceAll(v, "${"+name+"}", value)
		v = strings.ReplaceAll(v, "$"+name, value)
	}
	return v
}
func loc(path string, line, column int) diag.Location {
	return diag.Location{Path: path, Line: line, Column: column}
}
func newDiagnostic(code string, level diag.Level, path string, line, column int, message string) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Level: level, Message: message, Location: loc(path, line, column)}
}
func isChartKey(k string) bool { return k == "repository" || k == "url" || k == "repoURL" }

// isImageTriple reports whether n is a mapping shaped like a split image
// reference (spec section 9): it carries a `repository` whose value is
// image-shaped. Chart repository URLs are not image-shaped and stay out.
func isImageTriple(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.MappingNode && isImageShaped(valueAt(n, "repository"))
}

func isImageShaped(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "/") || strings.Contains(v, "://") {
		return false
	}
	return true
}
func isBitnamiChartSource(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "/")
	return v == "https://charts.bitnami.com/bitnami" || v == "oci://registry-1.docker.io/bitnamicharts" || v == "oci://docker.io/bitnamicharts"
}
func mappingString(n *yaml.Node, w string) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == w && n.Content[i+1].Kind == yaml.ScalarNode {
			return n.Content[i+1].Value
		}
	}
	return ""
}

func findString(n *yaml.Node, path []string) string {
	for _, part := range path {
		if n.Kind != yaml.MappingNode {
			return ""
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == part {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil {
			return ""
		}
		n = next
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}
func pathEnds(path []string, suffix ...string) bool {
	if len(path) < len(suffix) {
		return false
	}
	for i := range suffix {
		if path[len(path)-len(suffix)+i] != suffix[i] {
			return false
		}
	}
	return true
}
