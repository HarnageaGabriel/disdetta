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
		s.walk(root, 0, 0, false)
	}
	return out
}

type walkState struct {
	path           string
	keys           []string
	globalRegistry string
	depthReported  bool
	out            *diag.Report
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
					reg := mappingString(v, "registry")
					if reg == "" {
						reg = s.globalRegistry
					}
					repo := mappingString(v, "repository")
					tag := mappingString(v, "tag")
					digest := mappingString(v, "digest")
					if repo != "" {
						ref := imageref.Join(reg, repo, tag)
						if digest != "" {
							ref = imageref.Parse(ref.Original + "@" + digest)
						}
						s.addRef(ref, mappingLine(v, "repository")+lineOffset, mappingColumn(v, "repository"), embedded)
					}
				}
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
func (s *walkState) addRef(r imageref.Reference, line, column int, embedded bool) {
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
	if embedded {
		attrs = append(attrs, "embedded-values")
	}
	sort.Strings(attrs)
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: rule, Severity: sev, Confidence: confidence, Impact: catalog.Impact(r.Component()), Component: r.Component(), Location: loc(s.path, line, column), Reference: r.Safe, Original: r.SafeOriginal, Attributes: attrs})
}

// Dockerfile detects image references in FROM instructions.
func Dockerfile(path string, data []byte) diag.Report {
	var out diag.Report
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line := 0
	s := walkState{path: path, out: &out}
	for scanner.Scan() {
		line++
		f := strings.Fields(scanner.Text())
		if len(f) < 2 || !strings.EqualFold(f[0], "FROM") {
			continue
		}
		i := 1
		for i < len(f) && strings.HasPrefix(f[i], "--") {
			i++
		}
		if i < len(f) {
			s.addImage(f[i], line, 1, false)
		}
	}
	if scanner.Err() != nil {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, line+1, 1, "Dockerfile line length limit reached"))
	}
	return out
}
func loc(path string, line, column int) diag.Location {
	return diag.Location{Path: path, Line: line, Column: column}
}
func newDiagnostic(code string, level diag.Level, path string, line, column int, message string) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Level: level, Message: message, Location: loc(path, line, column)}
}
func isChartKey(k string) bool { return k == "repository" || k == "url" || k == "repoURL" }
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
func mappingLine(n *yaml.Node, w string) int {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == w {
			return n.Content[i+1].Line
		}
	}
	return n.Line
}
func mappingColumn(n *yaml.Node, w string) int {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == w {
			return n.Content[i+1].Column
		}
	}
	return n.Column
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
