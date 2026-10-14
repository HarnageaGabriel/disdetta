// Package detect contains pure detectors over parsed YAML and Dockerfile text.
package detect

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
)

const (
	maxYAMLDepth      = 100
	maxDockerfileLine = 1024 * 1024
)

var statefulNames = map[string]bool{
	"postgresql": true, "redis": true, "valkey": true, "kafka": true,
	"mongodb": true, "keycloak": true,
}

// YAML inspects all YAML documents in data and retains yaml.Node line numbers.
func YAML(path string, data []byte) diag.Report {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var result diag.Report
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err != nil {
			if err == io.EOF {
				break
			}
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic(path, 0, "malformed YAML: "+err.Error()))
			break
		}
		if len(document.Content) == 0 {
			continue
		}
		root := document.Content[0]
		globalRegistry := findString(root, []string{"global", "imageRegistry"})
		state := yamlWalkState{path: path, globalRegistry: globalRegistry, secret: strings.EqualFold(findString(root, []string{"kind"}), "Secret"), result: &result}
		state.walk(root, 0, 0)
	}
	return result
}

type yamlWalkState struct {
	path           string
	keys           []string
	globalRegistry string
	secret         bool
	depthReported  bool
	result         *diag.Report
}

func (s *yamlWalkState) walk(node *yaml.Node, lineOffset, depth int) {
	if depth > maxYAMLDepth {
		if !s.depthReported {
			s.result.Diagnostics = append(s.result.Diagnostics, scanDiagnostic(s.path, node.Line+lineOffset, "YAML nesting exceeds depth limit"))
			s.depthReported = true
		}
		return
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			s.keys = append(s.keys, key.Value)
			if s.secret && len(s.keys) == 1 && (key.Value == "data" || key.Value == "stringData") {
				s.keys = s.keys[:len(s.keys)-1]
				continue
			}
			var enabled bool
			if pathEnds(s.keys, "global", "security", "allowInsecureImages") && value.Tag == "!!bool" && value.Decode(&enabled) == nil && enabled {
				s.result.Findings = append(s.result.Findings, finding("DSD-001", diag.SeverityAllowInsecure, "allowInsecureImages is enabled", "true", "configuration", s.path, value.Line+lineOffset, false))
			}
			if key.Value == "image" {
				if value.Kind == yaml.ScalarNode {
					addImage(s.path, value.Value, value.Line+lineOffset, &s.result.Findings)
				} else if value.Kind == yaml.MappingNode {
					registry := mappingString(value, "registry")
					if registry == "" {
						registry = s.globalRegistry
					}
					repository := mappingString(value, "repository")
					tag := mappingString(value, "tag")
					digest := mappingString(value, "digest")
					if repository != "" {
						ref := imageref.Join(registry, repository, tag)
						if digest != "" {
							ref = imageref.Parse(ref.Original + "@" + digest)
						}
						addReference(s.path, ref, mappingLine(value, "repository")+lineOffset, &s.result.Findings)
					}
				}
			}
			if (key.Value == "repository" || key.Value == "url" || key.Value == "repoURL") && value.Kind == yaml.ScalarNode && isBitnamiChartSource(value.Value) {
				s.result.Findings = append(s.result.Findings, finding("DSD-004", diag.SeverityBitnami, "Bitnami chart source", value.Value, "chart", s.path, value.Line+lineOffset, false))
			}
			if key.Value == "uses" && value.Kind == yaml.ScalarNode && strings.HasPrefix(value.Value, "docker://") {
				addImage(s.path, strings.TrimPrefix(value.Value, "docker://"), value.Line+lineOffset, &s.result.Findings)
			}
			if key.Value == "values" && value.Kind == yaml.ScalarNode && strings.TrimSpace(value.Value) != "" {
				var embedded yaml.Node
				if err := yaml.Unmarshal([]byte(value.Value), &embedded); err != nil {
					s.result.Diagnostics = append(s.result.Diagnostics, scanDiagnostic(s.path, value.Line+lineOffset+1, "malformed embedded helm.values YAML: "+err.Error()))
				} else if len(embedded.Content) > 0 {
					s.walk(embedded.Content[0], value.Line+lineOffset, depth+1)
				}
			}
			s.walk(value, lineOffset, depth+1)
			s.keys = s.keys[:len(s.keys)-1]
		}
		return
	}
	for _, child := range node.Content {
		s.walk(child, lineOffset, depth+1)
	}
}

// Dockerfile detects image references in FROM instructions, including flags and aliases.
func Dockerfile(path string, data []byte) diag.Report {
	var result diag.Report
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line := 0
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		index := 1
		for index < len(fields) && strings.HasPrefix(fields[index], "--") {
			index++
		}
		if index < len(fields) {
			addImage(path, fields[index], line, &result.Findings)
		}
	}
	if err := scanner.Err(); err != nil {
		result.Diagnostics = append(result.Diagnostics, scanDiagnostic(path, line+1, "Dockerfile scan failed: "+err.Error()))
	}
	return result
}

func addImage(path, value string, line int, findings *[]diag.Diagnostic) {
	addReference(path, imageref.Parse(value), line, findings)
}

func addReference(path string, ref imageref.Reference, line int, findings *[]diag.Diagnostic) {
	var code, message string
	severity := diag.SeverityBitnami
	switch ref.Classification {
	case imageref.BitnamiLegacy:
		code, message, severity = "DSD-002", "Bitnami legacy image", diag.SeverityLegacy
	case imageref.Bitnami, imageref.BitnamiSecure:
		code, message = "DSD-003", "Bitnami image"
	case imageref.Unresolved:
		code, message = "DSD-005", "Unresolved templated image"
	default:
		return
	}
	*findings = append(*findings, finding(code, severity, message, ref.String(), string(ref.Classification), path, line, isStateful(ref)))
}

func isStateful(ref imageref.Reference) bool {
	name := ref.Repository
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		name = name[slash+1:]
	}
	return statefulNames[strings.ToLower(name)]
}

func finding(code string, severity diag.Severity, message, reference, class, path string, line int, stateful bool) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Severity: severity, Message: message, Reference: reference, Classification: class, Path: path, Line: line, Stateful: stateful}
}

func isBitnamiChartSource(value string) bool {
	v := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "/")
	return v == "https://charts.bitnami.com/bitnami" || v == "oci://registry-1.docker.io/bitnamicharts" || v == "oci://docker.io/bitnamicharts"
}

func mappingString(node *yaml.Node, wanted string) string {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == wanted && node.Content[i+1].Kind == yaml.ScalarNode {
			return node.Content[i+1].Value
		}
	}
	return ""
}

func mappingLine(node *yaml.Node, wanted string) int {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == wanted {
			return node.Content[i+1].Line
		}
	}
	return node.Line
}

func findString(node *yaml.Node, path []string) string {
	for _, part := range path {
		if node.Kind != yaml.MappingNode {
			return ""
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == part {
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return ""
		}
		node = next
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value
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

func scanDiagnostic(path string, line int, message string) diag.ScanDiagnostic {
	return diag.ScanDiagnostic{Code: "DSD-006", Message: message, Path: path, Line: line}
}
