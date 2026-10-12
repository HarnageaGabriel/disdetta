// Package detect contains pure detectors over parsed YAML and Dockerfile text.
package detect

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
)

var statefulNames = map[string]bool{
	"postgresql": true, "redis": true, "valkey": true, "kafka": true,
	"mongodb": true, "keycloak": true,
}

// YAML inspects all YAML documents in data and retains yaml.Node line numbers.
func YAML(path string, data []byte) ([]diag.Diagnostic, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var findings []diag.Diagnostic
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(document.Content) == 0 {
			continue
		}
		globalRegistry := findString(document.Content[0], []string{"global", "imageRegistry"})
		walkYAML(path, document.Content[0], nil, globalRegistry, 0, &findings)
	}
	return findings, nil
}

func walkYAML(path string, node *yaml.Node, keys []string, globalRegistry string, lineOffset int, findings *[]diag.Diagnostic) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			current := appendPath(keys, key.Value)
			if pathEnds(current, "global", "security", "allowInsecureImages") && value.Value == "true" {
				*findings = append(*findings, finding("DSD-001", diag.SeverityAllowInsecure, "allowInsecureImages is enabled", "true", "configuration", path, value.Line+lineOffset, false))
			}
			if key.Value == "image" {
				if value.Kind == yaml.ScalarNode {
					addImage(path, value.Value, value.Line+lineOffset, findings)
				} else if value.Kind == yaml.MappingNode {
					registry := mappingString(value, "registry")
					if registry == "" {
						registry = globalRegistry
					}
					repository := mappingString(value, "repository")
					tag := mappingString(value, "tag")
					digest := mappingString(value, "digest")
					if repository != "" {
						ref := imageref.Join(registry, repository, tag)
						if digest != "" {
							ref = imageref.Parse(ref.Original + "@" + digest)
						}
						addReference(path, ref, mappingLine(value, "repository")+lineOffset, findings)
					}
				}
			}
			if (key.Value == "repository" || key.Value == "url" || key.Value == "repoURL") && value.Kind == yaml.ScalarNode && isBitnamiChartSource(value.Value) {
				*findings = append(*findings, finding("DSD-004", diag.SeverityBitnami, "Bitnami chart source", value.Value, "chart", path, value.Line+lineOffset, false))
			}
			if key.Value == "uses" && value.Kind == yaml.ScalarNode && strings.HasPrefix(value.Value, "docker://") {
				addImage(path, strings.TrimPrefix(value.Value, "docker://"), value.Line+lineOffset, findings)
			}
			if key.Value == "values" && value.Kind == yaml.ScalarNode && strings.TrimSpace(value.Value) != "" {
				var embedded yaml.Node
				if err := yaml.Unmarshal([]byte(value.Value), &embedded); err == nil && len(embedded.Content) > 0 {
					walkYAML(path, embedded.Content[0], current, globalRegistry, value.Line+lineOffset-1, findings)
				}
			}
			walkYAML(path, value, current, globalRegistry, lineOffset, findings)
		}
		return
	}
	for _, child := range node.Content {
		walkYAML(path, child, keys, globalRegistry, lineOffset, findings)
	}
}

// Dockerfile detects image references in FROM instructions, including flags and aliases.
func Dockerfile(path string, data []byte) []diag.Diagnostic {
	var findings []diag.Diagnostic
	scanner := bufio.NewScanner(bytes.NewReader(data))
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
			addImage(path, fields[index], line, &findings)
		}
	}
	return findings
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

func appendPath(path []string, key string) []string {
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = key
	return result
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
