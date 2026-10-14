package detect

import (
	"bytes"
	"errors"
	"io"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"gopkg.in/yaml.v3"
)

// Values scans a Helm user values document given as YAML (JSON is a YAML
// subset). It applies the v0.1 values detector: the allowInsecureImages guard
// (DSD-CFG-001), image triples, and whole-scalar fallbacks (spec v0.1 sections
// 2.1 and 9). The cluster scan uses it for Helm release config (spec v0.2
// section 3). Positions are kept; the caller normalizes cluster locations.
func Values(path string, data []byte) diag.Report {
	var out diag.Report
	root, err := firstDocument(data)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed values document"))
		return out
	}
	if root == nil || isSecretMapping(root) {
		return out
	}
	s := walkState{path: path, globalRegistry: findString(root, []string{"global", "imageRegistry"}), out: &out}
	s.scanConfig(root)
	s.scanImages(root, false)
	before := len(out.Findings)
	s.scanFallbacks(root)
	s.dropDuplicateFallbacks(before)
	out.Findings = diag.DedupeFindings(out.Findings)
	return out
}

// ChartMetadata scans Helm chart metadata (name, version, home, sources,
// annotations.images) for a vendored Bitnami chart, reporting one DSD-CHT-002
// (spec v0.1 section 2.1). The cluster scan uses it for the chart metadata of a
// Helm release (spec v0.2 section 3).
func ChartMetadata(path string, data []byte) diag.Report {
	var out diag.Report
	root, err := firstDocument(data)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed chart metadata"))
		return out
	}
	if root == nil {
		return out
	}
	s := walkState{path: path, out: &out}
	s.scanVendoredChart(root)
	return out
}

// firstDocument decodes the first YAML document of data into a node. It returns
// (nil, nil) for an empty document and an error for malformed input.
func firstDocument(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(stripBOM(data)))
	var doc yaml.Node
	err := dec.Decode(&doc)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	return doc.Content[0], nil
}
