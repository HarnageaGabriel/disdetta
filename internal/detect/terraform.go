// Terraform detects Bitnami chart and image evidence in Terraform Helm
// releases. The parser is deliberately parse-only: expressions are inspected
// as syntax and never evaluated, so no functions, files, variables, or
// environment values are read (spec v0.1 section 2.2 and ADR 0009).
package detect

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"gopkg.in/yaml.v3"
)

const (
	maxTerraformBytes            = 16 * 1024 * 1024
	maxTerraformDepth            = 256
	maxTerraformNodes            = 100000
	terraformTemplatePlaceholder = "{{?}}"
	// terraformRedactedTemplate replaces a templated segment in a printed
	// reference (spec section 6). The ellipsis is U+2026.
	terraformRedactedTemplate = "{{…}}"
	// maxTerraformParseDepth is the deepest nesting the HCL parser is
	// allowed to reach. The parser recurses over the nesting, so a file
	// nested deeper is never parsed: it is reported as DSD-SCN-005. The
	// limit of the detector (maxTerraformDepth) is checked on the parsed
	// tree; this bound only keeps the parser inside its stack.
	maxTerraformParseDepth = 1024
)

// MaxTerraformHeredocLines is the largest number of lines the body of a
// single heredoc may hold. The HCL parser costs more than linear time in
// the lines of a heredoc body, so a bigger body is never parsed: the file
// is reported as DSD-SCN-005 and not scanned (spec section 3).
const MaxTerraformHeredocLines = 20000

// MaxTerraformLines is the largest number of lines a Terraform file may
// hold. A bigger file is never parsed: it is reported as DSD-SCN-005 and
// not scanned (spec section 3).
const MaxTerraformLines = 200000

// terraformOCIPrefixes are the exact Bitnami OCI chart namespaces. A name
// that only contains "bitnamicharts" (my-bitnamicharts-fork) is another
// chart and stays out (spec section 2.1).
var terraformOCIPrefixes = []string{
	"oci://registry-1.docker.io/bitnamicharts/",
	"oci://docker.io/bitnamicharts/",
}

// Terraform parses and scans Terraform HCL for helm_release resources.
func Terraform(path string, data []byte) diag.Report {
	out := diag.Report{}
	if len(data) > maxTerraformBytes {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-008", diag.LevelError, path, 0, 0, "file exceeds 16 MiB limit; skipped"))
		return out
	}
	if !utf8Valid(data) {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed Terraform HCL"))
		return out
	}
	body := stripBOM(data)
	raw := terraformScanRaw(body)
	if raw.lines > MaxTerraformLines || raw.heredoc > MaxTerraformHeredocLines {
		// The file is not parsed: the HCL parser costs more than linear
		// time in the lines of a heredoc body, and a big file is never
		// parsed without a diagnostic (spec section 3).
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, 0, 0, "limit reached: Terraform heredoc or file too large"))
		return out
	}
	if raw.depth > maxTerraformParseDepth {
		// The parser recurses over the nesting of the expressions: a file
		// nested deeper is never parsed (spec section 3).
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, 0, 0, errTerraformLimit.Error()))
		return out
	}
	file, diags := hclsyntax.ParseConfig(body, path, hcl.InitialPos)
	if file == nil || diags.HasErrors() {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed Terraform HCL"))
		return out
	}
	root, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return out
	}
	if terraformBodyDepth(root, 0) > maxTerraformDepth {
		// The depth limit is read from the parsed tree: the file is
		// reported and not scanned (spec section 3).
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, 0, 0, errTerraformLimit.Error()))
		return out
	}
	s := terraformScan{path: path, out: &out, aliasSeen: map[*yaml.Node]bool{}}
	if err := s.body(root, 0); err != nil {
		s.reportLimit(0, 0)
	}
	out.Findings = dedupeTerraformFindings(out.Findings)
	out.Findings = diag.DedupeFindings(out.Findings)
	return out
}

type terraformScan struct {
	path string
	out  *diag.Report
	// nodes counts every visited syntax or YAML node against the budget.
	nodes int
	// limitReported keeps DSD-SCN-005 to one diagnostic per file.
	limitReported bool
	// aliasSeen is the chain of alias targets being expanded, so a cycle is
	// never followed twice (the cycle guard of the YAML detector).
	aliasSeen map[*yaml.Node]bool
	// aliasBudget counts the alias expansions of the file against the alias
	// limit of the YAML detector.
	aliasBudget int
}

// chargeNode charges one visited node against the budget. An exhausted
// budget is reported once (DSD-SCN-005) and stops the walk: a huge file is
// never scanned without a diagnostic (spec section 3).
func (s *terraformScan) chargeNode() bool {
	s.nodes++
	if s.nodes <= maxTerraformNodes {
		return true
	}
	s.reportLimit(0, 0)
	return false
}

// reportLimit emits DSD-SCN-005 once per file.
func (s *terraformScan) reportLimit(line, column int) {
	if s.limitReported {
		return
	}
	s.limitReported = true
	s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, line, column, errTerraformLimit.Error()))
}

// reportAliasLimit emits DSD-SCN-005 once per file for the alias expansion
// budget of the YAML detector.
func (s *terraformScan) reportAliasLimit(line, column int) {
	if s.limitReported {
		return
	}
	s.limitReported = true
	s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, line, column, "alias expansion limit reached"))
}

// reportGuardLimit emits DSD-SCN-005 once per file for the depth and alias
// expansion limits of the YAML detector, with the limit it reached.
func (s *terraformScan) reportGuardLimit(line, column int, err error) {
	if s.limitReported {
		return
	}
	s.limitReported = true
	s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, line, column, err.Error()))
}

func (s *terraformScan) body(body *hclsyntax.Body, depth int) error {
	if depth > maxTerraformDepth {
		s.reportLimit(0, 0)
		return errTerraformLimit
	}
	for _, block := range body.Blocks {
		if !s.chargeNode() {
			return errTerraformLimit
		}
		if block.Type == "resource" && len(block.Labels) == 2 && block.Labels[0] == "helm_release" {
			if err := s.release(block, depth+1); err != nil {
				return err
			}
			continue
		}
		if err := s.body(block.Body, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (s *terraformScan) release(block *hclsyntax.Block, depth int) error {
	body := block.Body
	chart := terraformString(body.Attributes["chart"])
	if attr := body.Attributes["repository"]; attr != nil {
		static, templated := terraformStaticString(attr.Expr)
		safe := terraformSafeReference(static)
		staticTrimmed := strings.TrimSpace(static)
		if url, ok := chartURLIn(safe); ok {
			confidence := diag.ConfidenceConfirmed
			if templated || safe != staticTrimmed {
				confidence = diag.ConfidenceUnresolved
			}
			s.chartFindingWithConfidence(attr.Expr.Range(), chart, url, confidence)
		} else if templated || safe != staticTrimmed {
			s.unresolved(attr.Expr.Range())
		}
	}
	if attr := body.Attributes["chart"]; attr != nil {
		s.chartAttribute(attr)
	}
	if attr := body.Attributes["values"]; attr != nil {
		if err := s.values(attr.Expr, depth+1); err != nil {
			return err
		}
	}
	for _, block := range body.Blocks {
		if !s.chargeNode() {
			return errTerraformLimit
		}
		switch block.Type {
		case "set", "set_list", "set_sensitive":
			s.setBlock(block, depth+1)
		default:
			if err := s.body(block.Body, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// chartAttribute reports a Bitnami chart written in the chart attribute.
// Only an exact Bitnami OCI path is a chart finding: the chart component is
// the path segment without its tag or digest. A chart whose static part
// still names the Bitnami OCI namespace and whose name is dynamic is a
// chart finding with unresolved confidence: the static part is the Bitnami
// evidence (spec section 2.2).
func (s *terraformScan) chartAttribute(attr *hclsyntax.Attribute) {
	static, templated := terraformStaticString(attr.Expr)
	if component, ok := terraformOCIChart(static); ok {
		s.ociChartFinding(attr.Expr.Range(), static, false, component)
		return
	}
	if terraformChartHasStaticEvidence(static) {
		s.ociChartFinding(attr.Expr.Range(), static, true, terraformOCIChartComponent(static))
		return
	}
	if templated || terraformSafeReference(static) != strings.TrimSpace(static) {
		s.unresolved(attr.Expr.Range())
	}
}

// values scans a values attribute. A list is scanned item by item; a
// yamlencode call is scanned as the object it encodes; any other text is
// scanned as an embedded YAML document.
func (s *terraformScan) values(expr hclsyntax.Expression, depth int) error {
	if depth > maxTerraformDepth {
		s.reportLimit(0, 0)
		return errTerraformLimit
	}
	switch value := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		for _, item := range value.Exprs {
			// Every element of the list is a visited node: a wide list
			// never bypasses the node budget (spec section 3).
			if !s.chargeNode() {
				return errTerraformLimit
			}
			if err := s.values(item, depth+1); err != nil {
				return err
			}
		}
	case *hclsyntax.FunctionCallExpr:
		if value.Name == "yamlencode" && len(value.Args) == 1 {
			if err := s.valuesObject(value.Args[0], nil, depth+1); err != nil {
				return err
			}
		}
		// file(...) and every other call are intentionally ignored; the
		// referenced file is scanned by the repository scanner separately.
	default:
		static, templated := terraformStaticString(expr)
		before := len(s.out.Findings)
		beforeDiagnostics := len(s.out.Diagnostics)
		parsed, err := s.valuesYAML(static, expr, depth+1)
		if err != nil {
			return err
		}
		if parsed && (templated || terraformSafeReference(static) != strings.TrimSpace(static)) && len(s.out.Findings) == before && len(s.out.Diagnostics) == beforeDiagnostics {
			s.unresolved(expr.Range())
		}
	}
	return nil
}

// valuesYAML scans an embedded values document written as YAML text. A
// malformed document is reported (DSD-SCN-001) and never dropped silently;
// the scan continues with the rest of the file (spec sections 3 and 5).
func (s *terraformScan) valuesYAML(text string, expr hclsyntax.Expression, depth int) (bool, error) {
	rng := expr.Range()
	if depth > maxTerraformDepth {
		s.reportLimit(rng.Start.Line, rng.Start.Column)
		return false, errTerraformLimit
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, s.path, rng.Start.Line, rng.Start.Column, "malformed embedded values"))
		return false, nil
	}
	if len(root.Content) == 0 {
		return true, nil
	}
	rootNode := root.Content[0]
	if err := GuardYAML(rootNode); err != nil {
		// The depth and alias expansion limits of the YAML detector apply
		// to an embedded values document (spec section 3).
		s.reportGuardLimit(rng.Start.Line, rng.Start.Column, err)
		return false, nil
	}
	if isSecretMapping(rootNode) {
		// Nothing under a Secret is scanned or printed, at any depth
		// (spec section 6).
		return true, nil
	}
	line, column := s.valuesBase(expr)
	s.valuesNode(rootNode, "", line, column, depth, findString(rootNode, []string{"global", "imageRegistry"}))
	return true, nil
}

// valuesBase returns the file position of the first character of an
// embedded values text. A heredoc body starts on the line after its marker
// and keeps the indentation its content was written with; a quoted string
// starts where the string starts.
func (s *terraformScan) valuesBase(expr hclsyntax.Expression) (int, int) {
	rng := expr.Range()
	template, ok := expr.(*hclsyntax.TemplateExpr)
	if !ok || len(template.Parts) == 0 {
		return rng.Start.Line, rng.Start.Column + 1
	}
	part := template.Parts[0].Range()
	if part.Start.Line <= rng.Start.Line {
		// A quoted string starts on the line of the expression.
		return rng.Start.Line, rng.Start.Column + 1
	}
	// A heredoc body starts on the line after its marker: the part carries
	// the position of the first content line, with the indentation the
	// content was written with.
	return part.Start.Line, part.Start.Column
}

// valuesNode walks an embedded values document. A mapping shaped like an
// image triple is reported once, at its repository node, and the repository
// scalar of that mapping is never reported again (spec section 9). key is
// the key of the node in its parent mapping: an alias is expanded with the
// key of the node that refers to it, so the context of a reference is never
// lost.
func (s *terraformScan) valuesNode(node *yaml.Node, key string, line, column, depth int, registry string) {
	if depth > maxTerraformDepth {
		s.reportLimit(line, column)
		return
	}
	if !s.chargeNode() {
		return
	}
	if isSecretMapping(node) {
		// Nothing under a Secret is scanned or printed, at any depth
		// (spec section 6).
		return
	}
	switch node.Kind {
	case yaml.MappingNode:
		triple := isImageTripleYAML(node)
		if triple {
			s.imageYAML(node, line, column, registry)
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if triple && strings.EqualFold(key.Value, "repository") {
				// Already reported as part of the image triple.
				continue
			}
			if key.Value == "global" || key.Value == "security" || key.Value == "allowInsecureImages" {
				s.configYAML(node, line, column, depth)
			}
			switch value.Kind {
			case yaml.AliasNode:
				// The alias is expanded with the key that refers to it:
				// a reference under a known image key keeps its context.
				s.valuesAlias(value, key.Value, line, column, depth, registry)
			case yaml.ScalarNode:
				// The scalar is scanned with its key: the whole-scalar
				// fallback of the YAML detector needs it.
				s.valuesScalar(value, key.Value, line, column, registry)
			default:
				s.valuesNode(value, key.Value, line, column, depth+1, registry)
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			s.valuesNode(child, key, line, column, depth+1, registry)
		}
	case yaml.ScalarNode:
		s.valuesScalar(node, key, line, column, registry)
	case yaml.AliasNode:
		s.valuesAlias(node, key, line, column, depth, registry)
	}
}

// valuesAlias follows an alias to the anchor it names, so the target is
// scanned with the same limits as the YAML detector: a cycle is never
// followed twice, and the alias expansion budget is reported once
// (DSD-SCN-005, spec section 3). The target is scanned with the key of the
// node that refers to it, so an alias under a known image key is resolved
// like the value it names.
func (s *terraformScan) valuesAlias(node *yaml.Node, key string, line, column, depth int, registry string) {
	if node.Alias == nil || s.aliasSeen[node.Alias] {
		return
	}
	if s.aliasBudget >= maxAliasNodes {
		s.reportAliasLimit(line+node.Line-1, column+node.Column-1)
		return
	}
	s.aliasBudget++
	s.aliasSeen[node.Alias] = true
	s.valuesNode(node.Alias, key, line, column, depth+1, registry)
	delete(s.aliasSeen, node.Alias)
}

// valuesScalar scans one scalar of an embedded values document. The
// whole-scalar fallback of the YAML detector applies: a Bitnami chart
// repository URL inside any scalar, and an image reference under a key no
// detector knows (spec section 9). A key the image detector resolves (an
// image key) names an image reference: it is reported by the image
// detector, never by the fallback. A scalar that carries a Helm template
// segment is classified with the template-aware reference parser, so the
// static part decides (spec section 2.2).
func (s *terraformScan) valuesScalar(node *yaml.Node, key string, line, column int, registry string) {
	rng := hcl.Range{Start: hcl.Pos{Line: line + node.Line - 1, Column: column + node.Column - 1}}
	if url, ok := chartURLIn(node.Value); ok {
		s.chartFinding(rng, "", url)
	}
	if isImageKey(key) {
		// A known image key is resolved by the image detector: the value
		// is an image reference, not a fallback (spec section 9).
		s.imageYAML(node, line, column, registry)
		return
	}
	if knownImageKeys[key] {
		// A known image key is resolved by the image detector, and a
		// component of a reported image triple is part of its reference
		// (spec section 9).
		return
	}
	if s.templateScalar(node.Value, rng) {
		return
	}
	if !isWholeImageScalar(node.Value) {
		return
	}
	s.addImageWithConfidence(node.Value, rng, true)
}

// templateScalar classifies a scalar that carries a Helm template segment.
// A reference whose static part names a Bitnami namespace is a finding with
// confidence unresolved; a reference without static Bitnami evidence stays a
// DSD-SCN-003 diagnostic (spec section 2.2). It returns false for a scalar
// that carries no template segment.
func (s *terraformScan) templateScalar(value string, rng hcl.Range) bool {
	if !strings.Contains(value, "{{") && !strings.Contains(value, "${") {
		return false
	}
	ref := imageref.Parse(value)
	if !ref.Templated {
		return false
	}
	s.reportReference(ref, rng)
	return true
}

// reportReference records one parsed reference at a position. A reference
// with static Bitnami evidence is a finding, with confidence unresolved when
// a part of it is templated; a reference without it is a DSD-SCN-003
// diagnostic (spec section 2.2).
func (s *terraformScan) reportReference(ref imageref.Reference, rng hcl.Range) {
	classification, ok, unresolved := ClassifyReference(ref, false, false)
	switch {
	case unresolved:
		s.unresolved(rng)
	case ok:
		s.addClassification(classification, rng)
	}
}

// valuesObject walks the object literal of a yamlencode call. Every leaf is
// scanned on its own: a dynamic leaf is unresolved (DSD-SCN-003) and never
// cancels the finding of a literal sibling (spec section 2.2).
func (s *terraformScan) valuesObject(expr hclsyntax.Expression, path []string, depth int) error {
	obj, ok := expr.(*hclsyntax.ObjectConsExpr)
	if !ok {
		s.unresolved(expr.Range())
		return nil
	}
	return s.valuesObjectAt(obj, path, depth, terraformObjectRegistry(obj))
}

// valuesObjectAt walks one object literal. registry is the global image
// registry of the values, the fallback of an image triple without one.
func (s *terraformScan) valuesObjectAt(obj *hclsyntax.ObjectConsExpr, path []string, depth int, registry string) error {
	if depth > maxTerraformDepth {
		s.reportLimit(0, 0)
		return nil
	}
	if !s.chargeNode() {
		return errTerraformLimit
	}
	if terraformObjectIsSecret(obj) {
		// Nothing under a Secret is scanned or printed, at any depth
		// (spec section 6).
		return nil
	}
	triple, tripleExpr, isTriple := terraformObjectImageTriple(obj, registry)
	reported := false
	if isTriple {
		reported = s.addImageReference(triple, tripleExpr.Range())
	}
	for _, item := range obj.Items {
		// Every attribute of the object is a visited node: a wide object
		// never bypasses the node budget (spec section 3).
		if !s.chargeNode() {
			return errTerraformLimit
		}
		key, literalKey := terraformStringResult(item.KeyExpr)
		if !literalKey {
			s.unresolved(item.KeyExpr.Range())
			continue
		}
		if isTriple {
			// The components of an image triple are part of its
			// reference: a reported triple is never reported again
			// (spec section 9).
			if key == "repository" {
				continue
			}
			if reported && (key == "registry" || key == "tag" || key == "digest") {
				// A dynamic component of a reported image is
				// covered by the finding of the triple.
				continue
			}
		}
		childPath := append(append([]string(nil), path...), key)
		switch child := item.ValueExpr.(type) {
		case *hclsyntax.ObjectConsExpr:
			if err := s.valuesObjectAt(child, childPath, depth+1, registry); err != nil {
				return err
			}
			continue
		case *hclsyntax.TupleConsExpr:
			if err := s.valuesCollection(child, childPath, depth+1, registry); err != nil {
				return err
			}
			continue
		}
		s.valuesLeaf(item.ValueExpr, childPath)
	}
	return nil
}

// valuesCollection walks a list of a yamlencode object. Every element is a
// visited node, and every literal leaf is scanned with the rules of an
// object leaf: a Bitnami chart repository URL inside any leaf is a chart
// finding, and an image reference under a key no detector knows is a
// finding with confidence inferred (spec section 9). A dynamic element is
// unresolved (DSD-SCN-003) and never cancels the finding of a literal
// sibling (spec section 2.2).
func (s *terraformScan) valuesCollection(list *hclsyntax.TupleConsExpr, path []string, depth int, registry string) error {
	if depth > maxTerraformDepth {
		s.reportLimit(0, 0)
		return errTerraformLimit
	}
	for _, item := range list.Exprs {
		// Every element of the list is a visited node: a wide list never
		// bypasses the node budget (spec section 3).
		if !s.chargeNode() {
			return errTerraformLimit
		}
		switch child := item.(type) {
		case *hclsyntax.ObjectConsExpr:
			if err := s.valuesObjectAt(child, path, depth+1, registry); err != nil {
				return err
			}
		case *hclsyntax.TupleConsExpr:
			if err := s.valuesCollection(child, path, depth+1, registry); err != nil {
				return err
			}
		default:
			s.valuesLeaf(item, path)
		}
	}
	return nil
}

// valuesLeaf reports one leaf of a values object. A literal leaf is
// scanned; a dynamic leaf keeps only its static part, and is unresolved
// (DSD-SCN-003) when that part names no Bitnami image.
func (s *terraformScan) valuesLeaf(expr hclsyntax.Expression, path []string) {
	if text, literal := terraformScalarResult(expr); literal {
		s.valuesLiteral(text, path, expr.Range())
		return
	}
	static, _ := terraformStaticString(expr)
	ref := imageref.Parse(static)
	if !ref.HasStaticEvidence {
		s.unresolved(expr.Range())
		return
	}
	classification, ok, unresolved := ClassifyReference(ref, false, false)
	switch {
	case unresolved:
		s.unresolved(expr.Range())
	case ok:
		s.addClassification(classification, expr.Range())
	}
}

// valuesLiteral reports a literal leaf of a values object. The whole-scalar
// fallback of the YAML detector applies to a leaf as well: a Bitnami chart
// repository URL inside any scalar, and an image reference under a key no
// detector knows (spec section 9).
func (s *terraformScan) valuesLiteral(text string, path []string, rng hcl.Range) {
	key := ""
	if len(path) > 0 {
		key = path[len(path)-1]
	}
	if url, ok := chartURLIn(text); ok {
		s.chartFinding(rng, "", url)
	}
	if (key == "image" || key == "repository") && isWholeImageScalar(text) {
		s.addImage(text, rng)
		return
	}
	if pathEnds(path, "global", "security", "allowInsecureImages") && strings.EqualFold(text, "true") {
		s.addConfig(rng)
		return
	}
	if knownImageKeys[key] || !isWholeImageScalar(text) {
		return
	}
	s.addImageWithConfidence(text, rng, true)
}

func (s *terraformScan) setBlock(block *hclsyntax.Block, depth int) {
	if depth > maxTerraformDepth {
		return
	}
	nameAttr, valueAttr := block.Body.Attributes["name"], block.Body.Attributes["value"]
	if nameAttr == nil || valueAttr == nil {
		return
	}
	name, nameOK := terraformStringResult(nameAttr.Expr)
	if !nameOK {
		s.unresolved(nameAttr.Expr.Range())
		return
	}
	values := []hclsyntax.Expression{valueAttr.Expr}
	if tuple, ok := valueAttr.Expr.(*hclsyntax.TupleConsExpr); ok {
		values = tuple.Exprs
	}
	for _, valueExpr := range values {
		static, templated := terraformStaticString(valueExpr)
		staticSafe := terraformSafeReference(static)
		rng := valueExpr.Range()
		if block.Type == "set" && name == "global.security.allowInsecureImages" && !templated && strings.EqualFold(static, "true") {
			s.addConfig(rng)
			continue
		}
		if !terraformImagePath(name) || (!templated && staticSafe == strings.TrimSpace(static) && !isWholeImageScalar(static)) {
			continue
		}
		r := imageref.Parse(staticSafe)
		if !r.HasStaticEvidence {
			s.unresolved(rng)
			continue
		}
		c, ok, unresolved := ClassifyReference(r, false, false)
		switch {
		case unresolved:
			s.unresolved(rng)
		case ok:
			s.addClassification(c, rng)
		}
	}
}

func (s *terraformScan) addImage(value string, rng hcl.Range) {
	s.addImageWithConfidence(value, rng, false)
}

// addImageReference reports a parsed image reference at a position. It
// reports whether the reference is a reportable Bitnami image: a reference
// with a dynamic component is reported with unresolved confidence (spec
// section 2.2).
func (s *terraformScan) addImageReference(r imageref.Reference, rng hcl.Range) bool {
	if !r.HasStaticEvidence {
		return false
	}
	c, ok, _ := ClassifyReference(r, false, false)
	if !ok {
		return false
	}
	s.addClassification(c, rng)
	return true
}

func (s *terraformScan) addImageWithConfidence(value string, rng hcl.Range, forceInferred bool) {
	if !isWholeImageScalar(value) {
		return
	}
	r := imageref.Parse(value)
	if !r.HasStaticEvidence {
		return
	}
	c, ok, _ := ClassifyReference(r, false, forceInferred)
	if ok {
		s.addClassification(c, rng)
	}
}

// addClassification records one classified reference at a position.
func (s *terraformScan) addClassification(c Classification, rng hcl.Range) {
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: c.Rule, Severity: c.Severity, Confidence: c.Confidence, Impact: c.Impact, Component: c.Component, Location: loc(s.path, rng.Start.Line, rng.Start.Column), Reference: c.Reference, Original: c.Original, Attributes: c.Attributes})
}

// addConfig records DSD-CFG-001: the Bitnami image guard is switched off.
func (s *terraformScan) addConfig(rng hcl.Range) {
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, rng.Start.Line, rng.Start.Column), Reference: "true", Original: "true", Attributes: []string{}})
}

// imageYAML reports an image reference in an embedded values document. A
// mapping is an image triple: its repository is joined with the sibling
// registry, tag and digest, and the global registry is the fallback
// (spec section 9). A component that carries a Helm template segment keeps
// only its static part, so the finding is unresolved (spec section 2.2).
func (s *terraformScan) imageYAML(node *yaml.Node, line, column int, registry string) {
	switch node.Kind {
	case yaml.ScalarNode:
		rng := hcl.Range{Start: hcl.Pos{Line: line + node.Line - 1, Column: column + node.Column - 1}}
		if isWholeImageScalar(node.Value) {
			s.addImage(node.Value, rng)
			return
		}
		s.templateScalar(node.Value, rng)
	case yaml.MappingNode:
		repo := valueAt(node, "repository")
		if repo == "" {
			return
		}
		reg := valueAt(node, "registry")
		if reg == "" {
			reg = registry
		}
		ref := imageref.Join(reg, repo, valueAt(node, "tag"))
		if digest := valueAt(node, "digest"); digest != "" {
			ref = imageref.Parse(ref.Original + "@" + digest)
		}
		position := nodeAt(node, "repository")
		if position == nil {
			position = node
		}
		s.reportReference(ref, hcl.Range{Start: hcl.Pos{Line: line + position.Line - 1, Column: column + position.Column - 1}})
	}
}

func (s *terraformScan) configYAML(node *yaml.Node, line, column, depth int) {
	if depth > maxTerraformDepth {
		return
	}
	if node.Kind == yaml.MappingNode {
		if value := nodeAt(node, "global", "security", "allowInsecureImages"); value != nil && value.Kind == yaml.ScalarNode && strings.EqualFold(value.Value, "true") {
			s.addConfig(hcl.Range{Start: hcl.Pos{Line: line + value.Line - 1, Column: column + value.Column - 1}})
		}
	}
}

func isImageKey(key string) bool {
	return strings.EqualFold(key, "image") || strings.EqualFold(key, "repository")
}

func isImageTripleYAML(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.MappingNode && isImageShaped(valueAt(node, "repository"))
}

func (s *terraformScan) chartFinding(rng hcl.Range, component, reference string) {
	s.chartFindingWithConfidence(rng, component, reference, diag.ConfidenceConfirmed)
}

func (s *terraformScan) chartFindingWithConfidence(rng hcl.Range, component, reference string, confidence diag.Confidence) {
	impact := diag.ImpactUnknown
	if component != "" {
		impact = catalog.Impact(component)
	}
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium, Confidence: confidence, Impact: impact, Component: component, Location: loc(s.path, rng.Start.Line, rng.Start.Column), Reference: reference, Original: reference, Attributes: []string{"chart"}})
}

func (s *terraformScan) ociChartFinding(rng hcl.Range, value string, unresolved bool, component string) {
	reference := strings.TrimSpace(value)
	confidence := diag.ConfidenceConfirmed
	if unresolved {
		reference = terraformRedactedReference(value)
		confidence = diag.ConfidenceUnresolved
	}
	s.chartFindingWithConfidence(rng, component, reference, confidence)
}

// terraformRedactedReference returns the static part of a reference with
// each templated segment redacted (spec section 6).
func terraformRedactedReference(value string) string {
	return strings.ReplaceAll(terraformSafeReference(value), terraformTemplatePlaceholder, terraformRedactedTemplate)
}

func (s *terraformScan) unresolved(rng hcl.Range) {
	s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-003", diag.LevelInfo, s.path, rng.Start.Line, rng.Start.Column, "unresolved reference without Bitnami evidence"))
}

var errTerraformLimit = errors.New("Terraform depth or node limit reached")

// terraformBodyDepth returns the deepest nesting of the blocks and the
// expressions of a body. The body itself counts as level 0, a block of the
// body as level 1, and an expression of the body as the level of the body
// plus the nesting of the expression.
func terraformBodyDepth(body *hclsyntax.Body, depth int) int {
	best := depth
	for _, attr := range body.Attributes {
		if d := depth + terraformExpressionDepth(attr.Expr); d > best {
			best = d
		}
	}
	for _, block := range body.Blocks {
		if d := terraformBlockDepth(block, depth+1); d > best {
			best = d
		}
	}
	return best
}

// terraformBlockDepth returns the deepest nesting of the attributes and the
// blocks of a block. The block itself counts as the given level.
func terraformBlockDepth(block *hclsyntax.Block, depth int) int {
	best := depth
	for _, attr := range block.Body.Attributes {
		if d := depth + terraformExpressionDepth(attr.Expr); d > best {
			best = d
		}
	}
	for _, inner := range block.Body.Blocks {
		if d := terraformBlockDepth(inner, depth+1); d > best {
			best = d
		}
	}
	return best
}

// terraformExpressionDepth returns the nesting depth of an expression: the
// number of braces, brackets, parentheses, interpolations and heredocs it
// opens. An expression held by another expression adds its depth to the
// depth of the expression that holds it.
func terraformExpressionDepth(expr hclsyntax.Expression) int {
	if expr == nil {
		return 0
	}
	switch value := expr.(type) {
	case *hclsyntax.ObjectConsExpr:
		depth := 0
		for _, item := range value.Items {
			if d := terraformExpressionDepth(item.KeyExpr); d > depth {
				depth = d
			}
			if d := terraformExpressionDepth(item.ValueExpr); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.TupleConsExpr:
		depth := 0
		for _, item := range value.Exprs {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.FunctionCallExpr:
		depth := 0
		for _, arg := range value.Args {
			if d := terraformExpressionDepth(arg); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.ParenthesesExpr:
		return 1 + terraformExpressionDepth(value.Expression)
	case *hclsyntax.TemplateWrapExpr:
		return 1 + terraformExpressionDepth(value.Wrapped)
	case *hclsyntax.ConditionalExpr:
		depth := 0
		for _, item := range []hclsyntax.Expression{value.Condition, value.TrueResult, value.FalseResult} {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.BinaryOpExpr:
		depth := 0
		for _, item := range []hclsyntax.Expression{value.LHS, value.RHS} {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.UnaryOpExpr:
		return 1 + terraformExpressionDepth(value.Val)
	case *hclsyntax.IndexExpr:
		depth := 0
		for _, item := range []hclsyntax.Expression{value.Collection, value.Key} {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.ForExpr:
		depth := 0
		for _, item := range []hclsyntax.Expression{value.CollExpr, value.KeyExpr, value.ValExpr, value.CondExpr} {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.SplatExpr:
		depth := 0
		for _, item := range []hclsyntax.Expression{value.Source, value.Each} {
			if d := terraformExpressionDepth(item); d > depth {
				depth = d
			}
		}
		return 1 + depth
	case *hclsyntax.ObjectConsKeyExpr:
		return terraformExpressionDepth(value.Wrapped)
	case *hclsyntax.RelativeTraversalExpr:
		return terraformExpressionDepth(value.Source)
	case *hclsyntax.TemplateExpr:
		return terraformTemplateDepth(value)
	}
	return 0
}

// terraformTemplateDepth returns the nesting depth of a template. A heredoc
// opens one level, like its marker: the body of a heredoc starts on the
// line after the marker, a quoted string on the line of the string.
func terraformTemplateDepth(value *hclsyntax.TemplateExpr) int {
	depth := 0
	for _, part := range value.Parts {
		if d := terraformExpressionDepth(part); d > depth {
			depth = d
		}
	}
	if len(value.Parts) > 0 && value.Parts[0].Range().Start.Line > value.Range().Start.Line {
		depth++
	}
	return depth
}

// The modes of the raw scan of a Terraform file.
const (
	terraformModeCode = iota
	terraformModeString
	terraformModeComment
	terraformModeHeredoc
)

// terraformRawScan is what the raw scan of a Terraform file counted.
type terraformRawScan struct {
	// lines is the number of lines of the file.
	lines int
	// heredoc is the number of lines of the largest heredoc body.
	heredoc int
	// depth is the deepest nesting of the expressions of the file.
	depth int
}

// terraformFrame is one open bracket, string, comment or interpolation of
// the raw scan. The closer is the character that ends the frame, and the
// restore is the mode the scan returns to.
type terraformFrame struct {
	closer  byte
	restore int
	level   bool
}

// terraformRawScanner is the linear scan of the raw bytes of a Terraform
// file. It counts the lines of the file, the lines of every heredoc body
// and the deepest nesting of the expressions, without parsing the file.
type terraformRawScanner struct {
	lines    int
	heredoc  int
	body     int
	depth    int
	maxDepth int
	mode     int
	marker   []byte
	stack    []terraformFrame
}

// terraformScanRaw reads the raw bytes of a Terraform file once, in linear
// time, and counts the lines of the file, the lines of the largest heredoc
// body and the deepest nesting of the expressions.
//
// The scan is line based and tolerant: a heredoc marker is a "<<" (with an
// optional "-") followed by an identifier, and its body ends at the line
// that holds the identifier alone. A marker that is never closed runs to
// the end of the file. A quoted string, a comment and the body of a heredoc
// hold no nesting, except for the interpolations they open.
func terraformScanRaw(data []byte) terraformRawScan {
	scanner := terraformRawScanner{}
	for pos := 0; pos < len(data); {
		end := pos
		for end < len(data) && data[end] != '\n' {
			end++
		}
		scanner.lines++
		scanner.line(data[pos:end])
		if end == len(data) {
			break
		}
		pos = end + 1
	}
	return terraformRawScan{lines: scanner.lines, heredoc: scanner.heredoc, depth: scanner.maxDepth}
}

// line reads one line of the file.
func (s *terraformRawScanner) line(text []byte) {
	if s.mode == terraformModeHeredoc {
		if s.closesHeredoc(text) {
			// The body of the heredoc ends: the scan returns to the code
			// that holds the marker.
			s.mode = terraformModeCode
			s.marker = nil
			s.body = 0
			return
		}
		s.body++
		if s.body > s.heredoc {
			s.heredoc = s.body
		}
	}
	s.text(text)
}

// closesHeredoc reports whether a line closes the open heredoc: the marker
// alone on the line, spaces around it allowed.
func (s *terraformRawScanner) closesHeredoc(text []byte) bool {
	return bytes.Equal(bytes.TrimSpace(text), s.marker)
}

// text reads the bytes of a line with the mode the scan is in.
func (s *terraformRawScanner) text(text []byte) {
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch s.mode {
		case terraformModeCode:
			switch {
			case c == '"':
				s.push(terraformFrame{closer: '"', restore: terraformModeCode})
				s.mode = terraformModeString
			case c == '#':
				// The rest of the line is a comment.
				return
			case c == '/' && i+1 < len(text) && text[i+1] == '/':
				// The rest of the line is a comment.
				return
			case c == '/' && i+1 < len(text) && text[i+1] == '*':
				s.push(terraformFrame{restore: terraformModeCode})
				s.mode = terraformModeComment
				i++
			case c == '<' && i+1 < len(text) && text[i+1] == '<':
				marker, ok := terraformHeredocMarker(text[i+2:])
				if !ok {
					i++
					break
				}
				// The body of the heredoc starts on the next line.
				s.marker = marker
				s.mode = terraformModeHeredoc
				return
			case c == '{' || c == '[' || c == '(':
				s.push(terraformFrame{closer: terraformCloser(c), restore: terraformModeCode, level: true})
				s.open()
			case c == '}' || c == ']' || c == ')':
				s.close(terraformCloser(c))
			}
		case terraformModeString:
			switch {
			case c == '\\':
				// The next byte is escaped.
				i++
			case c == '"':
				s.pop()
			case (c == '$' || c == '%') && i+1 < len(text) && text[i+1] == '{':
				s.push(terraformFrame{closer: '}', restore: terraformModeString, level: true})
				s.open()
				s.mode = terraformModeCode
				i++
			}
		case terraformModeComment:
			if c == '*' && i+1 < len(text) && text[i+1] == '/' {
				s.pop()
				i++
			}
		case terraformModeHeredoc:
			// The body of a heredoc holds no nesting, except for the
			// interpolations it opens.
			if (c == '$' || c == '%') && i+1 < len(text) && text[i+1] == '{' {
				s.push(terraformFrame{closer: '}', restore: terraformModeHeredoc, level: true})
				s.open()
				s.mode = terraformModeCode
				i++
			}
		}
	}
}

// push opens a frame.
func (s *terraformRawScanner) push(frame terraformFrame) {
	s.stack = append(s.stack, frame)
}

// pop closes the open frame and returns to the mode it holds.
func (s *terraformRawScanner) pop() {
	if len(s.stack) == 0 {
		return
	}
	frame := s.stack[len(s.stack)-1]
	s.stack = s.stack[:len(s.stack)-1]
	if frame.level {
		s.depth--
	}
	s.mode = frame.restore
}

// close closes the open frame the given character closes. A frame that
// another character closes is left open: a malformed file never counts as
// a deeper nesting.
func (s *terraformRawScanner) close(closer byte) {
	if len(s.stack) == 0 {
		return
	}
	if s.stack[len(s.stack)-1].closer != closer {
		return
	}
	s.pop()
}

// open counts one more level of nesting.
func (s *terraformRawScanner) open() {
	s.depth++
	if s.depth > s.maxDepth {
		s.maxDepth = s.depth
	}
}

// terraformCloser returns the character that closes the given bracket.
func terraformCloser(bracket byte) byte {
	switch bracket {
	case '{':
		return '}'
	case '[':
		return ']'
	}
	return ')'
}

// terraformHeredocMarker reads the heredoc marker that starts the given
// text: an optional "-" and an identifier. It returns the identifier of
// the marker. ok is false when the text does not start with a marker.
func terraformHeredocMarker(text []byte) (marker []byte, ok bool) {
	i := 0
	if i < len(text) && text[i] == '-' {
		i++
	}
	if i >= len(text) || !terraformIdentStart(text[i]) {
		return nil, false
	}
	start := i
	for i < len(text) && terraformIdentByte(text[i]) {
		i++
	}
	return text[start:i], true
}

// terraformIdentStart reports whether a byte can start an identifier.
func terraformIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

// terraformIdentByte reports whether a byte can be part of an identifier.
func terraformIdentByte(c byte) bool {
	return terraformIdentStart(c) || (c >= '0' && c <= '9') || c == '-'
}

func terraformString(attr *hclsyntax.Attribute) string {
	if attr == nil {
		return ""
	}
	value, _ := terraformStringResult(attr.Expr)
	return value
}

// terraformStringResult returns the literal string of an expression. Only
// strings are literal here: a key is always a string.
func terraformStringResult(expr hclsyntax.Expression) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch value := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if value.Val.Type() == cty.String {
			return value.Val.AsString(), true
		}
	case *hclsyntax.ObjectConsKeyExpr:
		if !value.ForceNonLiteral {
			if keyword := hcl.ExprAsKeyword(value.Wrapped); keyword != "" {
				return keyword, true
			}
		}
		return terraformStringResult(value.Wrapped)
	case *hclsyntax.TemplateExpr:
		if len(value.Parts) == 1 {
			return terraformStringResult(value.Parts[0])
		}
	}
	return "", false
}

// terraformScalarResult renders a literal expression the way yamlencode
// would: a string as it is, a bool as true or false, a number in its
// literal form. ok is false for every expression that is not a literal.
func terraformScalarResult(expr hclsyntax.Expression) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch value := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		return terraformCtyScalar(value.Val)
	case *hclsyntax.ObjectConsKeyExpr:
		if !value.ForceNonLiteral {
			if keyword := hcl.ExprAsKeyword(value.Wrapped); keyword != "" {
				return keyword, true
			}
		}
		return terraformScalarResult(value.Wrapped)
	case *hclsyntax.TemplateExpr:
		if len(value.Parts) == 1 {
			return terraformScalarResult(value.Parts[0])
		}
	}
	return "", false
}

// terraformCtyScalar renders a literal value the way yamlencode would.
func terraformCtyScalar(value cty.Value) (string, bool) {
	switch value.Type() {
	case cty.String:
		return value.AsString(), true
	case cty.Bool:
		if value.True() {
			return "true", true
		}
		return "false", true
	case cty.Number:
		return value.AsBigFloat().Text('f', -1), true
	}
	return "", false
}

// terraformStaticString renders only literal HCL template parts and replaces
// every computed part with the redaction placeholder. It never evaluates the
// expression or reads variables, functions, files, or environment values.
func terraformStaticString(expr hclsyntax.Expression) (string, bool) {
	if expr == nil {
		return "", true
	}
	switch value := expr.(type) {
	case *hclsyntax.LiteralValueExpr:
		if value.Val.Type() == cty.String {
			return value.Val.AsString(), false
		}
		return "", true
	case *hclsyntax.TemplateExpr:
		var b strings.Builder
		templated := false
		for _, part := range value.Parts {
			if text, literal := terraformStringResult(part); literal {
				b.WriteString(text)
				continue
			}
			b.WriteString(terraformTemplatePlaceholder)
			templated = true
		}
		return b.String(), templated
	case *hclsyntax.TemplateWrapExpr:
		_, templated := terraformStaticString(value.Wrapped)
		return terraformTemplatePlaceholder, templated
	default:
		return terraformTemplatePlaceholder, true
	}
}

// terraformObjectItem returns the value of an object key.
func terraformObjectItem(obj *hclsyntax.ObjectConsExpr, key string) (hclsyntax.Expression, bool) {
	if obj == nil {
		return nil, false
	}
	for _, item := range obj.Items {
		name, ok := terraformStringResult(item.KeyExpr)
		if ok && name == key {
			return item.ValueExpr, true
		}
	}
	return nil, false
}

// terraformObjectScalar returns the literal string value of an object key.
func terraformObjectScalar(obj *hclsyntax.ObjectConsExpr, key string) (string, bool) {
	expr, ok := terraformObjectItem(obj, key)
	if !ok {
		return "", false
	}
	return terraformScalarResult(expr)
}

// terraformObjectIsSecret reports whether an object declares kind: Secret.
// Nothing under a Secret is scanned or printed, at any depth (spec section 6).
func terraformObjectIsSecret(obj *hclsyntax.ObjectConsExpr) bool {
	kind, ok := terraformObjectScalar(obj, "kind")
	return ok && strings.EqualFold(kind, "Secret")
}

// terraformObjectRegistry returns the global image registry of a values
// object: the imageRegistry of its global mapping, at any depth.
func terraformObjectRegistry(obj *hclsyntax.ObjectConsExpr) string {
	if obj == nil {
		return ""
	}
	for _, item := range obj.Items {
		name, ok := terraformStringResult(item.KeyExpr)
		if !ok {
			continue
		}
		child, isObject := item.ValueExpr.(*hclsyntax.ObjectConsExpr)
		if !isObject {
			continue
		}
		if name == "global" {
			if registry, literal := terraformObjectScalar(child, "imageRegistry"); literal {
				return registry
			}
		}
		if registry := terraformObjectRegistry(child); registry != "" {
			return registry
		}
	}
	return ""
}

// terraformObjectImageTriple returns the image reference of an image
// triple, a mapping with an image-shaped repository, and the expression of
// its repository leaf. A dynamic component (a tag, registry or digest that
// is not a literal) keeps the redaction placeholder: the reference is then
// unresolved, and the rule is chosen from the static part (spec section
// 2.2). ok is false for any other mapping.
func terraformObjectImageTriple(obj *hclsyntax.ObjectConsExpr, globalRegistry string) (imageref.Reference, hclsyntax.Expression, bool) {
	repo, ok := terraformObjectScalar(obj, "repository")
	if !ok || !isImageShaped(repo) {
		return imageref.Reference{}, nil, false
	}
	registry, registryDynamic := terraformObjectComponent(obj, "registry")
	if registry == "" && !registryDynamic {
		registry = globalRegistry
	}
	tag, _ := terraformObjectComponent(obj, "tag")
	digest, _ := terraformObjectComponent(obj, "digest")
	ref := imageref.Join(registry, repo, tag)
	if digest != "" {
		ref = imageref.Parse(ref.Original + "@" + digest)
	}
	if !isWholeImageScalar(terraformReferenceShape(ref.Original)) {
		// A triple whose reference is not a whole image path is not an
		// image (spec section 9).
		return imageref.Reference{}, nil, false
	}
	expr, _ := terraformObjectItem(obj, "repository")
	return ref, expr, true
}

// terraformObjectComponent returns the static rendering of a component of
// an image triple and whether the component is dynamic. A dynamic component
// has no literal value: its rendering keeps the redaction placeholder, so
// the reference of the triple stays unresolved (spec section 2.2).
func terraformObjectComponent(obj *hclsyntax.ObjectConsExpr, key string) (string, bool) {
	expr, ok := terraformObjectItem(obj, key)
	if !ok {
		return "", false
	}
	if text, literal := terraformScalarResult(expr); literal {
		return text, false
	}
	static, templated := terraformStaticString(expr)
	return static, templated
}

// terraformReferenceShape returns the static shape of a reference: the
// reference without its templated segments. The shape is the whole-scalar
// check of a reference whose dynamic part is not known (spec section 9).
func terraformReferenceShape(value string) string {
	shape := strings.ReplaceAll(value, terraformTemplatePlaceholder, "")
	if strings.HasPrefix(value, terraformTemplatePlaceholder) {
		// A templated registry: the shape starts at the repository.
		shape = strings.TrimPrefix(shape, "/")
	}
	return shape
}

func terraformImagePath(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return name == "image" || strings.HasSuffix(name, ".repository") || strings.HasSuffix(name, ".image") || strings.HasSuffix(name, "image.repository")
}

// terraformOCIChart returns the chart component of an exact Bitnami OCI
// chart reference. The component is the path segment without its tag or
// digest. ok is false for any other value.
func terraformOCIChart(value string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range terraformOCIPrefixes {
		if !strings.HasPrefix(v, prefix) {
			continue
		}
		remainder := v[len(prefix):]
		if remainder == "" || strings.ContainsAny(remainder, "/?#") {
			return "", false
		}
		component := terraformStripTagDigest(remainder)
		if component == "" {
			return "", false
		}
		return component, true
	}
	return "", false
}

// terraformChartHasStaticEvidence reports whether the chart literal points
// at the Bitnami OCI namespace without being a plain chart path. A name that
// only contains "bitnamicharts" is not evidence.
func terraformChartHasStaticEvidence(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range terraformOCIPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// terraformStripTagDigest removes the tag and the digest of a reference.
func terraformStripTagDigest(value string) string {
	v := value
	if at := strings.IndexByte(v, '@'); at >= 0 {
		v = v[:at]
	}
	slash := strings.LastIndexByte(v, '/')
	if colon := strings.LastIndexByte(v, ':'); colon > slash {
		v = v[:colon]
	}
	return v
}

// terraformOCILastComponent returns the last path segment of an OCI
// reference, without its tag or digest.
func terraformOCILastComponent(value string) string {
	v := terraformStripTagDigest(value)
	if i := strings.LastIndexByte(v, '/'); i >= 0 {
		v = v[i+1:]
	}
	return strings.ToLower(strings.Trim(v, "/:"))
}

// terraformOCIChartComponent returns the chart name of a Bitnami OCI
// reference whose name may be dynamic. Only the static part before the
// first templated segment is evidence: a name that starts with a template
// segment stays unknown.
func terraformOCIChartComponent(value string) string {
	static := value
	if i := strings.Index(static, terraformTemplatePlaceholder); i >= 0 {
		static = static[:i]
	}
	component := terraformOCILastComponent(static)
	if component == "" || strings.Contains(component, terraformTemplatePlaceholder) {
		return ""
	}
	return component
}

// dedupeTerraformFindings drops the repeated findings of one reference. An
// anchor and the aliases that refer to it are one logical reference, so the
// finding with the strongest confidence is kept: a known image key is
// stronger evidence than the unknown-key fallback of the anchor (spec
// section 5).
func dedupeTerraformFindings(in []diag.Finding) []diag.Finding {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]int, len(in))
	out := in[:0]
	for _, finding := range in {
		key := fallbackKey(finding)
		index, ok := seen[key]
		if !ok {
			seen[key] = len(out)
			out = append(out, finding)
			continue
		}
		if terraformConfidenceRank(finding.Confidence) < terraformConfidenceRank(out[index].Confidence) {
			out[index] = finding
		}
	}
	return out
}

// terraformConfidenceRank orders the confidences from the strongest to the
// weakest: confirmed beats inferred beats unresolved.
func terraformConfidenceRank(confidence diag.Confidence) int {
	switch confidence {
	case diag.ConfidenceConfirmed:
		return 0
	case diag.ConfidenceInferred:
		return 1
	case diag.ConfidenceUnresolved:
		return 2
	}
	return 3
}

func terraformSafeReference(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for i := 0; i < len(value); {
		dollar := strings.Index(value[i:], "${")
		helm := strings.Index(value[i:], "{{")
		open := -1
		if dollar >= 0 && (helm < 0 || dollar <= helm) {
			open = i + dollar
		} else if helm >= 0 {
			open = i + helm
		}
		if open < 0 {
			b.WriteString(value[i:])
			break
		}
		b.WriteString(value[i:open])
		b.WriteString(terraformTemplatePlaceholder)
		if strings.HasPrefix(value[open:], "${") {
			if end := strings.Index(value[open+2:], "}"); end >= 0 {
				i = open + 2 + end + 1
				continue
			}
		} else if end := strings.Index(value[open+2:], "}}"); end >= 0 {
			i = open + 2 + end + 2
			continue
		}
		i = len(value)
	}
	return b.String()
}

func utf8Valid(data []byte) bool {
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			return false
		}
		data = data[size:]
	}
	return true
}
