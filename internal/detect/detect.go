// Package detect contains pure detectors over parsed YAML and Dockerfile text.
package detect

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	maxYAMLDepth      = 256
	maxDockerfileLine = 1024 * 1024
)

// MaxFindingsPerFile bounds the findings one scanned file reports (spec
// section 3). A file with more findings keeps the first ones, in the order
// they were found, and reports the limit as a DSD-SCN-005 warning.
const MaxFindingsPerFile = diag.MaxFindingsPerFile

// MaxDockerfileContinuationLines bounds the continuation lines of one logical
// Dockerfile instruction (spec section 3). A longer chain is not scanned and is
// reported as a DSD-SCN-005 warning.
const MaxDockerfileContinuationLines = 10000

// YAML inspects all YAML documents and retains one-based positions.
func YAML(path string, data []byte) diag.Report {
	data = stripBOM(data)
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out diag.Report
	// The state belongs to the file, not to one document: the whole-scalar
	// fallback and the deduplication are one pass over the findings of the
	// file, never one pass per document (spec sections 5 and 9).
	file := fileScan{fallbackSeen: map[string]bool{}}
	// The Helmfile state belongs to the file, not to one document: the
	// documents of a file are resolved together (spec section 9).
	var helmfileState *helmfileFile
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
		if err := GuardYAML(root); err != nil {
			out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, root.Line, root.Column, err.Error()))
			continue
		}
		if strings.EqualFold(findString(root, []string{"kind"}), "Secret") {
			continue
		}
		s := walkState{path: path, data: data, globalRegistry: findString(root, []string{"global", "imageRegistry"}), out: &out, file: &file}
		if isHelmfile(path) {
			if helmfileState == nil {
				helmfileState = newHelmfileFile()
			}
			s.helmfile = helmfileState
		}
		from := len(out.Findings)
		s.scanDocument(root)
		s.scanFallback(root, from)
		if file.limitHit {
			// The file reached the per-file finding limit: the rest of the
			// file is not scanned, so the cost of the scan stays bounded
			// (spec section 3).
			break
		}
	}
	// The deduplication runs once per file: an anchor and its alias uses are
	// one logical reference, reported once at the anchor (spec section 5).
	out.Findings = diag.DedupeFindings(out.Findings)
	reportFindingLimit(&out, path, &file)
	return out
}

// fileScan is the state one scanned file shares with its documents: the
// findings already reported and the limits that bound the scan (spec
// sections 3 and 9). It is built once per file, so the documents of a file
// never rebuild it.
type fileScan struct {
	// fallbackSeen holds the keys of the findings already reported, so the
	// whole-scalar fallback of a document is compared with the findings of
	// the whole file without rebuilding a map (spec section 9).
	fallbackSeen map[string]bool
	// limitHit records that the per-file finding limit was reached.
	limitHit bool
	// limitLocation is the position of the first finding that was not kept.
	limitLocation diag.Location
}

// reportFindingLimit bounds the findings of a file to the per-file limit and
// reports the limit as a DSD-SCN-005 diagnostic (spec section 3). The limit is
// never a silent truncation.
func reportFindingLimit(out *diag.Report, path string, file *fileScan) {
	kept, dropped := diag.CapFindings(out.Findings, MaxFindingsPerFile)
	out.Findings = kept
	if !dropped && !file.limitHit {
		return
	}
	out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, file.limitLocation.Line, file.limitLocation.Column, fmt.Sprintf("finding limit reached: %d findings per file", MaxFindingsPerFile)))
}

type walkState struct {
	path                   string
	keys                   []string
	globalRegistry         string
	depthReported          bool
	aliasLimitReported     bool
	templateComment        bool
	suppressedHelmfileURLs map[[2]int]bool
	shellScriptNodes       map[*yaml.Node]bool
	// helmfile is the state of the Helmfile file being scanned. It is
	// shared by the documents of the file and belongs to one scan, so two
	// scans never share it.
	helmfile *helmfileFile
	// data is the raw file content, used to resolve the column of a YAML
	// block scalar's content (spec 9.2).
	data []byte
	// file is the state of the file being scanned, shared by its documents.
	// It holds the findings already reported and the per-file finding
	// limit (spec sections 3 and 9). It is nil for a scan of one document
	// that has no file state.
	file *fileScan
	out  *diag.Report
}

func (s *walkState) walk(n *yaml.Node, lineOffset, depth int, embedded bool) {
	if depth > maxYAMLDepth {
		if !s.depthReported {
			s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, n.Line+lineOffset, n.Column, "YAML depth limit reached"))
			s.depthReported = true
		}
		return
	}
	if isSecretMapping(n) {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			s.keys = append(s.keys, k.Value)
			if pathEnds(s.keys, "global", "security", "allowInsecureImages") && v.Tag == "!!bool" {
				var enabled bool
				if v.Decode(&enabled) == nil && enabled {
					s.addFinding(diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, v.Line+lineOffset, v.Column), Reference: "true", Original: "true", Attributes: []string{}})
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
				s.addFinding(diag.Finding{RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: impact, Component: component, Location: loc(s.path, v.Line+lineOffset, v.Column), Reference: strings.TrimSpace(v.Value), Original: strings.TrimSpace(v.Value), Attributes: []string{"chart"}})
			}
			if k.Value == "uses" && v.Kind == yaml.ScalarNode && strings.HasPrefix(v.Value, "docker://") {
				s.addImage(strings.TrimPrefix(v.Value, "docker://"), v.Line+lineOffset, v.Column, embedded)
			}
			if k.Value == "values" && v.Kind == yaml.ScalarNode && strings.TrimSpace(v.Value) != "" {
				var sub yaml.Node
				if err := yaml.Unmarshal([]byte(v.Value), &sub); err != nil {
					s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, s.path, embeddedLineOffset(v)+lineOffset+1, v.Column, "malformed embedded values"))
				} else if len(sub.Content) > 0 {
					s.walk(sub.Content[0], embeddedLineOffset(v)+lineOffset, depth+1, true)
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

// addRefConfidence records the v0.1 outcome for one reference at a position.
// forceInferred marks a reference found inside a template action, whose runtime
// value is not certain (section 9.1).
func (s *walkState) addRefConfidence(r imageref.Reference, line, column int, embedded bool, forceInferred bool) {
	c, ok, unresolved := ClassifyReference(r, embedded, forceInferred)
	switch {
	case unresolved:
		s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-003", diag.LevelInfo, s.path, line, column, "unresolved reference without Bitnami evidence"))
	case ok:
		s.addFinding(diag.Finding{RuleID: c.Rule, Severity: c.Severity, Confidence: c.Confidence, Impact: c.Impact, Component: c.Component, Location: loc(s.path, line, column), Reference: c.Reference, Original: c.Original, Attributes: c.Attributes})
	}
}

// addFinding reports one finding of the file. The per-file finding limit
// bounds the report of a hostile file: the first findings are kept, in the
// order they were found, and the limit is reported once as DSD-SCN-005
// (spec section 3).
func (s *walkState) addFinding(f diag.Finding) {
	if s.file != nil && len(s.out.Findings) >= MaxFindingsPerFile {
		if !s.file.limitHit {
			s.file.limitHit = true
			s.file.limitLocation = f.Location
		}
		return
	}
	s.out.Findings = append(s.out.Findings, f)
}

// Classification is the v0.1 rule-selection outcome for one image reference
// (spec v0.1 section 2.1).
type Classification struct {
	Rule       string
	Severity   diag.Severity
	Confidence diag.Confidence
	Impact     diag.Impact
	Component  string
	Attributes []string
	Reference  string
	Original   string
}

// ClassifyReference applies the v0.1 rule selection to a parsed image
// reference (spec v0.1 section 2.1). ok is false when the reference is not a
// reportable Bitnami dependency; unresolved is true for the DSD-SCN-003 case (a
// diagnostic, not a finding), never together with ok. The cluster scan reuses
// this selection (spec v0.2 section 3).
func ClassifyReference(r imageref.Reference, embedded, forceInferred bool) (c Classification, ok, unresolved bool) {
	if r.IsExcluded() {
		return Classification{}, false, false
	}
	if r.Classification == imageref.Unresolved && !r.HasStaticEvidence {
		return Classification{}, false, true
	}
	if !r.HasStaticEvidence {
		return Classification{}, false, false
	}
	rule := ""
	sev := diag.SeverityHigh
	attrs := []string{}
	switch r.Classification {
	case imageref.BitnamiLegacy:
		rule = "DSD-IMG-001"
	case imageref.BitnamiSecure:
		switch {
		case r.Registry != "" && r.Registry != "docker.io":
			// A Bitnami namespace under another registry is a mirror or a
			// rebuild, not the Docker Hub community tier (spec 2.1, DSD-IMG-004).
			rule = "DSD-IMG-004"
			sev = diag.SeverityLow
		default:
			// The community tier is development-only whatever the tag; the
			// public-path pull risk of DSD-IMG-002 does not apply (spec 2.1).
			rule = "DSD-IMG-003"
			sev = diag.SeverityMedium
		}
	case imageref.Bitnami:
		switch {
		case r.Registry != "" && r.Registry != "docker.io":
			rule = "DSD-IMG-004"
			sev = diag.SeverityLow
		case r.Tag == "" && !r.Templated && r.Digest == "" || strings.EqualFold(r.Tag, "latest"):
			rule = "DSD-IMG-003"
			sev = diag.SeverityMedium
		default:
			rule = "DSD-IMG-002"
			attrs = append(attrs, "pull-risk")
		}
	default:
		return Classification{}, false, false
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
	return Classification{Rule: rule, Severity: sev, Confidence: confidence, Impact: catalog.Impact(r.Component()), Component: r.Component(), Attributes: attrs, Reference: r.Safe, Original: r.SafeOriginal}, true, false
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
	if isSecretMapping(n) {
		return
	}
	if n.Kind == yaml.MappingNode {
		if v := nodeAt(n, "global", "security", "allowInsecureImages"); v != nil && v.Tag == "!!bool" {
			var enabled bool
			if v.Decode(&enabled) == nil && enabled {
				s.addFinding(diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, v.Line, v.Column), Reference: "true", Original: "true", Attributes: []string{}})
			}
		}
	}
	for _, c := range n.Content {
		s.scanConfigAt(c, depth+1)
	}
}

// Dockerfile detects image references in FROM and external COPY instructions.
func Dockerfile(path string, data []byte) diag.Report {
	data = stripBOM(data)
	var out diag.Report
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line, start := 0, 0
	file := fileScan{fallbackSeen: map[string]bool{}}
	s := walkState{path: path, out: &out, file: &file}
	args, stages := map[string]string{}, map[string]bool{}
	seenFrom := false
	// The parts of the logical instruction are collected and joined once, so
	// a long continuation chain is built in linear time (spec section 3).
	var parts []string
	var raw strings.Builder
	inInstruction := false
	continuations := 0
	dropped := false
	limitReported := false
	var heredocs []heredoc
	var shellRuns []shellScriptValue
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if len(heredocs) > 0 {
			// Heredoc bodies are shell or file content, never Dockerfile
			// instructions: skip until the matching terminator (spec section 9).
			if heredocs[0].terminates(text) {
				heredocs = heredocs[1:]
			}
			continue
		}
		part := strings.TrimSpace(text)
		continued := strings.HasSuffix(part, "\\")
		part = strings.TrimSpace(strings.TrimSuffix(part, "\\"))
		if !inInstruction {
			start = line
			inInstruction = true
			continuations = 0
			dropped = false
			parts = parts[:0]
			raw.Reset()
			raw.WriteString(text)
		} else {
			continuations++
			if continuations > MaxDockerfileContinuationLines {
				// The chain is longer than the limit: the instruction is not
				// scanned and the rest of the chain is read but not kept, so
				// the next instructions are still scanned (spec section 3).
				dropped = true
				parts = parts[:0]
				raw.Reset()
				if !limitReported {
					limitReported = true
					out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, start, 1, "limit reached: Dockerfile continuation lines"))
				}
			}
			if !dropped {
				raw.WriteString("\n")
				raw.WriteString(text)
			}
			if dropped {
				if !continued {
					inInstruction = false
				}
				continue
			}
		}
		parts = append(parts, part)
		if continued {
			continue
		}
		inInstruction = false
		instruction := strings.TrimSpace(strings.Join(parts, " "))
		parts = parts[:0]
		heredocs = heredocDelimiters(instruction)
		f := strings.Fields(instruction)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(heredocs) == 0 && strings.EqualFold(f[0], "RUN") {
			rawText := raw.String()
			rawValue := strings.TrimLeft(rawText, " \t")
			prefix := len(rawText) - len(rawValue)
			if len(rawValue) >= len(f[0]) {
				content, removed := stripDockerRunFlags(rawValue[len(f[0]):])
				shellRuns = append(shellRuns, shellScriptValue{value: content, origin: shellOrigin{line: start, column: prefix + len(f[0]) + 1 + removed}})
			}
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
	s.scanShellValues(shellRuns)
	reportFindingLimit(&out, path, &file)
	return out
}

// stripDockerRunFlags removes the BuildKit flags that may lead a RUN
// instruction (--mount, --network, --security) and returns the remaining
// command with the number of characters removed, so the first token of the
// command keeps its column in the file.
func stripDockerRunFlags(content string) (string, int) {
	rest := content
	removed := 0
	flags := 0
	for {
		trimmed := strings.TrimLeft(rest, " \t")
		skip := len(rest) - len(trimmed)
		if !strings.HasPrefix(trimmed, "--") {
			if flags > 0 {
				removed += skip
				rest = trimmed
			}
			break
		}
		end := strings.IndexAny(trimmed, " \t")
		token := trimmed
		if end >= 0 {
			token = trimmed[:end]
		}
		name, _, hasValue := strings.Cut(token, "=")
		if name != "--mount" && name != "--network" && name != "--security" {
			break
		}
		removed += skip
		rest = trimmed
		flags++
		if end < 0 {
			removed += len(trimmed)
			rest = ""
			break
		}
		removed += end + 1
		rest = trimmed[end+1:]
		if hasValue {
			continue
		}
		// The flag takes its value as the next token.
		valueEnd := strings.IndexAny(rest, " \t")
		if valueEnd < 0 {
			removed += len(rest)
			rest = ""
			break
		}
		removed += valueEnd
		rest = rest[valueEnd:]
	}
	if flags == 0 {
		return content, 0
	}
	return rest, removed
}

// expandDockerArgs substitutes ${NAME} and $NAME variable tokens from the ARG
// defaults. Tokens are parsed, so a name is never rewritten as a substring of a
// longer one and the result does not depend on map iteration order (spec 10).
func expandDockerArgs(v string, args map[string]string) string {
	if len(args) == 0 || !strings.Contains(v, "$") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); {
		if v[i] != '$' {
			b.WriteByte(v[i])
			i++
			continue
		}
		if j := i + 1; j < len(v) && v[j] == '{' {
			if end := strings.IndexByte(v[j+1:], '}'); end >= 0 {
				name := v[j+1 : j+1+end]
				if value, ok := args[name]; ok {
					b.WriteString(value)
				} else {
					b.WriteString(v[i : j+1+end+1])
				}
				i = j + 1 + end + 1
				continue
			}
			b.WriteByte(v[i])
			i++
			continue
		}
		j := i + 1
		for j < len(v) && isArgNameByte(v[j]) {
			j++
		}
		if j == i+1 {
			b.WriteByte(v[i])
			i++
			continue
		}
		if value, ok := args[v[i+1:j]]; ok {
			b.WriteString(value)
		} else {
			b.WriteString(v[i:j])
		}
		i = j
	}
	return b.String()
}

func isArgNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
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

// knownImageKeys are the mapping keys the specific detectors already resolve as
// image references (spec section 9). The whole-scalar fallback never reports
// them again, so no scalar is counted twice; a Bitnami chart repository URL
// inside them is still a chart finding.
var knownImageKeys = map[string]bool{
	"annotations": true, "chart": true, "container": true, "digest": true,
	"home": true, "image": true, "imageRegistry": true, "images": true,
	"name": true, "newName": true, "registry": true, "repository": true,
	"repoURL": true, "services": true, "sources": true, "tag": true,
	"url": true, "uses": true, "values": true, "valuesObject": true,
}

var bitnamiChartURLs = []string{
	"https://charts.bitnami.com/bitnami",
	"oci://registry-1.docker.io/bitnamicharts",
	"oci://docker.io/bitnamicharts",
}

// scanFallback reports the whole-scalar fallback findings of one document and
// drops the ones that repeat a finding already reported (spec section 9).
// from is the index of the first finding the specific detectors of the
// document reported. The state is the one of the file: the map of the reported
// findings is built once and updated as the documents are scanned, so the
// fallback costs the findings of the document and never the findings of the
// whole file.
func (s *walkState) scanFallback(root *yaml.Node, from int) {
	before := len(s.out.Findings)
	s.scanFallbacks(root)
	if s.file != nil {
		// The findings the specific detectors of the document reported are
		// the ones a fallback must not repeat.
		for _, f := range s.out.Findings[from:before] {
			s.file.fallbackSeen[fallbackKey(f)] = true
		}
	}
	s.dropDuplicateFallbacks(before)
}

// dropDuplicateFallbacks removes whole-scalar fallback findings that repeat a
// rule already reported at the same file and line by a specific detector, or by
// an earlier fallback finding: one scalar is never counted twice (spec section
// 9). Findings added before from are left untouched.
func (s *walkState) dropDuplicateFallbacks(from int) {
	if from >= len(s.out.Findings) {
		return
	}
	var seen map[string]bool
	if s.file != nil {
		seen = s.file.fallbackSeen
	} else {
		seen = make(map[string]bool, from)
		for _, f := range s.out.Findings[:from] {
			seen[fallbackKey(f)] = true
		}
	}
	kept := s.out.Findings[:from]
	for _, f := range s.out.Findings[from:] {
		key := fallbackKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, f)
	}
	s.out.Findings = kept
}

func fallbackKey(f diag.Finding) string {
	return f.RuleID + "\x00" + f.Location.Path + "\x00" + strconv.Itoa(f.Location.Line)
}

// scanFallbacks applies the whole-scalar fallback (spec section 9): a whole
// scalar image reference under a key no detector knows, and a Bitnami chart
// repository URL inside any scalar, in any YAML file.
func (s *walkState) scanFallbacks(root *yaml.Node) { s.scanFallbackAt(root, "", 0) }

func (s *walkState) scanFallbackAt(n *yaml.Node, key string, depth int) {
	if n == nil || depth > maxYAMLDepth {
		return
	}
	if isSecretMapping(n) {
		return
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			s.scanFallbackAt(n.Content[i+1], n.Content[i].Value, depth+1)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			s.scanFallbackAt(c, key, depth+1)
		}
	case yaml.ScalarNode:
		s.scanFallbackScalar(n, key)
	}
}

func (s *walkState) scanFallbackScalar(n *yaml.Node, key string) {
	if s.shellScriptNodes[n] {
		return
	}
	_, suppressed := s.suppressedHelmfileURLs[[2]int{n.Line, n.Column}]
	if url, ok := chartURLIn(n.Value); ok && !suppressed {
		s.addFinding(diag.Finding{RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, n.Line, n.Column), Reference: url, Original: url, Attributes: []string{"chart"}})
	}
	if knownImageKeys[key] || !isWholeImageScalar(n.Value) {
		return
	}
	if r := imageref.Parse(n.Value); r.HasStaticEvidence {
		s.addRefConfidence(r, n.Line, n.Column, false, true)
	}
}

// isWholeImageScalar reports whether a YAML scalar is exactly one image
// reference. Filesystem paths, prose, shell fragments and URLs are rejected so
// that partial matches are never findings (spec section 9).
func isWholeImageScalar(v string) bool {
	if v == "" || v != strings.TrimSpace(v) || !strings.Contains(v, "/") {
		return false
	}
	if strings.HasPrefix(v, "/") || strings.HasSuffix(v, "/") || strings.Contains(v, "//") {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == '/', c == ':', c == '@':
		default:
			return false
		}
	}
	return true
}

// chartURLIn returns the Bitnami chart repository URL inside a scalar, if any
// (spec section 9: any scalar in any file, including inside a longer scalar).
func chartURLIn(v string) (string, bool) {
	lower := strings.ToLower(v)
	for _, u := range bitnamiChartURLs {
		i := strings.Index(lower, u)
		if i < 0 {
			continue
		}
		end := i + len(u)
		if end < len(v) && v[end] == '/' {
			end++
		}
		if end < len(v) && isReferenceChar(v[end]) {
			continue
		}
		return strings.TrimSpace(v[i:end]), true
	}
	return "", false
}

func isReferenceChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.', c == '-', c == '_':
		return true
	}
	return false
}

// stripBOM removes a UTF-8 byte order mark at the start of a text file, so a
// BOM cannot hide the first instruction or mapping key (spec section 9).
func stripBOM(data []byte) []byte {
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return data[3:]
	}
	return data
}

// isSecretMapping reports whether n is a mapping that declares kind: Secret.
// Nothing under a Secret is scanned or printed, at any depth (spec section 6).
func isSecretMapping(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.MappingNode && strings.EqualFold(valueAt(n, "kind"), "Secret")
}

// heredoc is one pending Dockerfile heredoc body.
type heredoc struct {
	name string
	dash bool
}

// terminates reports whether line closes the heredoc body. A <<- heredoc
// accepts a terminator indented with tabs.
func (h heredoc) terminates(line string) bool {
	line = strings.TrimRight(line, "\r")
	if h.dash {
		line = strings.TrimLeft(line, "\t")
	}
	return line == h.name
}

// heredocDelimiters returns the heredoc bodies a shell instruction opens, in
// order: <<EOF, <<-EOF, <<'EOF' and <<"EOF" are all recognized (spec 9).
func heredocDelimiters(instruction string) []heredoc {
	var out []heredoc
	for i := 0; i+1 < len(instruction); i++ {
		if instruction[i] != '<' || instruction[i+1] != '<' {
			continue
		}
		j := i + 2
		dash := false
		if j < len(instruction) && instruction[j] == '-' {
			dash = true
			j++
		}
		quote := byte(0)
		if j < len(instruction) && (instruction[j] == '\'' || instruction[j] == '"') {
			quote = instruction[j]
			j++
		}
		k := j
		for k < len(instruction) && isArgNameByte(instruction[k]) {
			k++
		}
		if k == j {
			continue
		}
		if quote != 0 && (k >= len(instruction) || instruction[k] != quote) {
			continue
		}
		out = append(out, heredoc{name: instruction[j:k], dash: dash})
		i = k
	}
	return out
}
