package detect

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
)

var (
	templateAction    = regexp.MustCompile(`\{\{[\s\S]*?\}\}`)
	templateComment   = regexp.MustCompile(`\{\{-?\s*/\*[\s\S]*?\*/\s*-?\}\}`)
	templateKeyLine   = regexp.MustCompile(`^\s*-?\s*image\s*:\s*(.*)$`)
	templateValueLine = regexp.MustCompile(`^(\s*)-?\s*([A-Za-z][A-Za-z0-9]*)\s*:\s*(.*)$`)
	templateLiteral   = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
)

// HasTemplateMarkers reports whether data contains a Go template action.
func HasTemplateMarkers(data []byte) bool { return bytes.Contains(data, []byte("{{")) }

// Malformed reports whether a YAML scan produced a malformed-file diagnostic.
func Malformed(r diag.Report) bool {
	for _, d := range r.Diagnostics {
		if d.Code == "DSD-SCN-001" {
			return true
		}
	}
	return false
}

// Template scans Helm template text line by line (spec section 9.1). It never
// prints a template body: only the static part of a reference is reported.
func Template(path string, data []byte) diag.Report {
	data = stripBOM(data)
	var out diag.Report
	out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-007", diag.LevelInfo, path, 0, 0, "file read as template text"))
	s := walkState{path: path, out: &out}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line := 0
	for scanner.Scan() {
		line++
		s.scanTemplateLine(scanner.Text(), line)
	}
	if scanner.Err() != nil {
		out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, line+1, 1, "template line length limit reached"))
	}
	s.scanTemplateValues(data)
	if isHelmfile(path) {
		s.scanHelmfileTemplate(data)
	}
	return out
}

func (s *walkState) scanTemplateLine(text string, line int) {
	if s.templateComment {
		end := strings.Index(text, "*/}}")
		if end < 0 {
			return
		}
		text = text[end+len("*/}}"):]
		s.templateComment = false
	}
	if i := strings.Index(text, "{{/*"); i >= 0 {
		end := strings.Index(text[i:], "*/}}")
		if end < 0 {
			text = text[:i]
			s.templateComment = true
		} else {
			text = text[:i] + text[i+end+len("*/}}"):]
		}
	}
	text = templateComment.ReplaceAllString(text, "")
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return
	}
	literalFound := false
	for _, block := range templateAction.FindAllString(text, -1) {
		for _, m := range templateLiteral.FindAllStringSubmatch(block, -1) {
			value := m[1]
			if value == "" {
				value = m[2]
			}
			if value == "" {
				continue
			}
			r := imageref.Parse(value)
			if !r.HasStaticEvidence {
				continue
			}
			s.addRefConfidence(r, line, strings.Index(text, block)+1, false, true)
			literalFound = true
		}
	}
	m := templateKeyLine.FindStringSubmatch(text)
	if m == nil {
		return
	}
	raw := m[1]
	value := templateScalar(raw)
	if value == "" {
		return
	}
	if r := imageref.Parse(value); r.HasStaticEvidence {
		s.addRef(r, line, strings.Index(text, raw)+1, false)
		return
	}
	if literalFound {
		return
	}
	s.addRef(imageref.Parse(value), line, strings.Index(text, raw)+1, false)
}

type templateImage struct {
	indent, line, column      int
	registry, repository, tag string
}

func (s *walkState) scanTemplateValues(data []byte) {
	var images []templateImage
	type keyAt struct {
		indent int
		key    string
	}
	var keys []keyAt
	flush := func(indent int) {
		for len(images) > 0 && images[len(images)-1].indent >= indent {
			image := images[len(images)-1]
			images = images[:len(images)-1]
			if isImageShaped(image.repository) {
				s.addRef(imageref.Join(image.registry, image.repository, image.tag), image.line, image.column, false)
			}
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "{{") {
			continue
		}
		m := templateValueLine.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		indent, key, raw := len(m[1]), m[2], m[3]
		for len(keys) > 0 && keys[len(keys)-1].indent >= indent {
			keys = keys[:len(keys)-1]
		}
		if key == "allowInsecureImages" && templateScalar(raw) == "true" && len(keys) >= 2 && keys[len(keys)-2].key == "global" && keys[len(keys)-1].key == "security" {
			s.addFinding(diag.Finding{RuleID: "DSD-CFG-001", Severity: diag.SeverityHigh, Confidence: diag.ConfidenceConfirmed, Impact: diag.ImpactUnknown, Location: loc(s.path, line, strings.Index(text, raw)+1), Reference: "true", Original: "true", Attributes: []string{}})
		}
		keys = append(keys, keyAt{indent: indent, key: key})
		imageKey := key == "registry" || key == "repository" || key == "tag"
		if !imageKey {
			flush(indent)
			continue
		}
		if len(images) == 0 || images[len(images)-1].indent != indent {
			flush(indent)
			images = append(images, templateImage{indent: indent})
		}
		image := &images[len(images)-1]
		value := templateScalar(raw)
		switch key {
		case "registry":
			image.registry = value
		case "repository":
			if image.repository != "" {
				flush(indent)
				images = append(images, templateImage{indent: indent})
				image = &images[len(images)-1]
			}
			image.repository, image.line, image.column = value, line, strings.Index(text, raw)+1
		case "tag":
			image.tag = value
		}
	}
	flush(-1)
}

func templateScalar(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	switch v[0] {
	case '"':
		if end := strings.LastIndexByte(v, '"'); end > 0 {
			if unquoted, err := strconv.Unquote(v[:end+1]); err == nil {
				return unquoted
			}
			return v[1:end]
		}
	case '\'':
		if end := strings.LastIndexByte(v, '\''); end > 0 {
			return strings.ReplaceAll(v[1:end], "''", "'")
		}
	default:
		if i := strings.Index(v, " #"); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
	}
	return v
}
