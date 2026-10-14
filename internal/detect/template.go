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
	templateAction  = regexp.MustCompile(`\{\{[\s\S]*?\}\}`)
	templateComment = regexp.MustCompile(`\{\{-?\s*/\*[\s\S]*?\*/\s*-?\}\}`)
	templateKeyLine = regexp.MustCompile(`^\s*-?\s*(image|repository)\s*:\s*(.*)$`)
	templateLiteral = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
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
	raw := m[2]
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
