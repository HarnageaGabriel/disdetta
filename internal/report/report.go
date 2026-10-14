// Package report renders scanner findings in stable human and machine formats.
package report

import (
	"encoding/json"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"
)

// Table writes the v1 compact deterministic table and summary.
func Table(w io.Writer, r diag.Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, e := fmt.Fprintln(tw, "LOCATION\tRULE\tSEVERITY\tCONFIDENCE\tIMPACT\tREFERENCE"); e != nil {
		return e
	}
	for _, f := range r.Findings {
		cells := []string{location(f.Location), f.RuleID, string(f.Severity), string(f.Confidence), string(f.Impact), f.Reference}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", SafeText(cells[0]), SafeText(cells[1]), SafeText(cells[2]), SafeText(cells[3]), SafeText(cells[4]), SafeText(cells[5])); e != nil {
			return e
		}
	}
	for _, d := range r.Diagnostics {
		if d.Level == diag.LevelInfo {
			continue
		}
		cells := []string{location(d.Location), d.Code, string(d.Level), "-", "-", d.Message}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", SafeText(cells[0]), SafeText(cells[1]), SafeText(cells[2]), cells[3], cells[4], SafeText(cells[5])); e != nil {
			return e
		}
	}
	s := r.Summary
	summary := fmt.Sprintf("scanned %d files, skipped %d, findings %d (high %d, medium %d, low %d), diagnostics %d, unresolved %d, ignored %d", s.FilesScanned, s.FilesSkipped, s.Findings.High+s.Findings.Medium+s.Findings.Low, s.Findings.High, s.Findings.Medium, s.Findings.Low, s.Diagnostics, s.Unresolved, s.Ignored)
	if s.Releases > 0 {
		// Cluster scans add the release count (spec v0.2 section 3); repository
		// output is unchanged because Releases is zero there.
		summary += fmt.Sprintf(", releases %d", s.Releases)
	}
	if _, e := fmt.Fprintln(tw, summary); e != nil {
		return e
	}
	return tw.Flush()
}

// JSON writes the schema-version-1 envelope with stable struct field order.
func JSON(w io.Writer, r diag.Report) error {
	v := struct {
		SchemaVersion string `json:"schemaVersion"`
		Tool          struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Summary     diag.Summary      `json:"summary"`
		Findings    []diag.Finding    `json:"findings"`
		Groups      []diag.Group      `json:"groups,omitempty"`
		Diagnostics []diag.Diagnostic `json:"diagnostics"`
	}{SchemaVersion: "1", Summary: r.Summary, Findings: r.Findings, Groups: r.Groups, Diagnostics: r.Diagnostics}
	v.Tool.Name = "disdetta"
	v.Tool.Version = "dev"
	if v.Findings == nil {
		v.Findings = []diag.Finding{}
	}
	if v.Diagnostics == nil {
		v.Diagnostics = []diag.Diagnostic{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func location(v diag.Location) string {
	if v.Line == 0 {
		return v.Path
	}
	if v.Column == 0 {
		return fmt.Sprintf("%s:%d", v.Path, v.Line)
	}
	return fmt.Sprintf("%s:%d:%d", v.Path, v.Line, v.Column)
}

// safeCell escapes a table cell so no raw control character or Unicode format
// character (category Cf) can forge a row, and an invalid UTF-8 byte is
// escaped rather than replaced (spec section 6).
func SafeText(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, v[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case !unicode.IsPrint(r) || unicode.In(r, unicode.Cf):
			switch {
			case r > 0xFFFF:
				fmt.Fprintf(&b, `\U%08x`, r)
			case r > 0xFF:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\x%02x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// safeCell is retained for package-local tests and older callers. All human
// renderers should use SafeText so the escaping contract stays centralized.
func safeCell(v string) string { return SafeText(v) }
