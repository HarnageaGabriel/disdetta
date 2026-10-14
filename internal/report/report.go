// Package report renders scanner findings in stable human and machine formats.
package report

import (
	"encoding/json"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"io"
	"strconv"
	"text/tabwriter"
)

// Table writes the v1 compact deterministic table and summary.
func Table(w io.Writer, r diag.Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, e := fmt.Fprintln(tw, "LOCATION\tRULE\tSEVERITY\tCONFIDENCE\tIMPACT\tREFERENCE"); e != nil {
		return e
	}
	for _, f := range r.Findings {
		cells := []string{location(f.Location), f.RuleID, string(f.Severity), string(f.Confidence), string(f.Impact), f.Reference}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", safeCell(cells[0]), safeCell(cells[1]), safeCell(cells[2]), safeCell(cells[3]), safeCell(cells[4]), safeCell(cells[5])); e != nil {
			return e
		}
	}
	for _, d := range r.Diagnostics {
		if d.Level == diag.LevelInfo {
			continue
		}
		cells := []string{location(d.Location), d.Code, string(d.Level), "-", "-", d.Message}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", safeCell(cells[0]), safeCell(cells[1]), safeCell(cells[2]), cells[3], cells[4], safeCell(cells[5])); e != nil {
			return e
		}
	}
	s := r.Summary
	if _, e := fmt.Fprintf(tw, "scanned %d files, skipped %d, findings %d (high %d, medium %d, low %d), diagnostics %d, unresolved %d, ignored %d\n", s.FilesScanned, s.FilesSkipped, s.Findings.High+s.Findings.Medium+s.Findings.Low, s.Findings.High, s.Findings.Medium, s.Findings.Low, s.Diagnostics, s.Unresolved, s.Ignored); e != nil {
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
		Diagnostics []diag.Diagnostic `json:"diagnostics"`
	}{SchemaVersion: "1", Summary: r.Summary, Findings: r.Findings, Diagnostics: r.Diagnostics}
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
func safeCell(v string) string { q := strconv.Quote(v); return q[1 : len(q)-1] }
