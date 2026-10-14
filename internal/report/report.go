// Package report renders scanner findings in stable human and machine formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// Table writes a compact deterministic table.
func Table(w io.Writer, result diag.Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "LOCATION\tCODE\tSEVERITY\tSTATEFUL\tREFERENCE"); err != nil {
		return err
	}
	for _, finding := range result.Findings {
		cells := []string{fmt.Sprintf("%s:%d", finding.Path, finding.Line), finding.Code, string(finding.Severity), strconv.FormatBool(finding.Stateful), finding.Reference}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", safeCell(cells[0]), safeCell(cells[1]), safeCell(cells[2]), safeCell(cells[3]), safeCell(cells[4])); err != nil {
			return err
		}
	}
	for _, diagnostic := range result.Diagnostics {
		location := diagnostic.Path
		if diagnostic.Line > 0 {
			location = fmt.Sprintf("%s:%d", diagnostic.Path, diagnostic.Line)
		}
		cells := []string{location, diagnostic.Code, "-", "-", diagnostic.Message}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", safeCell(cells[0]), safeCell(cells[1]), safeCell(cells[2]), safeCell(cells[3]), safeCell(cells[4])); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// JSON writes the versioned JSON envelope with stable struct field order.
func JSON(w io.Writer, result diag.Report) error {
	envelope := struct {
		SchemaVersion string                `json:"schemaVersion"`
		Findings      []diag.Diagnostic     `json:"findings"`
		Diagnostics   []diag.ScanDiagnostic `json:"diagnostics"`
	}{SchemaVersion: "1", Findings: nonNilFindings(result.Findings), Diagnostics: nonNilDiagnostics(result.Diagnostics)}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(envelope)
}

func safeCell(value string) string {
	quoted := strconv.Quote(value)
	return quoted[1 : len(quoted)-1]
}

func nonNilFindings(values []diag.Diagnostic) []diag.Diagnostic {
	if values == nil {
		return []diag.Diagnostic{}
	}
	return values
}

func nonNilDiagnostics(values []diag.ScanDiagnostic) []diag.ScanDiagnostic {
	if values == nil {
		return []diag.ScanDiagnostic{}
	}
	return values
}
