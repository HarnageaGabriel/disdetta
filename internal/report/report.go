// Package report renders scanner findings in stable human and machine formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// Table writes a compact deterministic table.
func Table(w io.Writer, findings []diag.Diagnostic) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "LOCATION\tCODE\tSEVERITY\tSTATEFUL\tREFERENCE"); err != nil {
		return err
	}
	for _, finding := range findings {
		if _, err := fmt.Fprintf(tw, "%s:%d\t%s\t%s\t%t\t%s\n", finding.Path, finding.Line, finding.Code, finding.Severity, finding.Stateful, finding.Reference); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// JSON writes the versioned JSON envelope with stable struct field order.
func JSON(w io.Writer, findings []diag.Diagnostic) error {
	envelope := struct {
		SchemaVersion string            `json:"schemaVersion"`
		Findings      []diag.Diagnostic `json:"findings"`
	}{SchemaVersion: "1", Findings: findings}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(envelope)
}
