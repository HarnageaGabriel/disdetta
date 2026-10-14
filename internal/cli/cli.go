// Package cli wires the disdetta command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
	"github.com/spf13/cobra"
	"io"
)

const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitError      = 2
	ExitIncomplete = 3
)

// IO supplies command streams for testability.
type IO struct {
	Out io.Writer
	Err io.Writer
}
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}
func (e *exitError) Unwrap() error { return e.err }

// NewRootCmd constructs a fresh command tree.
func NewRootCmd(streams IO) *cobra.Command {
	root := &cobra.Command{Use: "disdetta", Short: "Find Bitnami dependencies before migration", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true}
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.AddCommand(newVersionCmd(streams), newScanCmd(streams))
	return root
}
func newVersionCmd(streams IO) *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version information", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { _, e := fmt.Fprintln(streams.Out, "disdetta dev"); return e }}
}
func newScanCmd(streams IO) *cobra.Command {
	format, failOn := "table", "low"
	var rules []string
	cmd := &cobra.Command{Use: "scan [path]", Short: "Find Bitnami references in a repository", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if format != "table" && format != "json" {
			return &exitError{ExitError, fmt.Errorf("invalid --format %q (want table or json)", format)}
		}
		threshold, ok := parseThreshold(failOn)
		if !ok {
			return &exitError{ExitError, fmt.Errorf("invalid --fail-on %q (want high, medium, low, or none)", failOn)}
		}
		allowed := map[string]bool{}
		for _, id := range rules {
			if !isRule(id) {
				return &exitError{ExitError, fmt.Errorf("invalid --rule %q", id)}
			}
			allowed[id] = true
		}
		path := "."
		if len(args) == 1 {
			path = args[0]
		}
		result, e := repo.Scan(cmd.Context(), path)
		if e != nil {
			return &exitError{ExitError, e}
		}
		if len(allowed) > 0 {
			filtered := result.Findings[:0]
			for _, f := range result.Findings {
				if allowed[f.RuleID] {
					filtered = append(filtered, f)
				}
			}
			result.Findings = filtered
			recount(&result)
		}
		if format == "json" {
			e = report.JSON(streams.Out, result)
		} else {
			e = report.Table(streams.Out, result)
		}
		if e != nil {
			return &exitError{ExitError, fmt.Errorf("write report: %w", e)}
		}
		for _, f := range result.Findings {
			if threshold >= 0 && diag.SeverityRank(f.Severity) <= threshold {
				return &exitError{code: ExitFindings}
			}
		}
		if !result.Summary.Complete {
			return &exitError{code: ExitIncomplete}
		}
		return nil
	}}
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "low", "failure threshold: high, medium, low, or none")
	cmd.Flags().StringArrayVar(&rules, "rule", nil, "include finding rule ID (repeatable)")
	return cmd
}
func parseThreshold(v string) (int, bool) {
	switch v {
	case "high":
		return 0, true
	case "medium":
		return 1, true
	case "low":
		return 2, true
	case "none":
		return -1, true
	}
	return 0, false
}
func isRule(v string) bool {
	for _, e := range diag.List() {
		if e.Code == v && e.Severity != "" {
			return true
		}
	}
	return false
}
func recount(r *diag.Report) {
	r.Summary.Findings = diag.FindingCounts{}
	unresolved := 0
	for _, f := range r.Findings {
		switch f.Severity {
		case diag.SeverityHigh:
			r.Summary.Findings.High++
		case diag.SeverityMedium:
			r.Summary.Findings.Medium++
		case diag.SeverityLow:
			r.Summary.Findings.Low++
		}
		if f.Confidence == diag.ConfidenceUnresolved {
			unresolved++
		}
	}
	for _, d := range r.Diagnostics {
		if d.Code == "DSD-SCN-003" {
			unresolved++
		}
	}
	r.Summary.Unresolved = unresolved
}

// Execute runs the CLI and maps errors to stable exit codes.
func Execute(ctx context.Context, args []string, streams IO) int {
	root := NewRootCmd(streams)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var coded *exitError
	if errors.As(err, &coded) {
		if coded.err != nil {
			_, _ = fmt.Fprintf(streams.Err, "disdetta: %v\n", coded.err)
		}
		return coded.code
	}
	_, _ = fmt.Fprintf(streams.Err, "disdetta: %v\n", err)
	return ExitError
}
