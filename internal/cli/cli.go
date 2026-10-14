// Package cli wires the disdetta command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/cluster"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
	"github.com/spf13/cobra"
	"io"
	"time"
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
	root.AddCommand(newVersionCmd(streams), newScanCmd(streams), newPlanCmd(streams))
	return root
}
func newVersionCmd(streams IO) *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version information", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { _, e := fmt.Fprintln(streams.Out, "disdetta dev"); return e }}
}
func newScanCmd(streams IO) *cobra.Command {
	format, failOn, config := "table", "low", ""
	var rules, exclude, namespaces []string
	var clusterScan bool
	var contextName, kubeconfig string
	var readHelmSecrets bool
	var timeout time.Duration
	cmd := &cobra.Command{Use: "scan [path]", Short: "Find Bitnami references in a repository or a cluster", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
		if clusterScan && len(args) == 1 {
			return &exitError{ExitError, errors.New("cannot combine a path with --cluster")}
		}
		if clusterScan && len(exclude) > 0 {
			return &exitError{ExitError, errors.New("--exclude applies to repository scans only")}
		}
		var result diag.Report
		var scanErr error
		if clusterScan {
			options := cluster.Options{Context: contextName, Kubeconfig: kubeconfig, Namespaces: namespaces, ReadHelmSecrets: readHelmSecrets, Timeout: timeout}
			source, err := cluster.NewClientSource(options)
			if err != nil {
				return &exitError{ExitError, err}
			}
			result, scanErr = cluster.Scan(cmd.Context(), source, options)
			if scanErr == nil && config != "" {
				scanErr = repo.ApplyIgnoreFile(&result, config, time.Now())
			}
		} else {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			result, scanErr = repo.ScanWithOptions(cmd.Context(), path, repo.Options{ConfigPath: config, Clock: time.Now, Exclude: exclude})
		}
		if scanErr != nil {
			return &exitError{ExitError, scanErr}
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
			scanErr = report.JSON(streams.Out, result)
		} else {
			scanErr = report.Table(streams.Out, result)
		}
		if scanErr != nil {
			return &exitError{ExitError, fmt.Errorf("write report: %w", scanErr)}
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
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil, "skip paths matching a slash-separated glob relative to the root (repeatable, ** supported)")
	cmd.Flags().StringVar(&config, "config", "", "ignore configuration file (default .disdetta.yaml at scan root)")
	cmd.Flags().BoolVar(&clusterScan, "cluster", false, "scan a Kubernetes cluster instead of a path (spec v0.2)")
	cmd.Flags().StringVar(&contextName, "context", "", "kubeconfig context to use with --cluster")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file to use with --cluster (default kubectl resolution)")
	cmd.Flags().StringArrayVar(&namespaces, "namespace", nil, "namespace to scan with --cluster (repeatable; default all namespaces)")
	cmd.Flags().BoolVar(&readHelmSecrets, "read-helm-secrets", false, "read Helm release Secrets for tier 3 (may contain credentials)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-list timeout for --cluster (e.g. 30s)")
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

// recount recomputes the summary fields that a --rule filter or an ignore file
// can change, including the cluster release count and groups.
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
	}
	for _, d := range r.Diagnostics {
		if d.Code == "DSD-SCN-003" {
			unresolved++
		}
	}
	r.Summary.Unresolved = unresolved
	r.Summary.Diagnostics = len(r.Diagnostics)
	r.Summary.Releases, r.Groups = diag.ClusterSummary(r.Findings)
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
			_, _ = fmt.Fprintf(streams.Err, "disdetta: %s\n", report.SafeText(coded.err.Error()))
		}
		return coded.code
	}
	_, _ = fmt.Fprintf(streams.Err, "disdetta: %s\n", report.SafeText(err.Error()))
	return ExitError
}
