// Package cli wires the disdetta command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/HarnageaGabriel/disdetta/internal/report"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
	"github.com/spf13/cobra"
)

const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
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
	root := &cobra.Command{
		Use:           "disdetta",
		Short:         "Find Bitnami dependencies before migration",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(streams.Out)
	root.SetErr(streams.Err)
	root.AddCommand(newVersionCmd(streams), newScanCmd(streams))
	return root
}

func newVersionCmd(streams IO) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			_, err := fmt.Fprintln(streams.Out, "disdetta dev")
			return err
		},
	}
}

func newScanCmd(streams IO) *cobra.Command {
	format := "table"
	command := &cobra.Command{
		Use:   "scan [path]",
		Short: "Find Bitnami references in a repository",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" {
				return &exitError{code: ExitError, err: fmt.Errorf("invalid --format %q (want table or json)", format)}
			}
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			findings, err := repo.Scan(cmd.Context(), path)
			if err != nil {
				return &exitError{code: ExitError, err: err}
			}
			if format == "json" {
				err = report.JSON(streams.Out, findings)
			} else {
				err = report.Table(streams.Out, findings)
			}
			if err != nil {
				return &exitError{code: ExitError, err: fmt.Errorf("write report: %w", err)}
			}
			if len(findings) > 0 {
				return &exitError{code: ExitFindings}
			}
			return nil
		},
	}
	command.Flags().StringVar(&format, "format", "table", "output format: table or json")
	return command
}

// Execute runs the CLI and maps all usage and runtime errors to exit code 2.
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
