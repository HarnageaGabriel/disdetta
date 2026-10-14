package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/plan"
	"github.com/HarnageaGabriel/disdetta/internal/scan/cluster"
	"github.com/HarnageaGabriel/disdetta/internal/scan/repo"
	"github.com/spf13/cobra"
)

const ExitPlanIncomplete = 4

func newPlanCmd(streams IO) *cobra.Command {
	var release, fromRepo, out, format, route, contextName, kubeconfig string
	var fromCluster, readSecrets bool
	var namespaces, values []string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "plan", Short: "Create a read-only migration plan", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if release == "" {
			return &exitError{ExitError, fmt.Errorf("--release is required")}
		}
		if (fromRepo == "") == !fromCluster {
			return &exitError{ExitError, fmt.Errorf("choose exactly one of --from-repo or --from-cluster")}
		}
		if format != "table" && format != "json" {
			return &exitError{ExitError, fmt.Errorf("invalid --format %q (want table or json)", format)}
		}
		if fromCluster && !readSecrets {
			return &exitError{ExitError, fmt.Errorf("--from-cluster requires --read-helm-secrets")}
		}
		var in plan.Input
		var err error
		if fromCluster {
			in, err = clusterPlanInput(cmd.Context(), release, cluster.Options{Context: contextName, Kubeconfig: kubeconfig, Namespaces: namespaces, ReadHelmSecrets: true, Timeout: timeout})
		} else {
			in, err = repoPlanInputContext(cmd.Context(), fromRepo, release, values)
		}
		if err != nil {
			return &exitError{ExitError, err}
		}
		catalogs, err := plan.EmbeddedCatalogs()
		if err != nil {
			return &exitError{ExitError, err}
		}
		c, r, err := plan.SelectCatalog(catalogs, in.Chart, in.ChartVersion, route)
		if err != nil {
			return &exitError{ExitError, err}
		}
		result, err := plan.Build(in, c, r)
		if err != nil {
			return &exitError{ExitError, err}
		}
		if out != "" {
			if err := writePlanDir(out, result, format); err != nil {
				return &exitError{ExitError, err}
			}
		} else {
			var b []byte
			if format == "json" {
				b, err = plan.JSON(result)
			} else {
				b, err = plan.Table(result)
			}
			if err == nil {
				_, err = streams.Out.Write(b)
			}
			if err != nil {
				return &exitError{ExitError, fmt.Errorf("write plan: %w", err)}
			}
		}
		for _, item := range result.Unmapped {
			if item.Kind != "handled" {
				return &exitError{code: ExitPlanIncomplete}
			}
		}
		return nil
	}}
	cmd.Flags().StringVar(&release, "release", "", "release name")
	cmd.Flags().StringVar(&fromRepo, "from-repo", "", "repository root")
	cmd.Flags().BoolVar(&fromCluster, "from-cluster", false, "read a Helm release from a cluster")
	cmd.Flags().StringArrayVar(&values, "values", nil, "additional values file in Helm order (repeatable)")
	cmd.Flags().StringVar(&route, "route", "", "catalog route ID")
	cmd.Flags().StringVar(&out, "out", "", "write plan files to a directory")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table or json")
	cmd.Flags().StringVar(&contextName, "context", "", "kubeconfig context")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "kubeconfig file")
	cmd.Flags().StringArrayVar(&namespaces, "namespace", nil, "namespace (repeatable)")
	cmd.Flags().BoolVar(&readSecrets, "read-helm-secrets", false, "allow reading Helm release Secrets")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "cluster list timeout")
	return cmd
}

func repoPlanInput(root, release string, valuePaths []string) (plan.Input, error) {
	return repoPlanInputContext(context.Background(), root, release, valuePaths)
}
func repoPlanInputContext(ctx context.Context, root, release string, valuePaths []string) (plan.Input, error) {
	files, err := repo.ReadYAMLFiles(ctx, root)
	if err != nil {
		return plan.Input{}, fmt.Errorf("read repository: %w", err)
	}
	var extra [][]byte
	for _, p := range valuePaths {
		b, e := repo.ReadFile(p)
		if e != nil {
			return plan.Input{}, fmt.Errorf("read values %s: %w", p, e)
		}
		extra = append(extra, b)
	}
	return plan.FindRepoRelease(release, files, extra)
}
func clusterPlanInput(ctx context.Context, release string, opts cluster.Options) (plan.Input, error) {
	source, err := cluster.NewClientSource(opts)
	if err != nil {
		return plan.Input{}, err
	}
	rels, failures := source.ListReleases(ctx, opts.Namespaces)
	if len(failures) > 0 {
		return plan.Input{}, fmt.Errorf("list Helm release Secrets failed")
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].Namespace < rels[j].Namespace })
	var matched []cluster.Release
	for _, r := range rels {
		if r.Name == release {
			matched = append(matched, r)
		}
	}
	if len(matched) > 1 {
		return plan.Input{}, fmt.Errorf("release %q is ambiguous across namespaces", release)
	}
	for _, r := range matched {
		d, e := cluster.DecodePlanRelease(r.Name, r.Payload)
		if e != nil {
			return plan.Input{}, e
		}
		return plan.Input{Release: d.Name, Chart: d.Chart, ChartVersion: d.Version, Values: d.Config}, nil
	}
	return plan.Input{}, fmt.Errorf("release %q not found", release)
}
func writePlanDir(dir string, p plan.Plan, format string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	target, err := plan.TargetYAML(p)
	if err != nil {
		return err
	}
	unmapped, err := plan.UnmappedYAML(p)
	if err != nil {
		return err
	}
	files := map[string][]byte{"target.yaml": target, "unmapped": unmapped, "checklist.md": plan.ChecklistMarkdown(p)}
	if format == "json" {
		files["plan.json"], err = plan.JSON(p)
		if err != nil {
			return err
		}
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}
