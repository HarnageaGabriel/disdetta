//go:build kind

package kind

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	clusterName = "disdetta-cluster-scan"
	namespace   = "db"
	chartRef    = "oci://registry-1.docker.io/bitnamicharts/postgresql"
	// chartVersion pins the chart so the test does not drift with the published
	// chart (review 03 m5).
	chartVersion = "16.7.9"
	// imageTag is the tag the pinned chart resolves to in
	// docker.io/bitnamilegacy/postgresql.
	// Verified 2026-10-14 on Docker Hub: bitnamilegacy/postgresql:17.6.0-debian-12-r4
	// exists; chart 16.7.9 exists in bitnamicharts.
	imageTag = "17.6.0-debian-12-r4"
	// nodeImage pins the kind node so the Kubernetes minor stays within the
	// client-go v0.37 skew support (review 03 m5).
	// Verified 2026-10-14: default node image of kind v0.33.0 (see kind.yml),
	// Kubernetes 1.37 matches client-go v0.37.
	nodeImage = "kindest/node:v1.37.0"
)

// TestKindBitnamiChart installs the Bitnami postgresql chart with a
// bitnamilegacy image and global.security.allowInsecureImages=true, then runs
// the cluster scan with and without --read-helm-secrets. It asserts DSD-IMG-001
// both times and DSD-CFG-001 only with the flag (docs/spec/v0.2-cluster.md
// section 6).
func TestKindBitnamiChart(t *testing.T) {
	for _, tool := range []string{"docker", "kind", "helm", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("source docs/spec/v0.2-cluster.md section 6: %s not found, skipping the kind test", tool)
		}
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	binary := filepath.Join(work, "disdetta")
	runCommand(t, repoRoot, "go", "build", "-o", binary, "./cmd/disdetta")

	runCommand(t, repoRoot, "kind", "create", "cluster", "--name", clusterName, "--image", nodeImage, "--wait", "120s")
	t.Cleanup(func() {
		_ = exec.Command("kind", "delete", "cluster", "--name", clusterName).Run()
	})

	kubeconfig := filepath.Join(work, "kubeconfig")
	config := runCommand(t, repoRoot, "kind", "get", "kubeconfig", "--name", clusterName)
	if err := os.WriteFile(kubeconfig, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	runCommand(t, repoRoot, "helm", "install", "pg", chartRef,
		"--version", chartVersion,
		"--kubeconfig", kubeconfig,
		"--namespace", namespace, "--create-namespace",
		"--set", "image.repository=bitnamilegacy/postgresql",
		"--set", "image.tag="+imageTag,
		"--set", "global.security.allowInsecureImages=true",
		"--timeout", "5m")

	tier12 := scan(t, binary, kubeconfig)
	if !tier12.rules["DSD-IMG-001"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 6: DSD-IMG-001 missing without --read-helm-secrets: %v", tier12.ruleList)
	}
	if tier12.rules["DSD-CFG-001"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 6: DSD-CFG-001 must require --read-helm-secrets")
	}

	tier3 := scan(t, binary, kubeconfig, "--read-helm-secrets")
	if !tier3.rules["DSD-IMG-001"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 6: DSD-IMG-001 missing with --read-helm-secrets: %v", tier3.ruleList)
	}
	if !tier3.rules["DSD-CFG-001"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 6: DSD-CFG-001 missing with --read-helm-secrets: %v", tier3.ruleList)
	}
}

// scanResult is the subset of the JSON report the assertions read.
type scanResult struct {
	rules    map[string]bool
	ruleList []string
}

// scan runs `disdetta scan --cluster` against the namespace and returns the
// distinct rule IDs. --fail-on none keeps the exit code about completeness, not
// the finding policy.
func scan(t *testing.T, binary, kubeconfig string, extra ...string) scanResult {
	t.Helper()
	args := append([]string{"scan", "--cluster", "--kubeconfig", kubeconfig, "--namespace", namespace, "--format", "json", "--fail-on", "none"}, extra...)
	cmd := exec.Command(binary, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 6: disdetta %s: %v\n%s\n%s", strings.Join(args, " "), err, out.String(), errOut.String())
	}
	return parseReport(t, out.Bytes())
}

// parseReport reads the finding rule IDs and completeness from a JSON report
// (schemas/report-v1.json).
func parseReport(t *testing.T, data []byte) scanResult {
	t.Helper()
	var document struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
		Summary struct {
			Complete bool `json:"complete"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 6: parse report: %v\n%s", err, data)
	}
	if !document.Summary.Complete {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 6: report incomplete:\n%s", data)
	}
	result := scanResult{rules: map[string]bool{}}
	for _, finding := range document.Findings {
		if !result.rules[finding.RuleID] {
			result.rules[finding.RuleID] = true
			result.ruleList = append(result.ruleList, finding.RuleID)
		}
	}
	return result
}

// runCommand runs a command in dir and fails the test on a non-zero exit or a
// 10 minute timeout, so a hung cluster read cannot wedge CI.
func runCommand(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 6: %s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}
