package cluster

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
)

var update = flag.Bool("update", false, "update golden files")

// scanRecorded runs the cluster scan over the recorded fixture with tier 3 on,
// the scenario the goldens capture (spec v0.2 section 6).
func scanRecorded(t *testing.T) diag.Report {
	t.Helper()
	source, _ := newSource(t, recordedObjects(t)...)
	got, err := Scan(context.Background(), source, Options{Context: "recorded", ReadHelmSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestGoldenClusterReport compares the table and JSON renders of the recorded
// cluster against the checked-in goldens (spec v0.2 section 6). The JSON golden
// is also validated against schemas/report-v1.json by internal/report.
func TestGoldenClusterReport(t *testing.T) {
	got := scanRecorded(t)
	root := filepath.Join("..", "..", "..", "testdata", "cluster", "basic")
	renders := map[string]func(*bytes.Buffer) error{
		"table": func(b *bytes.Buffer) error { return report.Table(b, got) },
		"json":  func(b *bytes.Buffer) error { return report.JSON(b, got) },
	}
	for _, format := range []string{"table", "json"} {
		var buf bytes.Buffer
		if err := renders[format](&buf); err != nil {
			t.Fatal(err)
		}
		golden := filepath.Join(root, "scan."+format+".golden")
		if *update {
			if err := os.WriteFile(golden, buf.Bytes(), 0644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("source docs/spec/v0.2-cluster.md section 6: %s golden differs (run -update)\n--- got ---\n%s", format, buf.String())
		}
	}
}

// TestRecordedFixtureFindings is a semantic check independent of the goldens:
// every rule the fixture exercises appears, and the owner-filtered objects and
// controller-owned pod never become findings (spec v0.2 sections 2 and 3).
func TestRecordedFixtureFindings(t *testing.T) {
	got := scanRecorded(t)
	codes := map[string]int{}
	for _, f := range got.Findings {
		codes[f.RuleID]++
	}
	for _, want := range []string{"DSD-IMG-001", "DSD-IMG-002", "DSD-IMG-003", "DSD-IMG-004", "DSD-CFG-001", "DSD-CHT-002"} {
		if codes[want] == 0 {
			t.Errorf("source docs/spec/v0.2-cluster.md section 3: missing %s: %#v", want, codes)
		}
	}
	for _, f := range got.Findings {
		switch f.Location.Path {
		case "cluster/shop/ReplicaSet/web-7d9c", "cluster/db/Job/nightly-28917420", "cluster/shop/Pod/web-abc123":
			t.Errorf("source docs/spec/v0.2-cluster.md section 2 (owner filtering): %s must be skipped", f.Location.Path)
		}
	}
	if got.Summary.Releases != 2 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: releases %d, want 2", got.Summary.Releases)
	}
	if len(got.Groups) == 0 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: no groups")
	}
	if !got.Summary.Complete {
		t.Errorf("source docs/spec/v0.2-cluster.md section 4: recorded cluster should be complete: %#v", got.Diagnostics)
	}
}

// TestRecordedFixtureRedaction asserts no planted credential reaches any output:
// the table, the JSON, or a diagnostic message (spec v0.2 section 4, threat
// model T2). The fixture plants a password and a token in the release config,
// and a token in an unrelated Opaque Secret.
func TestRecordedFixtureRedaction(t *testing.T) {
	got := scanRecorded(t)
	if len(findingsFor(got, "DSD-CFG-001")) == 0 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 4: tier 3 did not run, redaction test is vacuous")
	}
	var table, jsonOut bytes.Buffer
	if err := report.Table(&table, got); err != nil {
		t.Fatal(err)
	}
	if err := report.JSON(&jsonOut, got); err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{"table": table.String(), "json": jsonOut.String()}
	for _, d := range got.Diagnostics {
		outputs["diagnostic "+d.Code] = d.Message
	}
	planted := []string{"hunter2", "planted-token", "planted-secret-value", "planted-password"}
	for name, out := range outputs {
		for _, secret := range planted {
			if strings.Contains(out, secret) {
				t.Errorf("source docs/spec/v0.2-cluster.md section 4 (threat model T2): %s output leaked %q", name, secret)
			}
		}
	}
}
