package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/report"
)

// fakeSource is an in-memory Source for the pure Scan tests (ADR 0007).
type fakeSource struct {
	workloads        Workloads
	workloadFailures []ListFailure
	releases         []Release
	releaseFailures  []ListFailure
	releaseCalls     int
}

func (f *fakeSource) ListWorkloads(context.Context, []string) (Workloads, []ListFailure) {
	return f.workloads, f.workloadFailures
}

func (f *fakeSource) ListReleases(context.Context, []string) ([]Release, []ListFailure) {
	f.releaseCalls++
	return f.releases, f.releaseFailures
}

// releasePayload builds the tier 3 payload the scan decodes: base64 StdEncoding
// of gzip JSON (docs/research/RESEARCH-NOTES.md section 9; Helm's encodeRelease
// https://github.com/helm/helm/blob/main/pkg/storage/driver/util.go).
func releasePayload(t *testing.T, document string) []byte {
	t.Helper()
	return []byte(base64.StdEncoding.EncodeToString(gzipPayload(t, []byte(document))))
}

func findingsFor(r diag.Report, rule string) []diag.Finding {
	var out []diag.Finding
	for _, f := range r.Findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func hasDiagnostic(r diag.Report, code string, level diag.Level) bool {
	for _, d := range r.Diagnostics {
		if d.Code == code && d.Level == level {
			return true
		}
	}
	return false
}

// TestScanTemplateSources checks tier 1 collection: a workload template and a
// standalone pod are scanned, a controller-owned pod is skipped, and the tier 2
// labels land on the resource (spec v0.2 sections 2 and 3).
func TestScanTemplateSources(t *testing.T) {
	source := &fakeSource{workloads: Workloads{
		Templates: []Workload{{
			Namespace:  "shop",
			Kind:       "Deployment",
			Name:       "web",
			Labels:     map[string]string{"helm.sh/chart": "web-1.2.3", "app.kubernetes.io/instance": "web"},
			Containers: []Container{{Name: "web", Image: "bitnamilegacy/nginx:1.25.3"}},
		}},
		Pods: []Pod{
			{Namespace: "shop", Name: "web-abc123", Owned: true, Containers: []Container{{Name: "web", Image: "bitnamilegacy/nginx:1.25.3"}}},
			{Namespace: "shop", Name: "pg-0", Containers: []Container{{Name: "db", Image: "bitnami/postgresql:16.4.0"}}},
		},
	}}
	got, err := Scan(context.Background(), source, Options{Context: "kind-dev"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 2 tier 1: %d findings, want 2", len(got.Findings))
	}
	if got.Summary.FilesScanned != 3 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: filesScanned %d", got.Summary.FilesScanned)
	}
	for _, f := range got.Findings {
		if f.Location.Line != 0 || f.Location.Column != 0 {
			t.Errorf("source docs/spec/v0.2-cluster.md section 3: line/column %#v", f.Location)
		}
		if f.Resource == nil || f.Resource.Context != "kind-dev" {
			t.Errorf("source docs/spec/v0.2-cluster.md section 3: resource %#v", f.Resource)
		}
	}
	deployment := findingsFor(got, "DSD-IMG-001")[0]
	if deployment.Location.Path != "cluster/shop/Deployment/web" {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: path %q", deployment.Location.Path)
	}
	if deployment.Resource.Release != "web" || deployment.Resource.Chart != "web-1.2.3" {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 2: %#v", deployment.Resource)
	}
	pod := deployment
	for _, f := range findingsFor(got, "DSD-IMG-002") {
		if f.Location.Path == "cluster/shop/Pod/pg-0" {
			pod = f
		}
	}
	if pod.Location.Path != "cluster/shop/Pod/pg-0" {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 2 tier 1: standalone pod not scanned: %#v", got.Findings)
	}
}

// TestScanTier3ValuesAndChart checks a decoded release: user values run through
// the v0.1 values detector (DSD-CFG-001) and chart metadata through the vendored
// chart detector (DSD-CHT-002) (spec v0.2 section 3).
func TestScanTier3ValuesAndChart(t *testing.T) {
	document := `{"name":"pg","chart":{"metadata":{"name":"postgresql","version":"16.4.0","home":"https://bitnami.com","sources":["https://github.com/bitnami/charts/tree/main/bitnami/postgresql"]}},"config":{"global":{"security":{"allowInsecureImages":true}}}}`
	source := &fakeSource{releases: []Release{{Namespace: "db", Name: "pg", Payload: releasePayload(t, document)}}}
	got, err := Scan(context.Background(), source, Options{ReadHelmSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsFor(got, "DSD-CFG-001")) != 1 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: missing DSD-CFG-001: %#v", got.Findings)
	}
	chart := findingsFor(got, "DSD-CHT-002")
	if len(chart) != 1 {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 3: missing DSD-CHT-002: %#v", got.Findings)
	}
	if chart[0].Resource.Kind != "Secret" || chart[0].Resource.Name != "pg" || chart[0].Resource.Release != "pg" || chart[0].Resource.Container != "" {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: resource %#v", chart[0].Resource)
	}
	if got.Summary.Releases != 1 || len(got.Groups) != 1 || got.Groups[0].Name != "pg" {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: summary %#v groups %#v", got.Summary, got.Groups)
	}
}

// TestScanTier3LegacyPayload checks a legacy plain JSON payload decodes the same
// way (docs/research/RESEARCH-NOTES.md section 9).
func TestScanTier3LegacyPayload(t *testing.T) {
	source := &fakeSource{releases: []Release{{Namespace: "db", Name: "pg", Payload: []byte(`{"config":{"global":{"security":{"allowInsecureImages":true}}}}`)}}}
	got, err := Scan(context.Background(), source, Options{ReadHelmSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsFor(got, "DSD-CFG-001")) != 1 {
		t.Fatalf("source docs/research/RESEARCH-NOTES.md section 9: %#v", got.Findings)
	}
}

// TestScanTier3Bounds checks a payload over a cap or not decodable becomes
// DSD-SCN-009 (error, incomplete) and the scan still returns (spec v0.2 sections
// 4 and 5).
func TestScanTier3Bounds(t *testing.T) {
	oversize := []byte(base64.StdEncoding.EncodeToString(gzipPayload(t, make([]byte, 8<<20))))
	source := &fakeSource{releases: []Release{
		{Namespace: "db", Name: "bad", Payload: oversize},
		{Namespace: "db", Name: "ugly", Payload: []byte("!!!not-base64!!!")},
	}}
	got, err := Scan(context.Background(), source, Options{ReadHelmSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(got, "DSD-SCN-009", diag.LevelError) {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 5: no DSD-SCN-009: %#v", got.Diagnostics)
	}
	if got.Summary.Complete {
		t.Errorf("source docs/spec/v0.2-cluster.md section 4: an error diagnostic must mark the report incomplete")
	}
}

// TestScanForbiddenTiers checks DSD-SCN-010: a forbidden tier 1-2 list is a
// warning that marks the report incomplete, a forbidden tier 3 list is a warning
// that also marks a requested scan incomplete (review 03 M2), and any other API
// error is an error (spec v0.2 sections 4 and 5).
func TestScanForbiddenTiers(t *testing.T) {
	tests := []struct {
		name         string
		source       *fakeSource
		options      Options
		wantLevel    diag.Level
		wantComplete bool
	}{
		{"tier 1 forbidden", &fakeSource{workloadFailures: []ListFailure{{Tier: 1, Resource: "deployments", Namespace: "db", Forbidden: true}}}, Options{}, diag.LevelWarning, false},
		// review 03 M2: a requested tier 3 list that RBAC forbids is incomplete.
		{"tier 3 forbidden", &fakeSource{releaseFailures: []ListFailure{{Tier: 3, Resource: "secrets", Forbidden: true}}}, Options{ReadHelmSecrets: true}, diag.LevelWarning, false},
		{"tier 3 error", &fakeSource{releaseFailures: []ListFailure{{Tier: 3, Resource: "secrets", Namespace: "db"}}}, Options{ReadHelmSecrets: true}, diag.LevelError, false},
		{"api error", &fakeSource{workloadFailures: []ListFailure{{Tier: 1, Resource: "pods", Namespace: "db"}}}, Options{}, diag.LevelError, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Scan(context.Background(), tt.source, tt.options)
			if err != nil {
				t.Fatal(err)
			}
			if !hasDiagnostic(got, "DSD-SCN-010", tt.wantLevel) {
				t.Fatalf("source docs/spec/v0.2-cluster.md section 5: want %s DSD-SCN-010: %#v", tt.wantLevel, got.Diagnostics)
			}
			if got.Summary.Complete != tt.wantComplete {
				t.Errorf("source docs/spec/v0.2-cluster.md section 4: complete=%v want %v", got.Summary.Complete, tt.wantComplete)
			}
		})
	}
}

// TestScanMirrorAttribute checks the mirror attribute from running imageIDs
// (spec v0.2 section 3).
func TestScanMirrorAttribute(t *testing.T) {
	image := "bitnami/redis:7.2.4"
	source := &fakeSource{workloads: Workloads{Pods: []Pod{
		{Namespace: "db", Name: "cache-0", Containers: []Container{{Name: "redis", Image: image}},
			Status: []ContainerStatus{{Name: "redis", Image: image, ImageID: "mycache.example.com/bitnami/redis@sha256:aaaa"}}},
		{Namespace: "other", Name: "cache-1", Containers: []Container{{Name: "redis", Image: image}}},
	}}}
	got, err := Scan(context.Background(), source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mirrored := map[string]bool{}
	for _, f := range got.Findings {
		for _, attr := range f.Attributes {
			if attr == "mirror" {
				mirrored[f.Resource.Name] = true
			}
		}
	}
	if !mirrored["cache-0"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: missing mirror attribute on cache-0: %#v", got.Findings)
	}
	if mirrored["cache-1"] {
		t.Errorf("source docs/spec/v0.2-cluster.md section 3: unexpected mirror attribute on cache-1")
	}
}

// TestScanDeterministic checks the report does not depend on list order
// (CONVENTIONS.md; spec v0.2 section 3).
func TestScanDeterministic(t *testing.T) {
	document := `{"chart":{"metadata":{"name":"postgresql","version":"16.4.0","sources":["https://github.com/bitnami/charts/x"]}},"config":{"global":{"security":{"allowInsecureImages":true}}}}`
	build := func() diag.Report {
		source := &fakeSource{
			workloads: Workloads{Templates: []Workload{
				{Namespace: "db", Kind: "StatefulSet", Name: "pg", Containers: []Container{{Name: "b", Image: "bitnami/postgresql:16.4.0"}, {Name: "a", Image: "bitnamilegacy/os-shell:12"}}},
				{Namespace: "db", Kind: "Job", Name: "migrate", Containers: []Container{{Name: "m", Image: "bitnami/kubectl:latest"}}},
			}},
			releases: []Release{{Namespace: "db", Name: "pg", Payload: releasePayload(t, document)}},
		}
		got, err := Scan(context.Background(), source, Options{ReadHelmSecrets: true})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	first, second := build(), build()
	var a, b bytes.Buffer
	if err := report.JSON(&a, first); err != nil {
		t.Fatal(err)
	}
	if err := report.JSON(&b, second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 3: non-deterministic report")
	}
	if len(first.Findings) == 0 || first.Findings[0].Fingerprint == "" {
		t.Fatalf("source docs/spec/v0.2-cluster.md section 3: missing fingerprints")
	}
}

// TestScanHelmSecretsOff checks tier 3 is never read without the flag (spec v0.2
// sections 1 and 2).
func TestScanHelmSecretsOff(t *testing.T) {
	source := &fakeSource{releases: []Release{{Namespace: "db", Name: "pg", Payload: releasePayload(t, `{"config":{"global":{"security":{"allowInsecureImages":true}}}}`)}}}
	got, err := Scan(context.Background(), source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if source.releaseCalls != 0 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 3: ListReleases called without the flag")
	}
	if len(findingsFor(got, "DSD-CFG-001")) != 0 || got.Summary.Releases != 0 || len(got.Groups) != 0 {
		t.Errorf("source docs/spec/v0.2-cluster.md section 2 tier 3: tier 3 leaked: %#v", got)
	}
}

// TestScanMirrorScopedToWorkload checks review 03 m2: the mirror attribute from
// an imageID is scoped to the workload that owns the pod and to the container,
// not to the whole namespace and image (spec v0.2 section 3).
func TestScanMirrorScopedToWorkload(t *testing.T) {
	image := "bitnami/redis:7.2.4"
	source := &fakeSource{workloads: Workloads{
		Templates: []Workload{
			{Namespace: "db", Kind: "Deployment", Name: "cache", Containers: []Container{
				{Name: "redis", Image: image},
				{Name: "sidecar", Image: image},
			}},
			{Namespace: "db", Kind: "Deployment", Name: "other", Containers: []Container{{Name: "redis", Image: image}}},
		},
		Pods: []Pod{{
			Namespace: "db", Name: "cache-abc", Owned: true,
			OwnerChain: []Owner{{Kind: "Deployment", Name: "cache"}},
			Containers: []Container{{Name: "redis", Image: image}},
			Status:     []ContainerStatus{{Name: "redis", Image: image, ImageID: "mycache.example.com/bitnami/redis@sha256:aaaa"}},
		}},
	}}
	got, err := Scan(context.Background(), source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	mirrored := map[string]bool{}
	for _, f := range got.Findings {
		if f.Resource == nil {
			continue
		}
		for _, attr := range f.Attributes {
			if attr == "mirror" {
				mirrored[f.Resource.Name+"/"+f.Resource.Container] = true
			}
		}
	}
	if !mirrored["cache/redis"] {
		t.Errorf("review 03 m2: missing mirror on the owning workload: %#v", got.Findings)
	}
	if mirrored["cache/sidecar"] {
		t.Errorf("review 03 m2: mirror leaked to another container of the same workload")
	}
	if mirrored["other/redis"] {
		t.Errorf("review 03 m2: mirror leaked to another workload with the same image")
	}
}

// TestScanTotalTimeBudget checks adversarial audit F2: the --timeout value is
// the total time budget of the scan, not the timeout of one list, so a
// stalling server cannot make the scan run for timeout x namespaces x kinds.
// The scan stops cleanly, reports what it read and one diagnostic that says
// the scan is incomplete.
func TestScanTotalTimeBudget(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(release)

	source := newHTTPSource(t, server.URL)
	start := time.Now()
	got, err := Scan(context.Background(), source, Options{Timeout: 700 * time.Millisecond, Namespaces: []string{"a", "b", "c"}})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("audit F2: the scan ran for %s with a budget of 700ms", elapsed)
	}
	if got.Summary.Complete {
		t.Error("audit F2: a scan that ran out of budget reported complete")
	}
	if len(got.Diagnostics) != 1 {
		t.Fatalf("audit F2: want one diagnostic, got %#v", got.Diagnostics)
	}
	if got.Diagnostics[0].Code != "DSD-SCN-005" || !strings.Contains(got.Diagnostics[0].Message, "time budget") {
		t.Errorf("audit F2: diagnostic %#v", got.Diagnostics[0])
	}
}

// TestScanListLimitDiagnostic checks adversarial audit F1: a list that reached
// a safety limit is reported as DSD-SCN-005 and the scan is incomplete.
func TestScanListLimitDiagnostic(t *testing.T) {
	source := &fakeSource{workloadFailures: []ListFailure{{Tier: 1, Resource: "pods", Namespace: "db", Code: "DSD-SCN-005", Detail: "list reached the MaxItemsPerList limit of 100000 items"}}}
	got, err := Scan(context.Background(), source, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDiagnostic(got, "DSD-SCN-005", diag.LevelWarning) {
		t.Fatalf("audit F1: no DSD-SCN-005: %#v", got.Diagnostics)
	}
	if got.Summary.Complete {
		t.Error("audit F1: a list that hit a limit must leave the scan incomplete")
	}
	for _, d := range got.Diagnostics {
		if !strings.Contains(d.Message, "MaxItemsPerList") {
			t.Errorf("audit F1: the diagnostic does not name the limit: %q", d.Message)
		}
	}
}

// TestSortClusterFindingsTieBreak checks review 03 m3: equal sort keys are fully
// ordered by original, then resource kind and name, so output is deterministic.
func TestSortClusterFindingsTieBreak(t *testing.T) {
	base := diag.Finding{
		RuleID:    "DSD-IMG-002",
		Severity:  diag.SeverityHigh,
		Impact:    diag.ImpactHigh,
		Location:  diag.Location{Path: "cluster/db/Pod/x"},
		Reference: "docker.io/bitnami/redis:7.2.4",
		Resource:  &diag.Resource{Kind: "Pod", Name: "x", Container: "redis"},
	}
	pod := base
	pod.Original = "a/redis:7.2.4"
	job := base
	job.Original = "a/redis:7.2.4"
	job.Resource = &diag.Resource{Kind: "Job", Name: "a", Container: "redis"}
	deployment := base
	deployment.Original = "a/redis:7.2.4"
	deployment.Resource = &diag.Resource{Kind: "Deployment", Name: "z", Container: "redis"}
	other := base
	other.Original = "b/redis:7.2.4"

	in := []diag.Finding{other, job, pod, deployment}
	sortClusterFindings(in)
	kinds := []string{in[0].Resource.Kind, in[1].Resource.Kind, in[2].Resource.Kind}
	if kinds[0] != "Deployment" || kinds[1] != "Job" || kinds[2] != "Pod" {
		t.Fatalf("review 03 m3: resource order %#v", kinds)
	}
	if in[3].Original != "b/redis:7.2.4" {
		t.Fatalf("review 03 m3: original order %#v", []string{in[0].Original, in[1].Original, in[2].Original, in[3].Original})
	}
}
