// Package diag defines disdetta's stable finding and diagnostic contract.
package diag

import (
	"sort"
	"strconv"
)

// Severity is a finding's policy severity.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Confidence describes how directly a reference identifies Docker Hub.
type Confidence string

const (
	ConfidenceConfirmed  Confidence = "confirmed"
	ConfidenceInferred   Confidence = "inferred"
	ConfidenceUnresolved Confidence = "unresolved"
)

// Impact estimates migration effort.
type Impact string

const (
	ImpactHigh    Impact = "high"
	ImpactMedium  Impact = "medium"
	ImpactLow     Impact = "low"
	ImpactUnknown Impact = "unknown"
)

// Level is a scan diagnostic level.
type Level string

const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelInfo    Level = "info"
)

// Location identifies a one-based source position.
type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// Finding is a Bitnami dependency found in configuration.
type Finding struct {
	RuleID      string     `json:"ruleId"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Impact      Impact     `json:"impact"`
	Component   string     `json:"component"`
	Location    Location   `json:"location"`
	Reference   string     `json:"reference"`
	Original    string     `json:"original"`
	Attributes  []string   `json:"attributes"`
	Fingerprint string     `json:"fingerprint"`
	// Resource identifies the cluster object a cluster finding was read from.
	// It is nil for repository findings (spec v0.2 section 3).
	Resource *Resource `json:"resource,omitempty"`
}

// Resource identifies the Kubernetes object a cluster finding was read from
// (spec v0.2 section 3). Container is empty for release-level findings;
// Release and Chart are empty when the tier 2 labels or tier 3 chart metadata
// do not name them.
type Resource struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Release   string `json:"release"`
	Chart     string `json:"chart"`
}

// Group aggregates the findings of one cluster workload or Helm release
// (spec v0.2 section 3). Fingerprints are ordered with the findings.
type Group struct {
	Namespace    string   `json:"namespace"`
	Name         string   `json:"name"`
	Component    string   `json:"component"`
	Severity     Severity `json:"severity"`
	Impact       Impact   `json:"impact"`
	Fingerprints []string `json:"fingerprints"`
}

// Diagnostic describes an input that could not be scanned completely.
type Diagnostic struct {
	Code     string   `json:"code"`
	Level    Level    `json:"level"`
	Message  string   `json:"message"`
	Location Location `json:"location"`
}

// FindingCounts groups findings by severity.
type FindingCounts struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// Summary describes scan coverage and totals.
type Summary struct {
	FilesScanned int           `json:"filesScanned"`
	FilesSkipped int           `json:"filesSkipped"`
	Findings     FindingCounts `json:"findings"`
	Diagnostics  int           `json:"diagnostics"`
	Unresolved   int           `json:"unresolved"`
	Ignored      int           `json:"ignored"`
	Complete     bool          `json:"complete"`
	// Releases is the number of distinct Helm releases with at least one
	// finding (spec v0.2 section 3). It is omitted when zero so repository
	// reports and their goldens stay unchanged.
	Releases int `json:"releases,omitempty"`
}

// Report is the complete scan result.
type Report struct {
	Summary     Summary
	Findings    []Finding
	Diagnostics []Diagnostic
	// Groups aggregates cluster findings per workload or Helm release
	// (spec v0.2 section 3). It is empty for repository scans.
	Groups []Group
}

// Entry describes a registered rule or diagnostic code.
type Entry struct {
	Code     string
	Title    string
	OneLiner string
	Severity Severity
	Level    Level
}

// DocURL returns the stable diagnostics page for an entry.
func (e Entry) DocURL() string {
	return "https://github.com/HarnageaGabriel/disdetta/blob/main/docs/diagnostics/" + e.Code + ".md"
}

// Kind returns whether the entry is a finding rule or scanner diagnostic.
func (e Entry) Kind() string {
	if e.Severity != "" {
		return "rule"
	}
	return "diagnostic"
}

var entries = []Entry{
	{Code: "DSD-CFG-001", Title: "allowInsecureImages is enabled", OneLiner: "Image verification is disabled by allowInsecureImages.", Severity: SeverityHigh},
	{Code: "DSD-IMG-001", Title: "Bitnami legacy image", OneLiner: "The frozen Bitnamilegacy image has no security updates.", Severity: SeverityHigh},
	{Code: "DSD-IMG-002", Title: "Versioned Bitnami image", OneLiner: "A versioned Bitnami image may no longer pull from the public path.", Severity: SeverityHigh},
	{Code: "DSD-IMG-003", Title: "Community Bitnami image", OneLiner: "A community-tier Bitnami image is intended for development.", Severity: SeverityMedium},
	{Code: "DSD-IMG-004", Title: "Bitnami image from another registry", OneLiner: "The Bitnami image is mirrored or rebuilt outside Docker Hub.", Severity: SeverityLow},
	{Code: "DSD-CHT-001", Title: "Bitnami chart source", OneLiner: "The chart is sourced from a Bitnami chart repository.", Severity: SeverityMedium},
	{Code: "DSD-CHT-002", Title: "Vendored Bitnami chart", OneLiner: "A vendored Bitnami chart pins its images.", Severity: SeverityMedium},
	{Code: "DSD-SCN-001", Title: "Malformed file", OneLiner: "The file could not be parsed.", Level: LevelError},
	{Code: "DSD-SCN-002", Title: "File skipped", OneLiner: "The path was skipped because it is not a regular file.", Level: LevelWarning},
	{Code: "DSD-SCN-008", Title: "File larger than the size limit", OneLiner: "The file exceeded the scan size limit.", Level: LevelError},
	{Code: "DSD-SCN-003", Title: "Unresolved reference", OneLiner: "A templated reference has no static Bitnami evidence.", Level: LevelInfo},
	{Code: "DSD-SCN-004", Title: "Read error", OneLiner: "The path could not be read.", Level: LevelError},
	{Code: "DSD-SCN-005", Title: "Limit reached", OneLiner: "A scanner safety limit was reached.", Level: LevelWarning},
	{Code: "DSD-SCN-006", Title: "Ignore entry expired", OneLiner: "The ignore entry has expired.", Level: LevelWarning},
	{Code: "DSD-SCN-007", Title: "Template text scanned line by line", OneLiner: "Template text was scanned line by line.", Level: LevelInfo},
	{Code: "DSD-SCN-009", Title: "Helm release payload over a cap or not decodable", OneLiner: "The Helm release payload could not be decoded.", Level: LevelError},
	{Code: "DSD-SCN-010", Title: "Cluster list failed", OneLiner: "A cluster list call failed.", Level: LevelWarning},
}

// List returns the registry sorted by code.
func List() []Entry {
	out := append([]Entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// DedupeFindings drops exact repeats so an anchor and every alias use of one
// logical reference are reported once, at the anchor (spec section 5).
func DedupeFindings(in []Finding) []Finding {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, f := range in {
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + strconv.Itoa(f.Location.Line) + "\x00" + strconv.Itoa(f.Location.Column) + "\x00" + f.Reference + "\x00" + f.Original + "\x00" + string(f.Confidence)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// SeverityRank returns high before medium before low.
func SeverityRank(v Severity) int {
	if v == SeverityHigh {
		return 0
	}
	if v == SeverityMedium {
		return 1
	}
	return 2
}

// ImpactRank returns high, medium, low, unknown.
func ImpactRank(v Impact) int {
	if v == ImpactHigh {
		return 0
	}
	if v == ImpactMedium {
		return 1
	}
	if v == ImpactLow {
		return 2
	}
	return 3
}

// ClusterSummary returns the number of distinct Helm releases with at least one
// finding and the per-workload or per-release groups of a cluster finding set
// (spec v0.2 section 3). Findings must already be ordered; groups come back in
// severity, impact, namespace, name order. It returns 0 and nil when no finding
// carries a Resource, so repository reports stay unchanged.
func ClusterSummary(findings []Finding) (int, []Group) {
	type accumulator struct {
		namespace string
		name      string
		component string
		severity  Severity
		impact    Impact
		group     []string
	}
	releases := map[string]bool{}
	byKey := map[string]*accumulator{}
	for _, f := range findings {
		if f.Resource == nil {
			continue
		}
		r := f.Resource
		if r.Release != "" {
			releases[r.Namespace+"\x00"+r.Release] = true
		}
		name := r.Release
		if name == "" {
			name = r.Name
		}
		key := r.Namespace + "\x00" + name
		a := byKey[key]
		if a == nil {
			a = &accumulator{namespace: r.Namespace, name: name, component: f.Component, severity: f.Severity, impact: f.Impact}
			byKey[key] = a
		}
		if SeverityRank(f.Severity) < SeverityRank(a.severity) {
			a.severity = f.Severity
			a.component = f.Component
		}
		if ImpactRank(f.Impact) < ImpactRank(a.impact) {
			a.impact = f.Impact
		}
		a.group = append(a.group, f.Fingerprint)
	}
	if len(byKey) == 0 {
		return 0, nil
	}
	groups := make([]Group, 0, len(byKey))
	for _, a := range byKey {
		groups = append(groups, Group{Namespace: a.namespace, Name: a.name, Component: a.component, Severity: a.severity, Impact: a.impact, Fingerprints: a.group})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if SeverityRank(groups[i].Severity) != SeverityRank(groups[j].Severity) {
			return SeverityRank(groups[i].Severity) < SeverityRank(groups[j].Severity)
		}
		if ImpactRank(groups[i].Impact) != ImpactRank(groups[j].Impact) {
			return ImpactRank(groups[i].Impact) < ImpactRank(groups[j].Impact)
		}
		if groups[i].Namespace != groups[j].Namespace {
			return groups[i].Namespace < groups[j].Namespace
		}
		return groups[i].Name < groups[j].Name
	})
	return len(releases), groups
}
