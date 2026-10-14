// Package diag defines disdetta's stable finding and diagnostic contract.
package diag

import "strconv"

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
}

// Report is the complete scan result.
type Report struct {
	Summary     Summary
	Findings    []Finding
	Diagnostics []Diagnostic
}

// Entry describes a registered rule or diagnostic code.
type Entry struct {
	Code     string
	Title    string
	Severity Severity
	Level    Level
}

var entries = []Entry{
	{Code: "DSD-CFG-001", Title: "allowInsecureImages is enabled", Severity: SeverityHigh}, {Code: "DSD-IMG-001", Title: "Bitnami legacy image", Severity: SeverityHigh}, {Code: "DSD-IMG-002", Title: "Versioned Bitnami image", Severity: SeverityHigh}, {Code: "DSD-IMG-003", Title: "Community Bitnami image", Severity: SeverityMedium}, {Code: "DSD-IMG-004", Title: "Bitnami image from another registry", Severity: SeverityLow}, {Code: "DSD-CHT-001", Title: "Bitnami chart source", Severity: SeverityMedium}, {Code: "DSD-CHT-002", Title: "Vendored Bitnami chart", Severity: SeverityMedium},
	{Code: "DSD-SCN-001", Title: "Malformed file", Level: LevelError}, {Code: "DSD-SCN-002", Title: "File skipped", Level: LevelWarning}, {Code: "DSD-SCN-008", Title: "File larger than the size limit", Level: LevelError}, {Code: "DSD-SCN-003", Title: "Unresolved reference", Level: LevelInfo}, {Code: "DSD-SCN-004", Title: "Read error", Level: LevelError}, {Code: "DSD-SCN-005", Title: "Limit reached", Level: LevelWarning}, {Code: "DSD-SCN-006", Title: "Ignore entry expired", Level: LevelWarning}, {Code: "DSD-SCN-007", Title: "Template text scanned line by line", Level: LevelInfo},
}

// List returns the registry in contract order.
func List() []Entry { return append([]Entry(nil), entries...) }

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
