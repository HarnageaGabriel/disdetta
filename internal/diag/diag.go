// Package diag defines disdetta's stable diagnostic vocabulary.
package diag

// Severity is ordered by Rank, with the strongest signal first.
type Severity string

const (
	SeverityAllowInsecure Severity = "DSD-SEV-1"
	SeverityLegacy        Severity = "DSD-SEV-2"
	SeverityBitnami       Severity = "DSD-SEV-3"
)

// Diagnostic is one safely printable scanner finding.
type Diagnostic struct {
	Code           string   `json:"code"`
	Severity       Severity `json:"severity"`
	Message        string   `json:"message"`
	Reference      string   `json:"reference"`
	Classification string   `json:"classification"`
	Path           string   `json:"path"`
	Line           int      `json:"line"`
	Stateful       bool     `json:"stateful"`
}

// Entry describes a registered stable code.
type Entry struct {
	Code     string
	Title    string
	Severity Severity
}

var entries = []Entry{
	{Code: "DSD-001", Title: "allowInsecureImages is enabled", Severity: SeverityAllowInsecure},
	{Code: "DSD-002", Title: "Bitnami legacy image", Severity: SeverityLegacy},
	{Code: "DSD-003", Title: "Bitnami image", Severity: SeverityBitnami},
	{Code: "DSD-004", Title: "Bitnami chart source", Severity: SeverityBitnami},
	{Code: "DSD-005", Title: "Unresolved templated image", Severity: SeverityBitnami},
}

// List returns the registry in code order.
func List() []Entry { return append([]Entry(nil), entries...) }

// Rank returns a stable severity sort rank.
func Rank(s Severity) int {
	switch s {
	case SeverityAllowInsecure:
		return 1
	case SeverityLegacy:
		return 2
	default:
		return 3
	}
}
