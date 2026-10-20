// Package report renders scanner findings in stable human and machine formats.
package report

import (
	"encoding/json"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/version"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"
)

// Table writes the v1 compact deterministic table and summary.
func Table(w io.Writer, r diag.Report) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, e := fmt.Fprintln(tw, "LOCATION\tRULE\tSEVERITY\tCONFIDENCE\tIMPACT\tREFERENCE"); e != nil {
		return e
	}
	for _, f := range r.Findings {
		cells := []string{location(f.Location), f.RuleID, string(f.Severity), string(f.Confidence), string(f.Impact), f.Reference}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", SafeText(cells[0]), SafeText(cells[1]), SafeText(cells[2]), SafeText(cells[3]), SafeText(cells[4]), SafeText(cells[5])); e != nil {
			return e
		}
	}
	for _, d := range r.Diagnostics {
		if d.Level == diag.LevelInfo {
			continue
		}
		cells := []string{location(d.Location), d.Code, string(d.Level), "-", "-", d.Message}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", SafeText(cells[0]), SafeText(cells[1]), SafeText(cells[2]), cells[3], cells[4], SafeText(cells[5])); e != nil {
			return e
		}
	}
	s := r.Summary
	summary := fmt.Sprintf("scanned %d files, skipped %d, findings %d (high %d, medium %d, low %d), diagnostics %d, unresolved %d, ignored %d", s.FilesScanned, s.FilesSkipped, s.Findings.High+s.Findings.Medium+s.Findings.Low, s.Findings.High, s.Findings.Medium, s.Findings.Low, s.Diagnostics, s.Unresolved, s.Ignored)
	if s.Releases > 0 {
		// Cluster scans add the release count (spec v0.2 section 3); repository
		// output is unchanged because Releases is zero there.
		summary += fmt.Sprintf(", releases %d", s.Releases)
	}
	if _, e := fmt.Fprintln(tw, summary); e != nil {
		return e
	}
	return tw.Flush()
}

// SARIF writes one deterministic SARIF 2.1.0 run for a report.
func SARIF(w io.Writer, r diag.Report) error {
	entries := diag.List()
	rules := make([]sarifRule, 0, len(entries))
	ruleIndex := make(map[string]int, len(entries))
	for _, e := range entries {
		if e.Severity == "" {
			continue
		}
		ruleIndex[e.Code] = len(rules)
		rules = append(rules, sarifRule{
			ID:               e.Code,
			Name:             slug(e.Title),
			ShortDescription: sarifText{Text: e.Title},
			FullDescription:  sarifText{Text: e.OneLiner},
			HelpURI:          e.DocURL(),
			DefaultConfiguration: sarifDefaultConfiguration{
				Level: sarifLevel(e.Severity),
			},
			Properties: sarifRuleProperties{Tags: []string{"bitnami", "security"}},
		})
	}
	notifications := make([]sarifNotification, 0, len(r.Diagnostics))
	for _, d := range r.Diagnostics {
		n := sarifNotification{
			Descriptor: sarifDescriptor{ID: d.Code},
			Level:      sarifDiagnosticLevel(d.Level),
			Message:    sarifMessage{Text: d.Message},
		}
		if d.Location.Path != "" {
			n.Locations = []sarifNotificationLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: d.Location.Path},
				Region:           sarifRegion{StartLine: d.Location.Line, StartColumn: d.Location.Column},
			}}}
		}
		notifications = append(notifications, n)
	}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		index, ok := ruleIndex[f.RuleID]
		if !ok {
			return fmt.Errorf("rule %q is not registered", f.RuleID)
		}
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: resultMessage(f)},
			Properties: sarifResultProperties{
				Confidence: string(f.Confidence),
				Impact:     string(f.Impact),
				Component:  f.Component,
				Attributes: f.Attributes,
			},
		}
		if f.Attributes == nil {
			res.Properties.Attributes = []string{}
		}
		if f.Location.Line == 0 && f.Resource != nil {
			res.Locations = []sarifResultLocation{{
				LogicalLocations: []sarifLogicalLocation{{
					FullyQualifiedName: f.Location.Path,
					Kind:               f.Resource.Kind,
				}},
			}}
		} else {
			region := sarifRegion{}
			if f.Location.Line >= 1 {
				region.StartLine = f.Location.Line
				if f.Location.Column >= 1 {
					region.StartColumn = f.Location.Column
				}
			}
			res.Locations = []sarifResultLocation{{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.Location.Path, URIBaseID: "%SRCROOT%"},
					Region:           region,
				},
			}}
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"disdettaFingerprint/v1": f.Fingerprint}
		}
		results = append(results, res)
	}
	exitCode := 0
	if !r.Summary.Complete {
		exitCode = 3
	} else if len(r.Findings) > 0 {
		exitCode = 1
	}
	doc := sarifLog{
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "disdetta",
				Version:        version.Get().Version,
				InformationURI: "https://github.com/HarnageaGabriel/disdetta",
				Rules:          rules,
			}},
			Invocations: []sarifInvocation{{
				ExecutionSuccessful:        r.Summary.Complete,
				ExitCode:                   exitCode,
				ToolExecutionNotifications: notifications,
				Properties:                 sarifInvocationProperties{Ignored: r.Summary.Ignored},
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// RulesTable writes the registry as a deterministic text table.
func RulesTable(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, e := fmt.Fprintln(tw, "CODE\tKIND\tSEVERITY\tLEVEL\tTITLE\tDOCS"); e != nil {
		return e
	}
	for _, e := range diag.List() {
		severity, level := string(e.Severity), string(e.Level)
		if severity == "" {
			severity = "-"
		}
		if level == "" {
			level = "-"
		}
		if _, e := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", SafeText(e.Code), e.Kind(), severity, level, SafeText(e.Title), e.DocURL()); e != nil {
			return e
		}
	}
	return tw.Flush()
}

// RulesJSON writes schema-version-1 registry JSON with stable struct field order.
func RulesJSON(w io.Writer) error {
	type ruleJSON struct {
		Code     string `json:"code"`
		Kind     string `json:"kind"`
		Severity string `json:"severity"`
		Level    string `json:"level"`
		Title    string `json:"title"`
		OneLiner string `json:"oneLiner"`
		Docs     string `json:"docs"`
	}
	entries := diag.List()
	out := struct {
		SchemaVersion string     `json:"schemaVersion"`
		Rules         []ruleJSON `json:"rules"`
	}{SchemaVersion: "1", Rules: make([]ruleJSON, 0, len(entries))}
	for _, e := range entries {
		severity, level := string(e.Severity), string(e.Level)
		if severity == "" {
			severity = ""
		}
		if level == "" {
			level = ""
		}
		out.Rules = append(out.Rules, ruleJSON{Code: e.Code, Kind: e.Kind(), Severity: severity, Level: level, Title: e.Title, OneLiner: e.OneLiner, Docs: e.DocURL()})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// JSON writes the schema-version-1 envelope with stable struct field order.
func JSON(w io.Writer, r diag.Report) error {
	v := struct {
		SchemaVersion string `json:"schemaVersion"`
		Tool          struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Summary     diag.Summary      `json:"summary"`
		Findings    []diag.Finding    `json:"findings"`
		Groups      []diag.Group      `json:"groups,omitempty"`
		Diagnostics []diag.Diagnostic `json:"diagnostics"`
	}{SchemaVersion: "1", Summary: r.Summary, Findings: r.Findings, Groups: r.Groups, Diagnostics: r.Diagnostics}
	v.Tool.Name = "disdetta"
	v.Tool.Version = "dev"
	if v.Findings == nil {
		v.Findings = []diag.Finding{}
	}
	if v.Diagnostics == nil {
		v.Diagnostics = []diag.Diagnostic{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func location(v diag.Location) string {
	if v.Line == 0 {
		return v.Path
	}
	if v.Column == 0 {
		return fmt.Sprintf("%s:%d", v.Path, v.Line)
	}
	return fmt.Sprintf("%s:%d:%d", v.Path, v.Line, v.Column)
}

// safeCell escapes a table cell so no raw control character or Unicode format
// character (category Cf) can forge a row, and an invalid UTF-8 byte is
// escaped rather than replaced (spec section 6).
func SafeText(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		r, size := utf8.DecodeRuneInString(v[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, v[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case !unicode.IsPrint(r) || unicode.In(r, unicode.Cf):
			switch {
			case r > 0xFFFF:
				fmt.Fprintf(&b, `\U%08x`, r)
			case r > 0xFF:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\x%02x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type sarifText struct {
	Text string `json:"text"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}
type sarifRuleProperties struct {
	Tags []string `json:"tags"`
}
type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	ShortDescription     sarifText                 `json:"shortDescription"`
	FullDescription      sarifText                 `json:"fullDescription"`
	HelpURI              string                    `json:"helpUri"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
	Properties           sarifRuleProperties       `json:"properties"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}
type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}
type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}
type sarifNotificationLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifDescriptor struct {
	ID string `json:"id"`
}
type sarifNotification struct {
	Descriptor sarifDescriptor             `json:"descriptor"`
	Level      string                      `json:"level"`
	Message    sarifMessage                `json:"message"`
	Locations  []sarifNotificationLocation `json:"locations,omitempty"`
}
type sarifResultProperties struct {
	Confidence string   `json:"confidence"`
	Impact     string   `json:"impact"`
	Component  string   `json:"component"`
	Attributes []string `json:"attributes"`
}
type sarifResultLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}
type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifResultLocation `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints,omitempty"`
	Properties          sarifResultProperties `json:"properties"`
}
type sarifInvocationProperties struct {
	Ignored int `json:"ignored"`
}
type sarifInvocation struct {
	ExecutionSuccessful        bool                      `json:"executionSuccessful"`
	ExitCode                   int                       `json:"exitCode"`
	ToolExecutionNotifications []sarifNotification       `json:"toolExecutionNotifications"`
	Properties                 sarifInvocationProperties `json:"properties"`
}
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}
type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

func sarifLevel(v diag.Severity) string {
	switch v {
	case diag.SeverityHigh:
		return "error"
	case diag.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
func sarifDiagnosticLevel(v diag.Level) string {
	switch v {
	case diag.LevelError:
		return "error"
	case diag.LevelWarning:
		return "warning"
	default:
		return "note"
	}
}
func slug(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && r == ' ':
			b.WriteByte('-')
		}
	}
	return b.String()
}
func resultMessage(f diag.Finding) string {
	entry := ""
	for _, e := range diag.List() {
		if e.Code == f.RuleID {
			entry = e.OneLiner
			break
		}
	}
	if entry == "" {
		entry = f.RuleID
	}
	if f.Reference != "" {
		return entry + " Reference: " + f.Reference
	}
	return entry
}
