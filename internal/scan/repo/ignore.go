package repo

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"gopkg.in/yaml.v3"
)

type ignoreFile struct {
	Ignores []ignoreEntry `yaml:"ignores"`
}
type ignoreEntry struct{ Fingerprint, Rule, Path, Reason, Expires string }

func parseIgnores(data []byte) ([]ignoreEntry, error) {
	var cfg ignoreFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid ignore file: %w", err)
	}
	for i, e := range cfg.Ignores {
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("invalid ignore file: ignores[%d].reason is required", i)
		}
		if _, err := time.Parse("2006-01-02", e.Expires); err != nil {
			return nil, fmt.Errorf("invalid ignore file: ignores[%d].expires must be YYYY-MM-DD", i)
		}
		fingerprintOK, _ := regexp.MatchString(`^[0-9a-f]{16}$`, e.Fingerprint)
		selectorOK := e.Rule != "" && e.Path != ""
		if fingerprintOK == selectorOK || (e.Fingerprint != "" && !fingerprintOK) {
			return nil, fmt.Errorf("invalid ignore file: ignores[%d] needs a 16-hex fingerprint or rule + path", i)
		}
		if selectorOK {
			valid := false
			for _, entry := range diag.List() {
				if entry.Code == e.Rule && entry.Severity != "" {
					valid = true
					break
				}
			}
			if !valid {
				return nil, fmt.Errorf("invalid ignore file: ignores[%d].rule is not a finding rule", i)
			}
			if strings.Contains(e.Path, "\\") {
				return nil, fmt.Errorf("invalid ignore file: ignores[%d].path must use forward slashes", i)
			}
		}
	}
	return cfg.Ignores, nil
}
func applyIgnores(r *diag.Report, entries []ignoreEntry, now time.Time, configPath string) {
	expired := make([]bool, len(entries))
	for i, e := range entries {
		if e.Expires < now.Format("2006-01-02") {
			expired[i] = true
			r.Diagnostics = append(r.Diagnostics, scanDiagnostic("DSD-SCN-006", diag.LevelWarning, configPath, "ignore entry expired"))
		}
	}
	kept := r.Findings[:0]
	for _, f := range r.Findings {
		suppressed := false
		for i, e := range entries {
			if !matchesIgnore(e, f) {
				continue
			}
			if expired[i] {
				continue
			}
			suppressed = true
			break
		}
		if suppressed {
			r.Summary.Ignored++
		} else {
			kept = append(kept, f)
		}
	}
	r.Findings = kept
}
func matchesIgnore(e ignoreEntry, f diag.Finding) bool {
	if e.Fingerprint != "" {
		return e.Fingerprint == f.Fingerprint
	}
	return e.Rule == f.RuleID && globMatch(e.Path, f.Location.Path)
}
func globMatch(pattern, value string) bool {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteByte('$')
	ok, _ := regexp.MatchString(b.String(), value)
	return ok
}
