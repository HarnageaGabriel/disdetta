// Package repo walks a repository and dispatches files to pure detectors.
package repo

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var skippedDirectories = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// MaxFileSize is the largest file scanned; larger files produce DSD-SCN-008.
const MaxFileSize = 16 * 1024 * 1024

// Options controls repository scanning integrations.
type Options struct {
	ConfigPath string
	Clock      func() time.Time
	Exclude    []string
}

// Scan walks root without changing it and returns a deterministic report.
func Scan(ctx context.Context, root string) (diag.Report, error) {
	return ScanWithOptions(ctx, root, Options{Clock: time.Now})
}

// ScanWithOptions walks root and applies ignores using the injected clock.
func ScanWithOptions(ctx context.Context, root string, options Options) (diag.Report, error) {
	original := root
	info, err := os.Lstat(root)
	if err != nil {
		return diag.Report{}, fmt.Errorf("scan %s: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, e := filepath.EvalSymlinks(root)
		if e != nil {
			return diag.Report{}, fmt.Errorf("resolve scan root %s: %w", root, e)
		}
		resolvedInfo, e := os.Stat(resolved)
		if e != nil {
			return diag.Report{}, fmt.Errorf("scan %s: %w", root, e)
		}
		if !resolvedInfo.IsDir() {
			r := diag.Report{Summary: diag.Summary{FilesSkipped: 1}, Diagnostics: []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, filepath.Base(root), "symbolic-link root file skipped")}}
			finalize(&r)
			return r, nil
		}
		root, info = resolved, resolvedInfo
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			r := diag.Report{Summary: diag.Summary{FilesSkipped: 1}, Diagnostics: []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, filepath.Base(root), "non-regular file skipped")}}
			finalize(&r)
			return r, nil
		}
		r := scanFile(root, filepath.Base(root), info)
		finalize(&r)
		return r, nil
	}
	var out diag.Report
	entries := []repositoryEntry{}
	err = walkRepository(ctx, root, func(entry repositoryEntry) error {
		if excluded(entry.display, options.Exclude) {
			return nil
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return diag.Report{}, fmt.Errorf("walk %s: %w", original, err)
	}
	claimed, plans, valuesReport := planValuesFiles(root, entries, options.Exclude)
	appendReport(&out, valuesReport)
	for _, entry := range entries {
		if entry.problem == 0 && claimed[pathKey(entry.path)] {
			continue // scanned once below, as chart values
		}
		switch entry.problem {
		case walkPathUnreadable:
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, entry.display, "path could not be read"))
			continue
		case walkSymlink:
			out.Summary.FilesSkipped++
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, entry.display, "symbolic link skipped"))
			continue
		case walkMetadataUnreadable:
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, entry.display, "file metadata could not be read"))
			continue
		case walkNonRegular:
			out.Summary.FilesSkipped++
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, entry.display, "non-regular file skipped"))
			continue
		}
		appendReport(&out, scanFile(entry.path, entry.display, entry.info))
	}
	for _, plan := range plans {
		appendReport(&out, scanValuesFile(plan))
	}
	finalize(&out)
	configPath := options.ConfigPath
	if configPath == "" {
		configPath = filepath.Join(root, ".disdetta.yaml")
	}
	data, configErr := os.ReadFile(configPath)
	if configErr == nil {
		entries, e := parseIgnores(data)
		if e != nil {
			return diag.Report{}, e
		}
		now := time.Time{}
		if options.Clock != nil {
			now = options.Clock()
		}
		displayConfig := filepath.Base(configPath)
		if rel, e := filepath.Rel(root, configPath); e == nil && !strings.HasPrefix(rel, "..") {
			displayConfig = filepath.ToSlash(rel)
		}
		applyIgnores(&out, entries, now, displayConfig)
		finalize(&out)
	} else if options.ConfigPath != "" || !errors.Is(configErr, os.ErrNotExist) {
		return diag.Report{}, fmt.Errorf("read ignore file %s: %w", configPath, configErr)
	}
	return out, nil
}
func scanFile(path, display string, info fs.FileInfo) (out diag.Report) {
	lower := strings.ToLower(info.Name())
	if lower == ".disdetta.yaml" {
		return out
	}
	yamlFile := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	dockerfile := lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile")
	kustomization := detect.IsKustomizationFile(path)
	templateText := strings.HasSuffix(lower, ".tpl") || (yamlFile && underChartTemplates(path))
	if !yamlFile && !dockerfile && !kustomization && !templateText {
		return out
	}
	data, err := readRegularFile(path, info)
	if errors.Is(err, ErrFileTooLarge) {
		out.Summary.FilesSkipped++
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-008", diag.LevelError, display, "file exceeds 16 MiB limit; skipped")}
		return out
	}
	if errors.Is(err, ErrUnsafeFile) {
		out.Summary.FilesSkipped++
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "file changed or became non-regular; skipped")}
		return out
	}
	if err != nil {
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file could not be read")}
		return out
	}
	out.Summary.FilesScanned = 1
	if dockerfile {
		detected := detect.Dockerfile(display, data)
		detected.Summary.FilesScanned = 1
		return detected
	}
	if templateText {
		detected := detect.Template(display, data)
		detected.Summary.FilesScanned = 1
		return detected
	}
	detected := detect.YAML(display, data)
	if detect.HasTemplateMarkers(data) && detect.Malformed(detected) {
		detected = detect.Template(display, data)
	}
	detected.Summary.FilesScanned = 1
	return detected
}

// excluded reports whether a slash-separated relative path matches a --exclude
// glob; excluded files are neither scanned nor skipped (spec section 7).
func excluded(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if globMatch(pattern, path) {
			return true
		}
	}
	return false
}

// underChartTemplates reports whether path is a YAML file in a Helm chart's
// templates/ directory, i.e. a sibling of Chart.yaml (spec section 9.1).
func underChartTemplates(path string) bool {
	dir := filepath.Dir(path)
	for {
		if filepath.Base(dir) == "templates" {
			_, err := os.Stat(filepath.Join(filepath.Dir(dir), "Chart.yaml"))
			return err == nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}
func appendReport(dst *diag.Report, src diag.Report) {
	dst.Summary.FilesScanned += src.Summary.FilesScanned
	dst.Summary.FilesSkipped += src.Summary.FilesSkipped
	dst.Summary.Ignored += src.Summary.Ignored
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Diagnostics = append(dst.Diagnostics, src.Diagnostics...)
}
func scanDiagnostic(code string, level diag.Level, path, message string) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Level: level, Message: message, Location: diag.Location{Path: path}}
}

// Finalize de-duplicates findings, applies contract ordering, and then assigns
// fingerprints and summary fields. Occurrences are numbered after sorting, in
// source order, so detector map iteration order never reaches the output
// (spec sections 4, 5).
func finalize(r *diag.Report) {
	r.Findings = diag.DedupeFindings(r.Findings)
	Sort(r)
	occ := map[string]int{}
	for i := range r.Findings {
		f := &r.Findings[i]
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + f.Reference
		n := occ[key]
		occ[key] = n + 1
		if f.Fingerprint == "" {
			sum := sha256.Sum256([]byte(key + "\x00" + strconv.Itoa(n)))
			f.Fingerprint = fmt.Sprintf("%x", sum[:8])
		}
		if f.Attributes == nil {
			f.Attributes = []string{}
		}
	}
	r.Summary.Findings = diag.FindingCounts{}
	r.Summary.Unresolved = 0
	for _, f := range r.Findings {
		switch f.Severity {
		case diag.SeverityHigh:
			r.Summary.Findings.High++
		case diag.SeverityMedium:
			r.Summary.Findings.Medium++
		case diag.SeverityLow:
			r.Summary.Findings.Low++
		}
	}
	r.Summary.Diagnostics = len(r.Diagnostics)
	r.Summary.Complete = true
	for _, d := range r.Diagnostics {
		if d.Code == "DSD-SCN-003" {
			r.Summary.Unresolved++
		}
		if d.Level == diag.LevelError {
			r.Summary.Complete = false
		}
	}
}

// Sort applies contract ordering.
func Sort(r *diag.Report) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if diag.SeverityRank(a.Severity) != diag.SeverityRank(b.Severity) {
			return diag.SeverityRank(a.Severity) < diag.SeverityRank(b.Severity)
		}
		if diag.ImpactRank(a.Impact) != diag.ImpactRank(b.Impact) {
			return diag.ImpactRank(a.Impact) < diag.ImpactRank(b.Impact)
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.Location.Column != b.Location.Column {
			return a.Location.Column < b.Location.Column
		}
		return a.RuleID < b.RuleID
	})
	sort.SliceStable(r.Diagnostics, func(i, j int) bool {
		a, b := r.Diagnostics[i], r.Diagnostics[j]
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.Code < b.Code
	})
}
