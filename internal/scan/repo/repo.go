// Package repo walks a repository and dispatches files to pure detectors.
package repo

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var skippedDirectories = map[string]bool{".git": true, "node_modules": true, "vendor": true}

const maxFileSize = 5 * 1024 * 1024

// Scan walks root without changing it and returns a deterministic report.
func Scan(ctx context.Context, root string) (diag.Report, error) {
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
			r := diag.Report{Diagnostics: []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, filepath.Base(root), "symbolic-link root file skipped")}}
			finalize(&r)
			return r, nil
		}
		root, info = resolved, resolvedInfo
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			r := diag.Report{Diagnostics: []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, filepath.Base(root), "non-regular file skipped")}}
			finalize(&r)
			return r, nil
		}
		r := scanFile(root, filepath.Base(root), info)
		finalize(&r)
		return r, nil
	}
	var out diag.Report
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root {
				return walkErr
			}
			rel, e := filepath.Rel(root, path)
			if e != nil {
				return e
			}
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, filepath.ToSlash(rel), "path could not be read"))
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			if path != root && skippedDirectories[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		display := filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			out.Summary.FilesSkipped++
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "symbolic link skipped"))
			return nil
		}
		entryInfo, e := entry.Info()
		if e != nil {
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file metadata could not be read"))
			return nil
		}
		if !entryInfo.Mode().IsRegular() {
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "non-regular file skipped"))
			return nil
		}
		appendReport(&out, scanFile(path, display, entryInfo))
		return nil
	})
	if err != nil {
		return diag.Report{}, fmt.Errorf("walk %s: %w", original, err)
	}
	finalize(&out)
	return out, nil
}
func scanFile(path, display string, info fs.FileInfo) (out diag.Report) {
	lower := strings.ToLower(info.Name())
	yamlFile := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	dockerfile := lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.")
	if !yamlFile && !dockerfile {
		return out
	}
	if info.Size() > maxFileSize {
		out.Summary.FilesSkipped++
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "file exceeds 5 MiB limit; skipped")}
		return out
	}
	file, err := os.Open(path)
	if err != nil {
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file could not be read")}
		return out
	}
	readOK := false
	defer func() {
		if e := file.Close(); e != nil && readOK {
			out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file could not be closed"))
		}
	}()
	opened, e := file.Stat()
	if e != nil {
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file metadata could not be read")}
		return out
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		out.Summary.FilesSkipped++
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "file changed or became non-regular; skipped")}
		return out
	}
	data, e := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if e != nil {
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-004", diag.LevelError, display, "file could not be read")}
		return out
	}
	readOK = true
	if len(data) > maxFileSize {
		out.Summary.FilesSkipped++
		out.Diagnostics = []diag.Diagnostic{scanDiagnostic("DSD-SCN-002", diag.LevelWarning, display, "file exceeds 5 MiB limit; skipped")}
		return out
	}
	out.Summary.FilesScanned = 1
	if dockerfile {
		detected := detect.Dockerfile(display, data)
		detected.Summary.FilesScanned = 1
		return detected
	}
	detected := detect.YAML(display, data)
	detected.Summary.FilesScanned = 1
	return detected
}
func appendReport(dst *diag.Report, src diag.Report) {
	dst.Summary.FilesScanned += src.Summary.FilesScanned
	dst.Summary.FilesSkipped += src.Summary.FilesSkipped
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Diagnostics = append(dst.Diagnostics, src.Diagnostics...)
}
func scanDiagnostic(code string, level diag.Level, path, message string) diag.Diagnostic {
	return diag.Diagnostic{Code: code, Level: level, Message: message, Location: diag.Location{Path: path}}
}

// Finalize calculates fingerprints, summary fields, and contract ordering.
func finalize(r *diag.Report) {
	occ := map[string]int{}
	for i := range r.Findings {
		f := &r.Findings[i]
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + f.Reference
		n := occ[key]
		occ[key] = n + 1
		sum := sha256.Sum256([]byte(key + "\x00" + strconv.Itoa(n)))
		f.Fingerprint = fmt.Sprintf("%x", sum[:8])
		if f.Attributes == nil {
			f.Attributes = []string{}
		}
	}
	Sort(r)
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
		if f.Confidence == diag.ConfidenceUnresolved {
			r.Summary.Unresolved++
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
