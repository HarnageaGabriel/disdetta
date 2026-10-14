// Package repo walks a repository and dispatches files to pure detectors.
package repo

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

var skippedDirectories = map[string]bool{".git": true, "node_modules": true, "vendor": true}

const maxFileSize = 5 * 1024 * 1024

// Scan walks root without changing it and returns deterministically sorted findings.
func Scan(ctx context.Context, root string) (diag.Report, error) {
	originalRoot := root
	info, err := os.Lstat(root)
	if err != nil {
		return diag.Report{}, fmt.Errorf("scan %s: %w", root, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if resolveErr != nil {
			return diag.Report{}, fmt.Errorf("resolve scan root %s: %w", root, resolveErr)
		}
		resolvedInfo, statErr := os.Stat(resolved)
		if statErr != nil {
			return diag.Report{}, fmt.Errorf("scan %s: %w", root, statErr)
		}
		if !resolvedInfo.IsDir() {
			return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(filepath.Base(root), "symbolic-link root is not a directory; file skipped")}}, nil
		}
		root, info = resolved, resolvedInfo
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(filepath.Base(root), "non-regular file skipped")}}, nil
		}
		result := scanFile(root, filepath.Base(root), info)
		Sort(&result)
		return result, nil
	}
	var result diag.Report
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root {
				return walkErr
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic(filepath.ToSlash(relative), "path could not be read: "+walkErr.Error()))
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
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		displayPath := filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic(displayPath, "symbolic link skipped"))
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic(displayPath, "file metadata could not be read: "+err.Error()))
			return nil
		}
		if !entryInfo.Mode().IsRegular() {
			result.Diagnostics = append(result.Diagnostics, scanDiagnostic(displayPath, "non-regular file skipped"))
			return nil
		}
		appendReport(&result, scanFile(path, displayPath, entryInfo))
		return nil
	})
	if err != nil {
		return diag.Report{}, fmt.Errorf("walk %s: %w", originalRoot, err)
	}
	Sort(&result)
	return result, nil
}

func scanFile(path, displayPath string, info fs.FileInfo) diag.Report {
	lower := strings.ToLower(info.Name())
	isYAML := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	isDockerfile := lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.")
	if !isYAML && !isDockerfile {
		return diag.Report{}
	}
	if info.Size() > maxFileSize {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file exceeds 5 MiB limit; skipped")}}
	}
	file, err := os.Open(path)
	if err != nil {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file could not be read: "+err.Error())}}
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file metadata could not be read: "+err.Error())}}
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file changed or became non-regular; skipped")}}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file could not be read: "+err.Error())}}
	}
	if len(data) > maxFileSize {
		return diag.Report{Diagnostics: []diag.ScanDiagnostic{scanDiagnostic(displayPath, "file exceeds 5 MiB limit; skipped")}}
	}
	if isDockerfile {
		return detect.Dockerfile(displayPath, data)
	}
	return detect.YAML(displayPath, data)
}

func appendReport(destination *diag.Report, source diag.Report) {
	destination.Findings = append(destination.Findings, source.Findings...)
	destination.Diagnostics = append(destination.Diagnostics, source.Diagnostics...)
}

func scanDiagnostic(path, message string) diag.ScanDiagnostic {
	return diag.ScanDiagnostic{Code: "DSD-006", Message: message, Path: path}
}

// Sort applies stable ordering to findings and scan diagnostics.
func Sort(result *diag.Report) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Stateful != b.Stateful {
			return a.Stateful
		}
		if diag.Rank(a.Severity) != diag.Rank(b.Severity) {
			return diag.Rank(a.Severity) < diag.Rank(b.Severity)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Reference < b.Reference
	})
	sort.SliceStable(result.Diagnostics, func(i, j int) bool {
		a, b := result.Diagnostics[i], result.Diagnostics[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Message < b.Message
	})
}
