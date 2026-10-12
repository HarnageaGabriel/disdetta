// Package repo walks a repository and dispatches files to pure detectors.
package repo

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

var skippedDirectories = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// Scan walks root without changing it and returns deterministically sorted findings.
func Scan(ctx context.Context, root string) ([]diag.Diagnostic, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", root, err)
	}
	if !info.IsDir() {
		return scanFile(root, filepath.Base(root), root)
	}
	var findings []diag.Diagnostic
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
		found, err := scanFile(path, filepath.ToSlash(relative), entry.Name())
		if err != nil {
			return err
		}
		findings = append(findings, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	Sort(findings)
	return findings, nil
}

func scanFile(path, displayPath, name string) ([]diag.Diagnostic, error) {
	lower := strings.ToLower(name)
	isYAML := strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	isDockerfile := lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.")
	if !isYAML && !isDockerfile {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if isDockerfile {
		return detect.Dockerfile(displayPath, data), nil
	}
	return detect.YAML(displayPath, data)
}

// Sort applies the stable stateful, severity, path and line ordering.
func Sort(findings []diag.Diagnostic) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
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
}
