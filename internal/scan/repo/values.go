package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
)

// valuesPlan is one values file resolved for a chart, scanned as chart values
// (spec section 9.2).
type valuesPlan struct {
	path    string // absolute path on disk
	display string // slash-separated path relative to the scan root
}

// valuesStatus is the outcome of resolving one valuesFile reference.
type valuesStatus int

const (
	valuesOK valuesStatus = iota
	valuesMissing
	valuesOutside
	valuesSymlink
	valuesNotRegular
	valuesLinkedParent
)

// planValuesFiles resolves the valuesFile references the scanned documents
// declare (spec section 9.2). It returns the walked files the resolved values
// files claim, so a file that is both a values file and a walked file is
// scanned once, the plans to scan, and the diagnostics of the references that
// could not be resolved.
func planValuesFiles(root string, entries []repositoryEntry, exclude []string) (map[string]bool, []valuesPlan, diag.Report) {
	claimed := map[string]bool{}
	regular := map[string]repositoryEntry{}
	for _, entry := range entries {
		if entry.problem == 0 {
			regular[pathKey(entry.path)] = entry
		}
	}
	var plans []valuesPlan
	var out diag.Report
	planned := map[string]bool{}
	for _, entry := range entries {
		if entry.problem != 0 || !declaresValuesFile(entry.path) {
			continue
		}
		// The file is read once more to look for the references it declares:
		// the walk reads it again to scan it, and only the files that hold a
		// valuesFile key are parsed a second time.
		data, err := readRegularFile(entry.path, entry.info)
		if err != nil {
			continue // the regular scan reports the read error
		}
		if !containsFold(data, valuesFileNeedle) {
			continue // the file declares no values file, so it is not parsed
		}
		refs := detect.ValuesFileRefs(entry.path, data)
		for _, ref := range refs.All() {
			resolved, info, status := resolveValuesFile(root, filepath.Dir(entry.path), ref)
			switch status {
			case valuesMissing:
				out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, entry.display, fmt.Sprintf("values file %q not found", ref)))
				continue
			case valuesOutside:
				out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, entry.display, fmt.Sprintf("values file %q is outside the scan root", ref)))
				continue
			case valuesSymlink, valuesNotRegular, valuesLinkedParent:
				// A declared reference that cannot be read is a missing
				// reference: the scan is incomplete (spec section 9.2).
				out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, entry.display, fmt.Sprintf("values file %q could not be read: %s", ref, valuesRefusalMessage(status))))
				continue
			}
			key, walked := walkedKey(regular, resolved, info)
			if planned[key] {
				continue // the same values file is scanned once
			}
			planned[key] = true
			display := displayPath(root, resolved)
			if len(exclude) != 0 && excluded(display, exclude) {
				continue // an excluded file is neither scanned nor skipped
			}
			plans = append(plans, valuesPlan{path: resolved, display: display})
			if walked {
				claimed[key] = true
			}
		}
	}
	return claimed, plans, out
}

// declaresValuesFile reports whether a file can declare a valuesFile: a
// Kustomization file, or any YAML file, which may hold a
// HelmChartInflationGenerator (spec section 9.2).
func declaresValuesFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		return true
	}
	// Only the extensionless Kustomization file is left: the other two names
	// kustomize accepts end in .yaml or .yml.
	base := filepath.Base(path)
	return len(base) == len("kustomization") && detect.IsKustomizationFile(path)
}

// valuesFileNeedle is the key a document declares its values file with. The
// detector looks for the same key, ignoring case.
var valuesFileNeedle = []byte("valuesfile")

// containsFold reports whether data holds needle, ignoring case. It never
// allocates, so the values pre-pass can look for the key in every file it
// reads, before it parses the file.
func containsFold(data, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(data) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		if bytes.EqualFold(data[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// resolveValuesFile resolves a valuesFile reference relative to the directory
// of the file that declares it and checks that the result stays inside the
// scan root (spec section 9.2): an absolute path, an escape with "..", a path
// that reaches a symbolic link or another link (a Windows junction), and a
// path that leaves the root once every link is resolved are refused.
func resolveValuesFile(root, dir, ref string) (string, fs.FileInfo, valuesStatus) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil, valuesMissing
	}
	if filepath.IsAbs(ref) {
		return "", nil, valuesOutside
	}
	resolved := filepath.Clean(filepath.Join(dir, ref))
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", nil, valuesOutside
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", nil, valuesMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return resolved, info, valuesSymlink
	}
	if !info.Mode().IsRegular() {
		return resolved, info, valuesNotRegular
	}
	if !plainAncestors(root, resolved) {
		return resolved, info, valuesLinkedParent
	}
	if !contained(root, resolved) {
		return resolved, info, valuesOutside
	}
	return resolved, info, valuesOK
}

// walkedKey returns the key of the walked file that holds a resolved values
// file: the same path, or the same file under another name, as a case
// difference on a case-insensitive filesystem. The file is then claimed, so it
// is scanned once.
func walkedKey(regular map[string]repositoryEntry, resolved string, info fs.FileInfo) (string, bool) {
	key := pathKey(resolved)
	if _, ok := regular[key]; ok {
		return key, true
	}
	for k, entry := range regular {
		if entry.info != nil && info != nil && os.SameFile(entry.info, info) {
			return k, true
		}
	}
	return key, false
}

// plainAncestors reports whether every directory between the root and the
// file is a plain directory. A symbolic link, a Windows junction or another
// reparse point is not a plain directory: it is never followed, so a values
// file below one is outside the scan root (spec section 9.2).
func plainAncestors(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 {
		return false
	}
	current := root
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return false
		}
	}
	return true
}

// contained reports whether the path stays inside the root once every link is
// resolved: the root and the path are resolved with filepath.EvalSymlinks and
// the resolved path must stay inside the resolved root (spec section 9.2).
func contained(root, path string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = root
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// valuesRefusalMessage names why a declared values file could not be read.
func valuesRefusalMessage(status valuesStatus) string {
	switch status {
	case valuesSymlink:
		return "it is a symbolic link"
	case valuesNotRegular:
		return "it is not a regular file"
	case valuesLinkedParent:
		return "it is reached through a symbolic link or a junction"
	default:
		return "it could not be read"
	}
}

// scanValuesFile scans one resolved values file as chart values (spec section
// 9.2).
func scanValuesFile(plan valuesPlan) diag.Report {
	var out diag.Report
	info, err := os.Lstat(plan.path)
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, plan.display, "values file could not be read"))
		return out
	}
	if info.Mode()&os.ModeSymlink != 0 {
		out.Summary.FilesSkipped++
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, plan.display, "symbolic link skipped"))
		return out
	}
	if !info.Mode().IsRegular() {
		out.Summary.FilesSkipped++
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, plan.display, "non-regular file skipped"))
		return out
	}
	data, err := readRegularFile(plan.path, info)
	if errors.Is(err, ErrFileTooLarge) {
		out.Summary.FilesSkipped++
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-008", diag.LevelError, plan.display, "file exceeds 16 MiB limit; skipped"))
		return out
	}
	if errors.Is(err, ErrUnsafeFile) {
		out.Summary.FilesSkipped++
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-002", diag.LevelWarning, plan.display, "file changed or became non-regular; skipped"))
		return out
	}
	if err != nil {
		out.Diagnostics = append(out.Diagnostics, scanDiagnostic("DSD-SCN-004", diag.LevelError, plan.display, "values file could not be read"))
		return out
	}
	detected := detect.HelmValues(plan.display, data)
	if detect.HasTemplateMarkers(data) && detect.Malformed(detected) {
		detected = detect.Template(plan.display, data)
	}
	detected.Summary.FilesScanned = 1
	return detected
}

// displayPath returns the slash-separated path of a file relative to the scan
// root.
func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return filepath.Base(path)
	}
	return filepath.ToSlash(rel)
}

// pathKey normalizes a path for comparison: cleaned, and case-folded where the
// filesystem is case-insensitive, so the same file is never scanned twice.
func pathKey(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(cleaned)
	}
	return cleaned
}
