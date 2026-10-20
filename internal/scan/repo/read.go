package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
)

var (
	ErrFileTooLarge = errors.New("file exceeds 16 MiB limit")
	ErrUnsafeFile   = errors.New("file is symbolic, non-regular, or changed while reading")
)

type walkProblem uint8

const (
	walkPathUnreadable walkProblem = iota + 1
	walkSymlink
	walkMetadataUnreadable
	walkNonRegular
)

type repositoryEntry struct {
	path, display string
	info          fs.FileInfo
	problem       walkProblem
}

func walkRepository(ctx context.Context, root string, visit func(repositoryEntry) error) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if path == root {
				return walkErr
			}
			display := filepath.ToSlash(path)
			if rel, err := filepath.Rel(root, path); err == nil {
				display = filepath.ToSlash(rel)
			}
			return visit(repositoryEntry{path: path, display: display, problem: walkPathUnreadable})
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
		// The detectors read only a few kinds of file. A regular file with
		// another name cannot change the report, so it is dropped before the
		// metadata lookup and before the relative path is built. The entries
		// that are not regular keep their diagnostics: a link and a device are
		// still reported as skipped.
		if entry.Type().IsRegular() && !scannableName(strings.ToLower(filepath.Base(path)), path) {
			return nil
		}
		display := filepath.Base(path)
		if rel, err := filepath.Rel(root, path); err == nil && rel != "." {
			display = filepath.ToSlash(rel)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return visit(repositoryEntry{path: path, display: display, problem: walkSymlink})
		}
		info, err := entry.Info()
		if err != nil {
			return visit(repositoryEntry{path: path, display: display, problem: walkMetadataUnreadable})
		}
		if !info.Mode().IsRegular() {
			return visit(repositoryEntry{path: path, display: display, info: info, problem: walkNonRegular})
		}
		return visit(repositoryEntry{path: path, display: display, info: info})
	})
}

// scannableName reports whether a file whose lower-cased base name is
// lowerBase can be consumed by one of the repository detectors. It looks at
// the name only, so the walk can decide before it looks at the metadata of
// the file.
//
// The names are the ones scanFile reads: a file that is not scannable here is
// not read by the scan either, so dropping it in the walk leaves the report
// unchanged. The Kustomization flag of scanFile only makes a file scannable
// when the file is the extensionless Kustomization: the other two names
// kustomize accepts end in .yaml or .yml and are already covered.
func scannableName(lowerBase, path string) bool {
	if lowerBase == ".disdetta.yaml" {
		return false
	}
	if strings.HasSuffix(lowerBase, ".yaml") || strings.HasSuffix(lowerBase, ".yml") {
		return true
	}
	if lowerBase == "dockerfile" || strings.HasPrefix(lowerBase, "dockerfile.") || strings.HasSuffix(lowerBase, ".dockerfile") {
		return true
	}
	if strings.HasSuffix(lowerBase, ".tpl") || strings.HasSuffix(lowerBase, ".yaml.gotmpl") || strings.HasSuffix(lowerBase, ".tf") {
		return true
	}
	return len(lowerBase) == len("kustomization") && detect.IsKustomizationFile(path)
}

// ReadFile performs the bounded, regular-file-only read used by repository
// scanning and plan input collection.
func ReadFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return readRegularFile(path, info)
}

func readRegularFile(path string, expected fs.FileInfo) (data []byte, err error) {
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return nil, ErrUnsafeFile
	}
	if expected.Size() > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, ErrUnsafeFile
	}
	data, err = io.ReadAll(io.LimitReader(file, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, ErrFileTooLarge
	}
	return data, nil
}

// ReadYAMLFiles walks the same skipped directories and enforces the same file
// safety rules as repository scanning. YAML symlinks and non-regular files are
// refused because silently omitting a release would make a plan incomplete.
func ReadYAMLFiles(ctx context.Context, root string) (map[string][]byte, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("repository root: %w", ErrUnsafeFile)
	}
	files := map[string][]byte{}
	err = walkRepository(ctx, root, func(entry repositoryEntry) error {
		ext := strings.ToLower(filepath.Ext(entry.path))
		if ext != ".yaml" && ext != ".yml" {
			if entry.problem == walkPathUnreadable {
				return fmt.Errorf("repository path could not be read")
			}
			return nil
		}
		if entry.problem != 0 {
			return fmt.Errorf("read %s: %w", entry.path, ErrUnsafeFile)
		}
		data, err := readRegularFile(entry.path, entry.info)
		if err != nil {
			return fmt.Errorf("read %s: %w", entry.path, err)
		}
		files[entry.path] = data
		return nil
	})
	return files, err
}
