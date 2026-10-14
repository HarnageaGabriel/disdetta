// Package imageref parses and redacts container image references without I/O.
package imageref

import (
	"strings"
	"unicode"
)

// Classification describes the detected namespace.
type Classification string

const (
	Other         Classification = "other"
	Bitnami       Classification = "bitnami"
	BitnamiLegacy Classification = "bitnamilegacy"
	BitnamiSecure Classification = "bitnamisecure"
	Unresolved    Classification = "unresolved"
)

// templatePlaceholder replaces each templated segment in redacted output
// (spec section 6). The ellipsis is U+2026.
const templatePlaceholder = "{{…}}"

// Reference is a normalized, safely printable image reference.
type Reference struct {
	Original, Registry, Repository, Tag, Digest string
	Classification                              Classification
	Templated                                   bool
	HasStaticEvidence                           bool
	Safe                                        string
	SafeOriginal                                string
}

// Parse parses a Docker-style image reference sufficiently for deterministic detection.
func Parse(value string) Reference {
	original := strings.TrimSpace(value)
	safeOriginal := redactTemplates(original)
	static, _ := stripTemplates(original)
	templated := static != original
	name := strings.TrimSpace(static)
	name = stripUserinfo(name)
	r := Reference{Original: original, Templated: templated, SafeOriginal: safeOriginal}
	if !templated && strings.HasPrefix(name, "/") {
		// An absolute filesystem path, not an image reference (spec section 9).
		// A templated prefix is different: the static remainder is what counts.
		r.Classification = Other
		return r
	}
	if at := strings.IndexByte(name, '@'); at >= 0 {
		r.Digest, name = name[at+1:], name[:at]
	}
	lastSlash := strings.LastIndexByte(name, '/')
	if colon := strings.LastIndexByte(name, ':'); colon > lastSlash {
		r.Tag, name = name[colon+1:], name[:colon]
	}
	name = strings.Trim(strings.TrimSpace(name), ":@/-")
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		r.Registry = normalizeRegistry(parts[0])
		r.Repository = strings.Join(parts[1:], "/")
	} else if name != "" {
		r.Registry = "docker.io"
		r.Repository = name
	}
	r.Repository = strings.TrimPrefix(r.Repository, "library/")
	r.Classification = classify(r.Repository)
	r.HasStaticEvidence = r.Classification != Other
	if templated && !r.HasStaticEvidence {
		r.Classification = Unresolved
	}
	r.Safe = render(r)
	if strings.Contains(original, "@") && strings.Contains(original[:strings.Index(original, "@")], ":") {
		r.SafeOriginal = strings.TrimPrefix(r.Safe, "docker.io/")
	}
	if containsUnsafe(r.SafeOriginal) {
		r.SafeOriginal = r.Safe
	}
	return r
}

// Join assembles split Helm registry/repository/tag fields before parsing.
func Join(registry, repository, tag string) Reference {
	v := strings.TrimSuffix(strings.TrimSpace(registry), "/")
	if v != "" {
		v += "/"
	}
	v += strings.TrimPrefix(strings.TrimSpace(repository), "/")
	if strings.TrimSpace(tag) != "" {
		v += ":" + strings.TrimSpace(tag)
	}
	return Parse(v)
}
func normalizeRegistry(v string) string {
	switch strings.ToLower(v) {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return strings.ToLower(v)
}
func classify(repo string) Classification {
	// The Bitnami namespace may appear as any path segment (spec section 2.1,
	// e.g. ghcr.io/acme/bitnami/redis), so every segment is inspected. Segments
	// are validated first: a filesystem path such as /opt/bitnami/postgresql is
	// not an image and stays Other.
	if !validImageRepository(repo) {
		return Other
	}
	found := Other
	for _, segment := range strings.Split(strings.ToLower(repo), "/") {
		switch segment {
		case "bitnamilegacy":
			return BitnamiLegacy
		case "bitnamisecure":
			found = BitnamiSecure
		case "bitnami":
			if found == Other {
				found = Bitnami
			}
		}
	}
	return found
}

// validImageRepository reports whether repo is shaped like a container image
// repository path: slash-separated, non-empty components of word characters and
// separators only. Filesystem paths, prose and shell fragments are rejected so
// the namespace scan above cannot fire on them (spec section 9).
func validImageRepository(repo string) bool {
	if repo == "" || strings.HasPrefix(repo, "/") || strings.HasSuffix(repo, "/") || strings.Contains(repo, "//") {
		return false
	}
	for _, segment := range strings.Split(repo, "/") {
		if segment == "" {
			return false
		}
		for i := 0; i < len(segment); i++ {
			c := segment[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '.', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}
func render(r Reference) string {
	if r.Registry == "" || r.Repository == "" {
		if r.Templated {
			return "{{…}}"
		}
		return ""
	}
	v := r.Registry + "/" + r.Repository
	if r.Templated {
		return v + templateSuffix(r.Original)
	}
	if r.Tag != "" {
		v += ":" + r.Tag
	}
	if r.Digest != "" {
		v += "@" + r.Digest
	}
	if containsUnsafe(v) {
		return r.Registry + "/" + r.Repository
	}
	return v
}
func templateSuffix(v string) string {
	start, _, ok := templateSegment(v, 0)
	if !ok {
		return ""
	}
	prefix := v[:start]
	sep := ""
	if strings.HasSuffix(prefix, ":") {
		sep = ":"
	} else if strings.HasSuffix(prefix, "@") {
		sep = "@"
	}
	_, count := stripTemplates(v)
	if count == 0 {
		return ""
	}
	return sep + strings.Repeat(templatePlaceholder, count)
}

// templateSegment returns the next template segment in s at or after from as a
// half-open byte range, and whether one was found. A {{ ... }} action is closed
// by its own }} so a }} inside a quoted string in the action body can never
// truncate the segment and leak the template tail (spec section 6).
func templateSegment(s string, from int) (int, int, bool) {
	for i := from; i < len(s); i++ {
		switch {
		case s[i] == '{' && i+1 < len(s) && s[i+1] == '{':
			if end, ok := templateActionEnd(s, i+2); ok {
				return i, end, true
			}
		case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
			if j := strings.IndexByte(s[i+2:], '}'); j >= 0 {
				return i, i + j + 3, true
			}
		case s[i] == '$':
			j := i + 1
			for j < len(s) && isTemplateNameByte(s[j]) {
				j++
			}
			if j > i+1 {
				return i, j, true
			}
		}
	}
	return 0, 0, false
}

// templateActionEnd returns the index just past the }} that closes an action
// whose body starts at from, skipping quoted string and raw string literals.
func templateActionEnd(s string, from int) (int, bool) {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '"', '`':
			quote := s[i]
			i++
			for i < len(s) && s[i] != quote {
				if quote == '"' && s[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(s) {
				return 0, false
			}
		case '}':
			if i+1 < len(s) && s[i+1] == '}' {
				return i + 2, true
			}
		}
	}
	return 0, false
}

// stripTemplates removes each template segment and reports how many were found.
func stripTemplates(s string) (string, int) {
	var b strings.Builder
	count := 0
	for i := 0; ; {
		start, end, ok := templateSegment(s, i)
		if !ok {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i:start])
		count++
		i = end
	}
	return b.String(), count
}

// redactTemplates replaces each template segment with templatePlaceholder.
func redactTemplates(s string) string {
	var b strings.Builder
	for i := 0; ; {
		start, end, ok := templateSegment(s, i)
		if !ok {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i:start])
		b.WriteString(templatePlaceholder)
		i = end
	}
	return b.String()
}

func isTemplateNameByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
func stripUserinfo(v string) string {
	if at := strings.LastIndexByte(v, '@'); at >= 0 {
		before := v[:at]
		if !strings.Contains(before, "/") || strings.Contains(before, ":") {
			return v[at+1:]
		}
	}
	return v
}
func containsUnsafe(v string) bool {
	for _, r := range v {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// Component returns the last repository path segment.
func (r Reference) Component() string {
	v := r.Repository
	if i := strings.LastIndexByte(v, '/'); i >= 0 {
		v = v[i+1:]
	}
	return strings.ToLower(strings.Trim(v, "-:/"))
}

// IsExcluded reports projects explicitly excluded by the contract.
func (r Reference) IsExcluded() bool {
	n := r.Component()
	return strings.HasPrefix(n, "sealed-secrets") || n == "minideb" || n == "charts-syncer"
}
