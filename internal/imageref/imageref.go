// Package imageref parses and redacts container image references without I/O.
package imageref

import (
	"regexp"
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

var templatePattern = regexp.MustCompile(`\{\{[\s\S]*?\}\}|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

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
	safeOriginal := templatePattern.ReplaceAllString(original, "{{…}}")
	static := templatePattern.ReplaceAllString(original, "")
	templated := static != original
	name := strings.TrimSpace(static)
	name = stripUserinfo(name)
	r := Reference{Original: original, Templated: templated, SafeOriginal: safeOriginal}
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
	first, _, _ := strings.Cut(strings.ToLower(repo), "/")
	switch first {
	case "bitnami":
		return Bitnami
	case "bitnamilegacy":
		return BitnamiLegacy
	case "bitnamisecure":
		return BitnamiSecure
	}
	return Other
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
	idx := templatePattern.FindStringIndex(v)
	if idx == nil {
		return ""
	}
	prefix := v[:idx[0]]
	sep := ""
	if strings.HasSuffix(prefix, ":") {
		sep = ":"
	} else if strings.HasSuffix(prefix, "@") {
		sep = "@"
	}
	return sep + strings.Join(make([]string, len(templatePattern.FindAllString(v, -1))), "{{…}}") + "{{…}}"
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
