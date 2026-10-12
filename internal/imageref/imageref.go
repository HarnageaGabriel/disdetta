// Package imageref parses and classifies container image references without I/O.
package imageref

import "strings"

// Classification describes ownership inferred from the repository path.
type Classification string

const (
	Other         Classification = "other"
	Bitnami       Classification = "bitnami"
	BitnamiLegacy Classification = "bitnamilegacy"
	BitnamiSecure Classification = "bitnamisecure"
	Unresolved    Classification = "unresolved"
)

// Reference is a normalized image reference.
type Reference struct {
	Original       string
	Registry       string
	Repository     string
	Tag            string
	Digest         string
	Classification Classification
}

// Parse parses a Docker-style image reference sufficiently for deterministic detection.
func Parse(value string) Reference {
	original := strings.TrimSpace(value)
	r := Reference{Original: original}
	if strings.Contains(original, "{{") || strings.Contains(original, "}}") {
		r.Classification = Unresolved
		return r
	}
	name := original
	if at := strings.IndexByte(name, '@'); at >= 0 {
		r.Digest, name = name[at+1:], name[:at]
	}
	lastSlash := strings.LastIndexByte(name, '/')
	if colon := strings.LastIndexByte(name, ':'); colon > lastSlash {
		r.Tag, name = name[colon+1:], name[:colon]
	}
	parts := strings.Split(name, "/")
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		r.Registry, r.Repository = parts[0], strings.Join(parts[1:], "/")
	} else {
		r.Registry, r.Repository = "docker.io", name
	}
	r.Registry = normalizeRegistry(r.Registry)
	r.Repository = strings.TrimPrefix(r.Repository, "library/")
	r.Classification = classifyRepository(r.Repository)
	return r
}

// Join assembles split Helm registry/repository/tag fields before parsing.
func Join(registry, repository, tag string) Reference {
	value := strings.TrimSuffix(strings.TrimSpace(registry), "/")
	if value != "" {
		value += "/"
	}
	value += strings.TrimPrefix(strings.TrimSpace(repository), "/")
	if strings.TrimSpace(tag) != "" {
		value += ":" + strings.TrimSpace(tag)
	}
	return Parse(value)
}

func normalizeRegistry(registry string) string {
	switch strings.ToLower(registry) {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	default:
		return strings.ToLower(registry)
	}
}

func classifyRepository(repository string) Classification {
	first, _, _ := strings.Cut(strings.ToLower(repository), "/")
	switch first {
	case "bitnami":
		return Bitnami
	case "bitnamilegacy":
		return BitnamiLegacy
	case "bitnamisecure":
		return BitnamiSecure
	default:
		return Other
	}
}

// String returns a normalized reference while preserving tag and digest.
func (r Reference) String() string {
	if r.Classification == Unresolved {
		return r.Original
	}
	value := r.Registry + "/" + r.Repository
	if r.Tag != "" {
		value += ":" + r.Tag
	}
	if r.Digest != "" {
		value += "@" + r.Digest
	}
	return value
}
