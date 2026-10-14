// Package imageref parses and classifies container image references without I/O.
package imageref

import (
	"strings"
	"unicode"
)

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
	Redacted       bool
}

// Parse parses a Docker-style image reference sufficiently for deterministic detection.
func Parse(value string) Reference {
	original := strings.TrimSpace(value)
	r := Reference{Original: original}
	if strings.Contains(original, "{{") || strings.Contains(original, "}}") {
		prefix := original
		if index := strings.Index(prefix, "{{"); index >= 0 {
			prefix = prefix[:index]
		}
		prefix = strings.TrimRight(strings.TrimSpace(prefix), ":@/-")
		if prefix != "" {
			parsed := Parse(prefix)
			r.Registry, r.Repository = parsed.Registry, parsed.Repository
		}
		r.Classification = Unresolved
		r.Redacted = true
		return r
	}
	name := original
	if at, slash := strings.IndexByte(name, '@'), strings.IndexByte(name, '/'); at >= 0 && (slash < 0 || at < slash) {
		name = name[at+1:]
		r.Redacted = true
	}
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
	if !validTag(r.Tag) || !validDigest(r.Digest) || looksCredential(r.Tag) || looksCredential(r.Digest) || containsUnsafe(r.Registry) || containsUnsafe(r.Repository) {
		r.Redacted = true
	}
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
		if r.Registry != "" && r.Repository != "" && !containsUnsafe(r.Registry) && !containsUnsafe(r.Repository) {
			return r.Registry + "/" + r.Repository
		}
		return "<unresolved>"
	}
	value := r.Registry + "/" + r.Repository
	if r.Redacted {
		registry, repository := safeName(r.Registry), safeName(r.Repository)
		if registry == "" || repository == "" {
			return "<redacted>"
		}
		return registry + "/" + repository
	}
	if r.Tag != "" {
		value += ":" + r.Tag
	}
	if r.Digest != "" {
		value += "@" + r.Digest
	}
	return value
}

func validTag(tag string) bool {
	if tag == "" {
		return true
	}
	if len(tag) > 128 {
		return false
	}
	for i, r := range tag {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && (i <= 0 || (r != '.' && r != '-')) {
			return false
		}
	}
	return true
}

func validDigest(digest string) bool {
	if digest == "" {
		return true
	}
	algorithm, encoded, ok := strings.Cut(digest, ":")
	if !ok || algorithm == "" || encoded == "" {
		return false
	}
	for _, r := range algorithm {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("+._-", r) {
			return false
		}
	}
	for _, r := range encoded {
		if !unicode.IsDigit(r) && (unicode.ToLower(r) < 'a' || unicode.ToLower(r) > 'f') {
			return false
		}
	}
	return true
}

func looksCredential(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "credential", "bearer"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return len(value) >= 32 && !strings.HasPrefix(lower, "sha")
}

func containsUnsafe(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '@' {
			return true
		}
	}
	return false
}

func safeName(value string) string {
	for index, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("._:/-", r) {
			return strings.TrimRight(value[:index], "._:/-")
		}
	}
	return value
}
