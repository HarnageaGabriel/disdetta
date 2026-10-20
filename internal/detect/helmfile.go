package detect

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"gopkg.in/yaml.v3"
)

// helmfileRepository is one entry of a Helmfile `repositories:` list.
type helmfileRepository struct {
	name         string
	url          string
	oci          bool
	urlLine      int
	urlColumn    int
	urlTemplated bool
}

// helmfileRelease is one release of a Helmfile that names a chart.
type helmfileRelease struct {
	alias     string
	chart     string
	component string
	line      int
	column    int
}

// helmfileFile is the state of one Helmfile file: the repositories and the
// releases of every document of the file. The YAML driver reports one
// document at a time, so the state of the whole file is kept here: a release
// resolves against a repository declared in any document of the file, whatever
// the order of the documents and of their entries (review finding 2).
type helmfileFile struct {
	path     string
	report   *diag.Report
	repos    map[string][]helmfileRepository
	declared []helmfileRepository
	releases []helmfileRelease
	used     map[string]bool
	resolved []bool
}

// helmfileCurrent is the state of the Helmfile file being scanned. The YAML
// driver creates one walk state per document and one report per file, so the
// state of the whole file is kept here and is replaced when another file is
// scanned. The repository scanner reads one file at a time, so the state
// never serves two files at once.
var helmfileCurrent *helmfileFile

// newHelmfileFile returns the state of a Helmfile file.
func newHelmfileFile(path string, report *diag.Report) *helmfileFile {
	return &helmfileFile{
		path:   path,
		report: report,
		repos:  map[string][]helmfileRepository{},
		used:   map[string]bool{},
	}
}

// helmfileFile returns the state of the Helmfile file being scanned.
func (s *walkState) helmfileFile() *helmfileFile {
	if helmfileCurrent == nil || helmfileCurrent.report != s.out || helmfileCurrent.path != s.path {
		helmfileCurrent = newHelmfileFile(s.path, s.out)
	}
	return helmfileCurrent
}

// isHelmfile reports whether path is a Helmfile source recognized by section 9.
func isHelmfile(path string) bool {
	path = strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	base := path[strings.LastIndexByte(path, '/')+1:]
	if base == "helmfile.yaml" || base == "helmfile.yml" || strings.HasSuffix(base, ".yaml.gotmpl") {
		return true
	}
	dir := path[:strings.LastIndexByte(path, '/')+1]
	return strings.HasSuffix(dir, "helmfile.d/") && strings.HasSuffix(base, ".yaml")
}

// scanHelmfile resolves Helmfile repository aliases and scans inline release
// values. The repositories and the releases of the whole file are resolved
// together, so the order of the documents and of their entries never changes
// the result (review finding 2).
func (s *walkState) scanHelmfile(root *yaml.Node) {
	file := s.helmfileFile()
	for _, entry := range sequenceAt(root, "repositories") {
		s.addHelmfileRepository(file, entry)
	}
	for _, release := range sequenceAt(root, "releases") {
		if chart := nodeAt(release, "chart"); chart != nil && chart.Kind == yaml.ScalarNode {
			file.addRelease(chart.Value, chart.Line, chart.Column)
		}
		s.scanHelmfileValues(nodeAt(release, "values"))
	}
	file.resolve(s)
}

// addHelmfileRepository records one `repositories:` entry of a YAML document.
func (s *walkState) addHelmfileRepository(file *helmfileFile, entry *yaml.Node) {
	urlNode := nodeAt(entry, "url")
	repository := helmfileRepository{
		name:         valueAt(entry, "name"),
		oci:          helmfileBool(valueAt(entry, "oci")),
		urlTemplated: urlNode != nil && helmfileTemplated(urlNode.Value),
	}
	if urlNode != nil && urlNode.Kind == yaml.ScalarNode {
		repository.url = urlNode.Value
		repository.urlLine = urlNode.Line
		repository.urlColumn = urlNode.Column
	}
	s.recordHelmfileRepository(file, repository)
}

// recordHelmfileRepository keeps one repository declaration. A name declared
// more than once keeps every declaration: the name is the Bitnami repository
// when any of its declarations is (review finding 3).
func (s *walkState) recordHelmfileRepository(file *helmfileFile, repository helmfileRepository) {
	file.declared = append(file.declared, repository)
	if repository.name == "" {
		return
	}
	file.repos[repository.name] = append(file.repos[repository.name], repository)
	if repository.urlTemplated {
		// A templated URL is not certain: it is never a finding.
		s.suppressHelmfileURL(repository)
		return
	}
	if file.used[repository.name] && isBitnamiHelmfileRepository(repository) {
		// The name is already used by a release: one dependency is one
		// finding, so this declaration adds no repository URL finding.
		s.suppressHelmfileURL(repository)
	}
}

// addRelease records one release that names a chart. A templated or local
// chart names no repository alias, so it is never a finding.
func (f *helmfileFile) addRelease(value string, line, column int) {
	value = strings.TrimSpace(value)
	if value == "" || helmfileTemplated(value) || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return
	}
	alias, chart, ok := strings.Cut(value, "/")
	if !ok || chart == "" {
		return
	}
	component := chart
	if i := strings.LastIndexByte(component, '/'); i >= 0 {
		component = component[i+1:]
	}
	f.releases = append(f.releases, helmfileRelease{
		alias:     alias,
		chart:     value,
		component: strings.ToLower(strings.Trim(component, "-:/")),
		line:      line,
		column:    column,
	})
	f.resolved = append(f.resolved, false)
}

// resolve reports one chart finding for every release whose repository alias
// is the Bitnami repository, and marks the alias as used. The alias must be
// declared in the same file: an include (`helmfiles:`, `bases:`) is not
// followed, so an alias declared in another file is never resolved (review
// finding 4).
func (f *helmfileFile) resolve(s *walkState) {
	for i := range f.releases {
		if f.resolved[i] {
			continue
		}
		release := f.releases[i]
		declarations := f.repos[release.alias]
		if len(declarations) == 0 {
			// The alias is not declared in this file. It may be declared in
			// an included file, which is not read, so the release stays
			// unresolved until the end of the file.
			continue
		}
		f.used[release.alias] = true
		repository, ok := bitnamiHelmfileDeclaration(declarations)
		if !ok {
			// The alias is known but is not the Bitnami repository. Another
			// document may declare the same name as Bitnami, so the release
			// stays unresolved until the end of the file.
			continue
		}
		f.resolved[i] = true
		s.addHelmfileChartFinding(release, repository)
		for _, declaration := range declarations {
			if !isBitnamiHelmfileRepository(declaration) {
				continue
			}
			// One dependency is one finding: a repository that a release
			// uses is not a finding of its own (review finding 1).
			s.suppressHelmfileURL(declaration)
			s.removeHelmfileURLFinding(declaration)
		}
	}
}

// bitnamiHelmfileDeclaration returns the declaration that points at the
// Bitnami chart repository. A name declared more than once is the Bitnami
// repository when any of its declarations is (review finding 3).
func bitnamiHelmfileDeclaration(declarations []helmfileRepository) (helmfileRepository, bool) {
	for _, declaration := range declarations {
		if isBitnamiHelmfileRepository(declaration) {
			return declaration, true
		}
	}
	return helmfileRepository{}, false
}

// addHelmfileChartFinding reports the chart of one release that resolves to
// the Bitnami chart repository.
func (s *walkState) addHelmfileChartFinding(release helmfileRelease, repository helmfileRepository) {
	s.out.Findings = append(s.out.Findings, diag.Finding{
		RuleID:     "DSD-CHT-001",
		Severity:   diag.SeverityMedium,
		Confidence: diag.ConfidenceConfirmed,
		Impact:     catalog.Impact(release.component),
		Component:  release.component,
		Location:   loc(s.path, release.line, release.column),
		Reference:  repository.url,
		Original:   release.chart,
		Attributes: []string{"chart"},
	})
}

func helmfileBool(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "true")
}

func helmfileTemplated(value string) bool {
	return strings.Contains(value, "{{") && strings.Contains(value, "}}")
}

func (s *walkState) suppressHelmfileURL(repository helmfileRepository) {
	if repository.urlLine == 0 {
		return
	}
	if s.suppressedHelmfileURLs == nil {
		s.suppressedHelmfileURLs = make(map[[2]int]bool)
	}
	s.suppressedHelmfileURLs[[2]int{repository.urlLine, repository.urlColumn}] = true
}

// removeHelmfileURLFinding drops the repository URL finding of a repository
// that a release uses: one dependency is one finding (review finding 1). The
// URL of a repository declared in an earlier document of the file was already
// reported, so the finding is removed from the report.
func (s *walkState) removeHelmfileURLFinding(repository helmfileRepository) {
	if repository.urlLine == 0 {
		return
	}
	kept := s.out.Findings[:0]
	for _, finding := range s.out.Findings {
		if finding.RuleID == "DSD-CHT-001" && finding.Location.Path == s.path &&
			finding.Location.Line == repository.urlLine && finding.Location.Column == repository.urlColumn {
			continue
		}
		kept = append(kept, finding)
	}
	s.out.Findings = kept
}

func (s *walkState) scanHelmfileValues(values *yaml.Node) {
	if values == nil {
		return
	}
	if values.Kind == yaml.AliasNode {
		values = values.Alias
	}
	switch {
	case values.Kind == yaml.MappingNode:
		s.scanImages(values, false)
	case values.Kind == yaml.SequenceNode:
		for _, entry := range values.Content {
			if entry.Kind == yaml.AliasNode {
				entry = entry.Alias
			}
			if entry != nil && entry.Kind == yaml.MappingNode {
				s.scanImages(entry, false)
			}
		}
	}
}

func isBitnamiHelmfileRepository(repository helmfileRepository) bool {
	if repository.urlTemplated {
		return false
	}
	url := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(repository.url)), "/")
	if repository.oci {
		url = strings.TrimPrefix(url, "oci://")
		return url == "registry-1.docker.io/bitnamicharts" || url == "docker.io/bitnamicharts"
	}
	return isBitnamiChartSource(repository.url)
}

// scanHelmfileTemplate applies the line-based Helmfile rules to gotmpl files
// (spec section 9.1). The whole file is read at once, so the repositories and
// the releases are resolved together whatever their order.
func (s *walkState) scanHelmfileTemplate(data []byte) {
	file := newHelmfileFile(s.path, s.out)
	current := helmfileRepository{}
	section := ""
	recordCurrent := func() {
		if current.name != "" || current.url != "" {
			s.recordHelmfileRepository(file, current)
		}
		current = helmfileRepository{}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), maxDockerfileLine)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := helmfileIndent(text)
		if indent == 0 {
			if section == "repositories" {
				recordCurrent()
			}
			key, _, ok := helmfileKey(trimmed)
			if !ok {
				section = ""
				continue
			}
			if key == "repositories" || key == "releases" {
				section = key
			} else {
				section = ""
			}
			continue
		}
		if section == "repositories" {
			if strings.HasPrefix(trimmed, "- ") {
				recordCurrent()
				trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			}
			if key, value, ok := helmfileKey(trimmed); ok {
				switch key {
				case "name":
					current.name = templateScalar(value)
				case "url":
					current.url = templateScalar(value)
					current.urlTemplated = helmfileTemplated(current.url)
					current.urlLine = line
					current.urlColumn = strings.Index(text, value) + 1
					if current.urlColumn < 1 {
						current.urlColumn = 1
					}
				case "oci":
					current.oci = helmfileBool(templateScalar(value))
				}
			}
		} else if section == "releases" {
			if key, value, ok := helmfileKey(trimmed); ok && key == "chart" {
				start := strings.Index(text, value)
				if start < 0 {
					start = 0
				}
				file.addRelease(templateScalar(value), line, start+1)
			}
		}
		s.scanHelmfileTemplateLine(text, line)
	}
	if section == "repositories" {
		recordCurrent()
	}
	file.resolve(s)
	// A repository that no release uses is a finding of its own.
	for _, repository := range file.declared {
		if repository.urlTemplated || file.used[repository.name] {
			continue
		}
		if url, ok := chartURLIn(repository.url); ok {
			s.out.Findings = append(s.out.Findings, diag.Finding{
				RuleID:     "DSD-CHT-001",
				Severity:   diag.SeverityMedium,
				Confidence: diag.ConfidenceConfirmed,
				Impact:     diag.ImpactUnknown,
				Location:   loc(s.path, repository.urlLine, repository.urlColumn),
				Reference:  url,
				Original:   url,
				Attributes: []string{"chart"},
			})
		}
	}
}

func (s *walkState) scanHelmfileTemplateLine(text string, line int) {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
	}
	if !strings.HasPrefix(trimmed, "image:") || !strings.Contains(trimmed, "{") || !strings.Contains(trimmed, "repository:") {
		return
	}
	payload := trimmed[len("image:"):]
	start := strings.Index(payload, "repository:")
	if start < 0 {
		return
	}
	value := strings.TrimSpace(payload[start+len("repository:"):])
	if end := strings.IndexAny(value, ",}"); end >= 0 {
		value = value[:end]
	}
	value = templateScalar(value)
	if value == "" {
		return
	}
	column := strings.Index(text, "repository:")
	if column < 0 {
		column = 0
	}
	s.addImage(value, line, column+len("repository:")+1, false)
}

func helmfileIndent(text string) int {
	indent := 0
	for _, r := range text {
		if r != ' ' && r != '\t' {
			break
		}
		indent++
	}
	return indent
}

func helmfileKey(text string) (string, string, bool) {
	if strings.HasPrefix(text, "- ") {
		text = strings.TrimSpace(strings.TrimPrefix(text, "- "))
	}
	i := strings.IndexByte(text, ':')
	if i <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(text[:i])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, strings.TrimSpace(text[i+1:]), true
}
