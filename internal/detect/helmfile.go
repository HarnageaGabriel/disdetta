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
// the order of the documents and of their entries (review finding 2). The
// state belongs to one scan of one file and is carried by the walk state, so
// two scans never share it.
type helmfileFile struct {
	repos    map[string][]helmfileRepository
	releases []helmfileRelease
	used     map[string]bool
	resolved []bool
}

// newHelmfileFile returns the state of a Helmfile file.
func newHelmfileFile() *helmfileFile {
	return &helmfileFile{
		repos: map[string][]helmfileRepository{},
		used:  map[string]bool{},
	}
}

// helmfileFile returns the state of the Helmfile file being scanned.
func (s *walkState) helmfileFile() *helmfileFile {
	if s.helmfile == nil {
		s.helmfile = newHelmfileFile()
	}
	return s.helmfile
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
			s.addHelmfileRelease(file, chart.Value, chart.Line, chart.Column)
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
	if repository.name != "" {
		file.repos[repository.name] = append(file.repos[repository.name], repository)
	}
	if repository.urlTemplated {
		// A templated URL is not certain: it is never a finding.
		s.suppressHelmfileURL(repository)
		return
	}
	if !isBitnamiHelmfileRepository(repository) {
		return
	}
	if file.used[repository.name] {
		// The name is already used by a release: one dependency is one
		// finding, so this declaration adds no repository URL finding.
		s.suppressHelmfileURL(repository)
		return
	}
	// A Bitnami repository that no release uses is a finding of its own, on
	// its url entry. A release of the file that uses the alias drops it
	// (one dependency is one finding).
	s.addHelmfileRepositoryFinding(repository)
	s.suppressHelmfileURL(repository)
}

// addHelmfileRepositoryFinding reports the URL of a Bitnami repository: the
// `oci://` form and the bare registry form of the OCI repository are both
// Bitnami repositories (spec section 9).
func (s *walkState) addHelmfileRepositoryFinding(repository helmfileRepository) {
	if repository.urlLine == 0 || repository.urlTemplated {
		return
	}
	if !isBitnamiHelmfileRepository(repository) {
		return
	}
	url := strings.TrimSpace(repository.url)
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

// addHelmfileRelease records one release that names a chart. A direct OCI
// reference to the Bitnami chart repository names no repository alias: it is
// a finding of its own. A templated or local chart names no repository alias
// either, so it is never a finding.
func (s *walkState) addHelmfileRelease(file *helmfileFile, value string, line, column int) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if reference, component, templated, ok := bitnamiHelmfileOCIChart(value); ok {
		// The whole-scalar fallback must not report the static part of
		// the reference a second time.
		s.suppressHelmfileScalar(line, column)
		s.addHelmfileOCIChartFinding(value, reference, component, templated, line, column)
		return
	}
	if helmfileTemplated(value) {
		return
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
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
	file.releases = append(file.releases, helmfileRelease{
		alias:     alias,
		chart:     value,
		component: strings.ToLower(strings.Trim(component, "-:/")),
		line:      line,
		column:    column,
	})
	file.resolved = append(file.resolved, false)
}

// bitnamiHelmfileOCIChart reports whether a chart value names the Bitnami OCI
// chart repository directly, and returns the static reference, the chart
// component and whether the reference is templated. The component is the last
// path segment of the reference: a templated chart name has no component.
func bitnamiHelmfileOCIChart(value string) (reference, component string, templated, ok bool) {
	rest, found := strings.CutPrefix(strings.ToLower(value), "oci://")
	if !found {
		return "", "", false, false
	}
	registry, path, found := strings.Cut(rest, "/")
	if !found {
		return "", "", false, false
	}
	if registry != "registry-1.docker.io" && registry != "docker.io" {
		return "", "", false, false
	}
	chart, found := strings.CutPrefix(path, "bitnamicharts/")
	if !found || chart == "" {
		return "", "", false, false
	}
	name := chart
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Trim(name, "-:/")
	reference = "oci://" + registry + "/bitnamicharts"
	if helmfileTemplated(value) {
		// The repository is certain, the chart may not be.
		if helmfileTemplated(name) {
			name = ""
		}
		return reference, name, true, true
	}
	if name == "" {
		return "", "", false, false
	}
	return reference, name, false, true
}

// addHelmfileOCIChartFinding reports a chart that names the Bitnami OCI chart
// repository directly, without a repository alias. A templated chart name
// keeps the static reference but is never certain.
func (s *walkState) addHelmfileOCIChartFinding(value, reference, component string, templated bool, line, column int) {
	confidence := diag.ConfidenceConfirmed
	impact := catalog.Impact(component)
	original := value
	if templated {
		confidence = diag.ConfidenceUnresolved
		impact = diag.ImpactUnknown
		original = reference
	}
	s.out.Findings = append(s.out.Findings, diag.Finding{
		RuleID:     "DSD-CHT-001",
		Severity:   diag.SeverityMedium,
		Confidence: confidence,
		Impact:     impact,
		Component:  component,
		Location:   loc(s.path, line, column),
		Reference:  reference,
		Original:   original,
		Attributes: []string{"chart"},
	})
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
	s.suppressHelmfileScalar(repository.urlLine, repository.urlColumn)
}

// suppressHelmfileScalar stops the whole-scalar fallback from reporting a
// chart repository URL at a position: the Helmfile detector reports it, with
// the Helmfile rules (spec section 9).
func (s *walkState) suppressHelmfileScalar(line, column int) {
	if s.suppressedHelmfileURLs == nil {
		s.suppressedHelmfileURLs = make(map[[2]int]bool)
	}
	s.suppressedHelmfileURLs[[2]int{line, column}] = true
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
	switch values.Kind {
	case yaml.MappingNode:
		s.scanImages(values, false)
	case yaml.SequenceNode:
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
	file := s.helmfileFile()
	current := helmfileRepository{}
	section := ""
	item := helmfileItem{}
	item.reset()
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
		if indent == 0 && !strings.HasPrefix(trimmed, "- ") {
			// A top-level key or a template action.
			if isHelmfileTemplateAction(trimmed) {
				// A pure template action is not a key: the section of the
				// file stays (review finding 4).
				continue
			}
			if section == "repositories" {
				recordCurrent()
			}
			key, _, ok := helmfileKey(trimmed)
			if !ok {
				section = ""
				item.reset()
				continue
			}
			if key == "repositories" || key == "releases" {
				section = key
			} else {
				section = ""
			}
			item.reset()
			continue
		}
		key, value, _ := helmfileKey(trimmed)
		newItem := false
		property := false
		if strings.HasPrefix(trimmed, "- ") {
			// A list item: a column-0 item is an entry of the current
			// section, not a top-level key (review finding 4).
			newItem = item.start(indent)
			property = newItem
		} else {
			property = item.property(indent)
		}
		switch section {
		case "repositories":
			if newItem {
				recordCurrent()
			}
			if !property {
				break
			}
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
		case "releases":
			if !property || key != "chart" {
				break
			}
			start := strings.Index(text, value)
			if start < 0 {
				start = 0
			}
			s.addHelmfileRelease(file, templateScalar(value), line, start+1)
		}
		s.scanHelmfileTemplateLine(text, line)
	}
	if section == "repositories" {
		recordCurrent()
	}
	file.resolve(s)
}

// helmfileItem is the list item a Helmfile section is in: the indent of the
// item and the indent of its properties. A key is a property of the item only
// at the property indent, so a key nested in the item is never a property of
// the item (review finding 5).
type helmfileItem struct {
	indent int
	prop   int
}

// reset forgets the current item.
func (i *helmfileItem) reset() {
	i.indent = -1
	i.prop = -1
}

// start records a list item at the given indent. It reports whether the line
// starts a new item: a deeper item is nested in the current one.
func (i *helmfileItem) start(indent int) bool {
	if i.indent >= 0 && indent > i.indent {
		return false
	}
	i.indent = indent
	i.prop = -1
	return true
}

// property reports whether a key at the given indent is a property of the
// current item. The property indent is the indent of the first property line
// of the item.
func (i *helmfileItem) property(indent int) bool {
	if i.indent < 0 || indent <= i.indent {
		return false
	}
	if i.prop < 0 {
		i.prop = indent
	}
	return indent == i.prop
}

// isHelmfileTemplateAction reports whether a line holds only a Go template
// action. Such a line is not a YAML key: it never ends the section of a
// Helmfile (review finding 4).
func isHelmfileTemplateAction(trimmed string) bool {
	return strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}")
}

func (s *walkState) scanHelmfileTemplateLine(text string, line int) {
	trimmed := strings.TrimSpace(text)
	indent := helmfileIndent(text)
	offset := indent
	if strings.HasPrefix(trimmed, "- ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		offset = indent + 1 + helmfileIndent(text[indent+1:])
	}
	if !strings.HasPrefix(trimmed, "image:") || !strings.Contains(trimmed, "{") || !strings.Contains(trimmed, "repository:") {
		return
	}
	payload := trimmed[len("image:"):]
	start := strings.Index(payload, "repository:")
	if start < 0 {
		return
	}
	rest := payload[start+len("repository:"):]
	skip := len(rest) - len(strings.TrimLeft(rest, " \t"))
	raw := strings.TrimRight(rest[skip:], " \t")
	if end := strings.IndexAny(raw, ",}"); end >= 0 {
		raw = raw[:end]
	}
	raw = strings.TrimRight(raw, " \t")
	value := templateScalar(raw)
	if value == "" {
		return
	}
	// The column is the first character of the value, as the YAML driver
	// reports it (review finding 6).
	column := offset + len("image:") + start + len("repository:") + skip + 1
	s.addImage(value, line, column, false)
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
