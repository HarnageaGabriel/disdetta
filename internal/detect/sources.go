package detect

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/catalog"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
	"gopkg.in/yaml.v3"
)

const maxAliasNodes = 10000

func (s *walkState) scanDocument(root *yaml.Node) {
	kind := strings.ToLower(valueAt(root, "kind"))
	base := strings.ToLower(filepath.Base(s.path))
	if base != "input.yaml" && base != "input.yml" {
		s.scanConfig(root)
	}
	switch {
	case base == "chart.yaml":
		s.scanCharts(root)
	case kind == "helmrepository" || kind == "ocirepository":
		s.addChartAt(nodeAt(root, "spec", "url"), "")
	case kind == "helmrelease":
		chart := valueAt(root, "spec", "chart", "spec", "chart")
		before := len(s.out.Findings)
		s.scanImages(nodeAt(root, "spec", "values"), false)
		if chart != "" {
			for i := before; i < len(s.out.Findings); i++ {
				s.out.Findings[i].Impact = catalog.Impact(chart)
			}
		}
	case kind == "helmchartinflationgenerator":
		s.scanHelmChartGenerator(root)
	case kind == "application":
		s.scanArgo(nodeAt(root, "spec"))
	case kind == "applicationset":
		s.scanArgo(nodeAt(root, "spec", "template", "spec"))
	case isKubernetesKind(kind):
		s.scanPodSpecs(root, kind)
	case isKustomizationBase(base):
		s.scanKustomize(root)
	case isCompose(base):
		s.scanCompose(root)
	case isActions(s.path):
		s.scanActions(root)
	case isGitLab(base):
		s.scanGitLab(root)
	case isAzure(base):
		s.scanAzure(root)
	case base == "input.yaml" || base == "input.yml":
		s.walk(root, 0, 0, false)
	case strings.Contains(base, "values"):
		s.scanImages(root, false)
	}
	// Shell commands are scanned only in the CI sources named by spec 9.2.
	// Their script scalars are marked, so the whole-scalar fallback does not
	// report prose or echo arguments that the shell tokenizer must ignore.
	// Any other scalar of the same file still falls back (spec section 9).
	s.scanShellScripts(root)
	// Whole-scalar fallback (spec section 9): unknown-key image scalars and
	// Bitnami chart repository URLs inside any scalar, in any file. A scalar a
	// specific detector already reported is not reported again.
	before := len(s.out.Findings)
	s.scanFallbacks(root)
	s.dropDuplicateFallbacks(before)
	// An anchor and its alias uses are one logical reference, reported once at
	// the anchor (spec section 5).
	s.out.Findings = diag.DedupeFindings(s.out.Findings)
}

func (s *walkState) scanCharts(root *yaml.Node) {
	for _, dep := range sequenceAt(root, "dependencies") {
		s.addChartAt(nodeAt(dep, "repository"), valueAt(dep, "name"))
	}
	s.scanVendoredChart(root)
}

// scanVendoredChart reports one DSD-CHT-002 for a Chart.yaml that vendors the
// Bitnami chart: sources/home point at github.com/bitnami/charts, or the
// annotations.images list names Bitnami images (spec section 2.1).
func (s *walkState) scanVendoredChart(root *yaml.Node) {
	component := valueAt(root, "name")
	confidence := diag.ConfidenceConfirmed
	var evidence *yaml.Node
	reference := ""
	for _, src := range sequenceAt(root, "sources") {
		if src.Kind == yaml.ScalarNode && isBitnamiChartsURL(src.Value) {
			evidence = src
			break
		}
	}
	if evidence == nil {
		if home := nodeAt(root, "home"); home != nil && home.Kind == yaml.ScalarNode && isBitnamiChartsURL(home.Value) {
			evidence = home
		}
	}
	attrs := []string{"chart"}
	if evidence != nil {
		reference = strings.TrimSpace(evidence.Value)
	} else {
		var r imageref.Reference
		evidence, r, confidence = bitnamiAnnotationImage(nodeAt(root, "annotations", "images"))
		if evidence != nil {
			reference = r.Safe
			if r.Registry != "" && r.Registry != "docker.io" {
				attrs = append(attrs, "mirror")
			}
		}
	}
	if evidence == nil {
		return
	}
	impact := diag.ImpactUnknown
	if component != "" {
		impact = catalog.Impact(component)
	}
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CHT-002", Severity: diag.SeverityMedium, Confidence: confidence, Impact: impact, Component: component, Location: loc(s.path, evidence.Line, evidence.Column), Reference: reference, Original: reference, Attributes: attrs})
}

func isBitnamiChartsURL(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "/")
	return v == "https://github.com/bitnami/charts" || strings.HasPrefix(v, "https://github.com/bitnami/charts/")
}

// bitnamiAnnotationImage returns the images node, the first Bitnami image in an
// annotations.images list, and its confidence. One finding per chart, never one
// per annotation line. A templated image is unresolved, an image from another
// registry is inferred, and only Docker Hub is confirmed (spec section 2.2).
func bitnamiAnnotationImage(n *yaml.Node) (*yaml.Node, imageref.Reference, diag.Confidence) {
	evidence := n
	for _, entry := range annotationEntries(n) {
		image := ""
		if entry.Kind == yaml.ScalarNode {
			image = entry.Value
		} else {
			image = valueAt(entry, "image")
		}
		if image == "" {
			continue
		}
		r := imageref.Parse(image)
		if !r.HasStaticEvidence {
			continue
		}
		switch {
		case r.Templated:
			return evidence, r, diag.ConfidenceUnresolved
		case r.Registry != "" && r.Registry != "docker.io":
			return evidence, r, diag.ConfidenceInferred
		}
		return evidence, r, diag.ConfidenceConfirmed
	}
	return nil, imageref.Reference{}, ""
}

func annotationEntries(n *yaml.Node) []*yaml.Node {
	if n == nil {
		return nil
	}
	for depth := 0; n.Kind == yaml.AliasNode && n.Alias != nil && depth < maxYAMLDepth; depth++ {
		n = n.Alias
	}
	if n.Kind == yaml.ScalarNode {
		var parsed yaml.Node
		if err := yaml.Unmarshal([]byte(n.Value), &parsed); err != nil || len(parsed.Content) == 0 {
			return nil
		}
		n = parsed.Content[0]
	}
	if n.Kind == yaml.SequenceNode {
		return n.Content
	}
	return []*yaml.Node{n}
}
func (s *walkState) scanArgo(spec *yaml.Node) {
	if spec == nil {
		return
	}
	sources := append([]*yaml.Node{}, sequenceAt(spec, "sources")...)
	if one := nodeAt(spec, "source"); one != nil {
		sources = append(sources, one)
	}
	for _, src := range sources {
		chart := valueAt(src, "chart")
		s.addChartAt(nodeAt(src, "repoURL"), chart)
		before := len(s.out.Findings)
		if v := nodeAt(src, "helm", "values"); v != nil && v.Kind == yaml.ScalarNode && strings.TrimSpace(v.Value) != "" {
			var embedded yaml.Node
			if err := yaml.Unmarshal([]byte(v.Value), &embedded); err != nil || len(embedded.Content) == 0 {
				// A malformed embedded values block is never dropped silently
				// (spec sections 3, 5; review 02 F1).
				s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, s.path, embeddedLineOffset(v)+1, v.Column, "malformed embedded values"))
			} else {
				s.scanImagesAt(embedded.Content[0], true, embeddedLineOffset(v), map[*yaml.Node]bool{}, new(int))
			}
		}
		s.scanImages(nodeAt(src, "helm", "valuesObject"), true)
		if chart != "" {
			for i := before; i < len(s.out.Findings); i++ {
				s.out.Findings[i].Impact = catalog.Impact(chart)
			}
		}
	}
}
func (s *walkState) scanPodSpecs(root *yaml.Node, kind string) {
	var pod *yaml.Node
	switch kind {
	case "pod":
		pod = nodeAt(root, "spec")
	case "cronjob":
		pod = nodeAt(root, "spec", "jobTemplate", "spec", "template", "spec")
	case "job":
		pod = nodeAt(root, "spec", "template", "spec")
	default:
		pod = nodeAt(root, "spec", "template", "spec")
	}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, c := range sequenceAt(pod, key) {
			s.addNodeImage(nodeAt(c, "image"), false)
		}
	}
}
func (s *walkState) scanKustomize(root *yaml.Node) {
	for _, image := range sequenceAt(root, "images") {
		name := valueAt(image, "newName")
		if name == "" {
			name = valueAt(image, "name")
		}
		if tag := valueAt(image, "newTag"); tag != "" {
			name += ":" + tag
		}
		if digest := valueAt(image, "digest"); digest != "" {
			name += "@" + digest
		}
		n := nodeAt(image, "newName")
		if n == nil {
			n = nodeAt(image, "name")
		}
		if n != nil {
			s.addImage(name, n.Line, n.Column, false)
		}
	}
	for _, chart := range sequenceAt(root, "helmCharts") {
		s.addChartAt(nodeAt(chart, "repo"), valueAt(chart, "name"))
		s.scanImages(nodeAt(chart, "valuesInline"), true)
	}
}

func (s *walkState) scanHelmChartGenerator(root *yaml.Node) {
	s.addChartAt(nodeAt(root, "repo"), valueAt(root, "name"))
	s.scanImages(nodeAt(root, "valuesInline"), true)
}

// isKustomizationBase reports whether a (lower-cased) file name selects the
// Kustomize scanner: the file names kustomize accepts, including the
// extensionless `Kustomization` (spec section 9.2).
func isKustomizationBase(base string) bool {
	return base == "kustomization" || base == "kustomization.yaml" || base == "kustomization.yml"
}

// IsKustomizationFile reports whether path names a Kustomization file: the
// file names kustomize accepts, `kustomization.yaml`, `kustomization.yml` and
// the extensionless `Kustomization`, matched case-insensitively (spec section
// 9.2).
func IsKustomizationFile(path string) bool {
	return isKustomizationBase(strings.ToLower(filepath.Base(path)))
}

// ValuesRefs holds the valuesFile references the YAML documents of a file
// declare (spec section 9.2).
type ValuesRefs struct {
	// Generator lists the valuesFile of every HelmChartInflationGenerator.
	Generator []string
	// Chart lists the valuesFile of every helmCharts entry.
	Chart []string
}

// All returns every declared reference, the helmCharts entries first.
func (v ValuesRefs) All() []string {
	out := make([]string, 0, len(v.Chart)+len(v.Generator))
	out = append(out, v.Chart...)
	out = append(out, v.Generator...)
	return out
}

// ValuesFileRefs returns the valuesFile references the YAML documents in data
// declare, in document order: the top-level valuesFile of every
// HelmChartInflationGenerator, and the valuesFile of every helmCharts entry of
// a Kustomization document. A file that declares none is not parsed at all.
// The repository scanner resolves the references relative to the directory of
// the file that declares them (spec section 9.2).
func ValuesFileRefs(path string, data []byte) ValuesRefs {
	var out ValuesRefs
	if !containsFold(data, "valuesfile") {
		return out
	}
	kustomize := IsKustomizationFile(path)
	dec := yaml.NewDecoder(bytes.NewReader(stripBOM(data)))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			break
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if strings.EqualFold(valueAt(root, "kind"), "HelmChartInflationGenerator") {
			if ref := strings.TrimSpace(valueAt(root, "valuesFile")); ref != "" {
				out.Generator = append(out.Generator, ref)
			}
		}
		if kustomize {
			for _, chart := range sequenceAt(root, "helmCharts") {
				if ref := strings.TrimSpace(valueAt(chart, "valuesFile")); ref != "" {
					out.Chart = append(out.Chart, ref)
				}
			}
		}
	}
	return out
}

// containsFold reports whether data holds s, ignoring ASCII case. It never
// allocates, so a repository scan can look for a key in every file it reads.
func containsFold(data []byte, s string) bool {
	needle := []byte(s)
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(data); i++ {
		if bytes.EqualFold(data[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// HelmValues scans one file as chart values, without filename-based
// dispatching, so a valuesFile the repository scanner resolved for a chart is
// scanned as chart values whatever its name (spec section 9.2). The coverage
// is the one of a values file: the whole tree is scanned for image references
// and the whole-scalar fallback applies.
func HelmValues(path string, data []byte) diag.Report {
	data = stripBOM(data)
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out diag.Report
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-001", diag.LevelError, path, 0, 0, "malformed YAML"))
			break
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if err := GuardYAML(root); err != nil {
			out.Diagnostics = append(out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, path, root.Line, root.Column, err.Error()))
			continue
		}
		if strings.EqualFold(valueAt(root, "kind"), "Secret") {
			continue
		}
		s := walkState{path: path, globalRegistry: findString(root, []string{"global", "imageRegistry"}), out: &out}
		s.scanConfig(root)
		s.scanImages(root, false)
		before := len(s.out.Findings)
		s.scanFallbacks(root)
		s.dropDuplicateFallbacks(before)
		s.out.Findings = diag.DedupeFindings(s.out.Findings)
	}
	return out
}

func (s *walkState) scanCompose(root *yaml.Node) {
	for _, service := range mapValues(nodeAt(root, "services")) {
		s.addNodeImage(nodeAt(service, "image"), false)
	}
}
func (s *walkState) scanActions(root *yaml.Node) {
	for _, job := range mapValues(nodeAt(root, "jobs")) {
		container := nodeAt(job, "container")
		if container != nil {
			if container.Kind == yaml.ScalarNode {
				s.addNodeImage(container, false)
			} else {
				s.addNodeImage(nodeAt(container, "image"), false)
			}
		}
		for _, service := range mapValues(nodeAt(job, "services")) {
			s.addNodeImage(nodeAt(service, "image"), false)
		}
		for _, step := range sequenceAt(job, "steps") {
			if uses := nodeAt(step, "uses"); uses != nil && strings.HasPrefix(uses.Value, "docker://") {
				s.addImage(strings.TrimPrefix(uses.Value, "docker://"), uses.Line, uses.Column, false)
			}
		}
	}
}
func (s *walkState) scanGitLab(root *yaml.Node) {
	scan := func(n *yaml.Node) {
		s.addImageForm(nodeAt(n, "image"))
		for _, svc := range sequenceAt(n, "services") {
			s.addImageForm(svc)
		}
	}
	scan(root)
	scan(nodeAt(root, "default"))
	reserved := map[string]bool{"image": true, "services": true, "default": true, "stages": true, "variables": true, "include": true, "workflow": true}
	for k, v := range mapEntries(root) {
		if !reserved[k] && v.Kind == yaml.MappingNode {
			scan(v)
		}
	}
}
func (s *walkState) scanAzure(root *yaml.Node) {
	s.addImageForm(nodeAt(root, "container"))
	for _, c := range sequenceAt(root, "resources", "containers") {
		s.addNodeImage(nodeAt(c, "image"), false)
	}
	for _, job := range sequenceAt(root, "jobs") {
		s.addImageForm(nodeAt(job, "container"))
		for _, svc := range mapValues(nodeAt(job, "services")) {
			s.addImageForm(svc)
		}
	}
}
func (s *walkState) addImageForm(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		s.addNodeImage(n, false)
	} else {
		s.addNodeImage(nodeAt(n, "name"), false)
		s.addNodeImage(nodeAt(n, "image"), false)
	}
}
func (s *walkState) addNodeImage(n *yaml.Node, embedded bool) {
	if n != nil && n.Kind == yaml.ScalarNode {
		s.addImage(n.Value, n.Line, n.Column, embedded)
	}
}
func (s *walkState) addChartAt(n *yaml.Node, component string) {
	if n == nil || n.Kind != yaml.ScalarNode || !isBitnamiChartSource(n.Value) {
		return
	}
	impact := diag.ImpactUnknown
	if component != "" {
		impact = catalog.Impact(component)
	}
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CHT-001", Severity: diag.SeverityMedium, Confidence: diag.ConfidenceConfirmed, Impact: impact, Component: component, Location: loc(s.path, n.Line, n.Column), Reference: strings.TrimSpace(n.Value), Original: strings.TrimSpace(n.Value), Attributes: []string{"chart"}})
}
func (s *walkState) scanImages(n *yaml.Node, embedded bool) {
	s.scanImagesAt(n, embedded, 0, map[*yaml.Node]bool{}, new(int))
}

// scanImagesAt walks a values-shaped subtree. lineOffset is how many lines the
// walked content is shifted inside the file, so a reference embedded in a block
// scalar keeps its own line instead of the values: marker line (spec 5).
func (s *walkState) scanImagesAt(n *yaml.Node, embedded bool, lineOffset int, seen map[*yaml.Node]bool, budget *int) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode {
		if n.Alias == nil || seen[n.Alias] {
			return
		}
		if *budget >= maxAliasNodes {
			// Only alias expansions consume the budget, so an ordinary large
			// values file is never truncated (review 02 F2). Hitting the limit
			// is a diagnostic, never a silent truncation (spec section 3).
			if !s.aliasLimitReported {
				s.aliasLimitReported = true
				s.out.Diagnostics = append(s.out.Diagnostics, newDiagnostic("DSD-SCN-005", diag.LevelWarning, s.path, n.Line, n.Column, "alias expansion limit reached"))
			}
			return
		}
		*budget++
		seen[n.Alias] = true
		s.scanImagesAt(n.Alias, embedded, lineOffset, seen, budget)
		delete(seen, n.Alias)
		return
	}
	if isSecretMapping(n) {
		return
	}
	if n.Kind == yaml.MappingNode {
		if isImageTriple(n) {
			s.scanSplitImage(n, embedded, lineOffset)
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "<<" {
				s.scanImagesAt(v, embedded, lineOffset, seen, budget)
			} else if k.Value == "image" && v.Kind == yaml.ScalarNode {
				s.addImage(v.Value, v.Line+lineOffset, v.Column, embedded)
			} else {
				s.scanImagesAt(v, embedded, lineOffset, seen, budget)
			}
		}
		return
	}
	for _, c := range n.Content {
		s.scanImagesAt(c, embedded, lineOffset, seen, budget)
	}
}

// embeddedLineOffset returns the line number the first line of an embedded
// scalar's content maps to: a block scalar's content starts below its marker,
// an inline scalar's content starts on its own line.
func embeddedLineOffset(v *yaml.Node) int {
	if v.Style == yaml.LiteralStyle || v.Style == yaml.FoldedStyle {
		return v.Line
	}
	if v.Line > 0 {
		return v.Line - 1
	}
	return 0
}

func (s *walkState) scanSplitImage(n *yaml.Node, embedded bool, lineOffset int) {
	repo := valueAt(n, "repository")
	if repo == "" {
		return
	}
	reg := valueAt(n, "registry")
	if reg == "" {
		reg = s.globalRegistry
	}
	ref := reg
	if ref != "" {
		ref += "/"
	}
	ref += repo
	if tag := valueAt(n, "tag"); tag != "" {
		ref += ":" + tag
	}
	if d := valueAt(n, "digest"); d != "" {
		ref += "@" + d
	}
	line, col := 0, 0
	if rn := nodeAt(n, "repository"); rn != nil {
		line, col = rn.Line+lineOffset, rn.Column
	}
	s.addImage(ref, line, col, embedded)
}

func nodeAt(n *yaml.Node, path ...string) *yaml.Node {
	for _, p := range path {
		if n == nil {
			return nil
		}
		if n.Kind == yaml.AliasNode {
			n = n.Alias
		}
		n = mappingLookup(n, p, map[*yaml.Node]bool{}, 0)
	}
	return n
}
func mappingLookup(n *yaml.Node, key string, seen map[*yaml.Node]bool, depth int) *yaml.Node {
	if n == nil || depth > maxYAMLDepth || seen[n] {
		return nil
	}
	seen[n] = true
	defer delete(seen, n)
	if n.Kind == yaml.AliasNode {
		return mappingLookup(n.Alias, key, seen, depth+1)
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "<<" {
			continue
		}
		merge := n.Content[i+1]
		candidates := []*yaml.Node{merge}
		if merge.Kind == yaml.SequenceNode {
			candidates = merge.Content
		}
		for _, candidate := range candidates {
			if found := mappingLookup(candidate, key, seen, depth+1); found != nil {
				clone := *found
				clone.Line, clone.Column = candidate.Line, candidate.Column
				return &clone
			}
		}
	}
	return nil
}
func valueAt(n *yaml.Node, path ...string) string {
	n = nodeAt(n, path...)
	if n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}
func sequenceAt(n *yaml.Node, path ...string) []*yaml.Node {
	n = nodeAt(n, path...)
	if n != nil && n.Kind == yaml.SequenceNode {
		return n.Content
	}
	return nil
}
func mapValues(n *yaml.Node) []*yaml.Node {
	out := []*yaml.Node{}
	for _, v := range mapEntries(n) {
		out = append(out, v)
	}
	return out
}
func mapEntries(n *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if n == nil {
		return out
	}
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value != "<<" {
			out[n.Content[i].Value] = n.Content[i+1]
		}
	}
	return out
}
func isKubernetesKind(k string) bool {
	switch k {
	case "pod", "deployment", "statefulset", "daemonset", "replicaset", "job", "cronjob":
		return true
	}
	return false
}
func isCompose(b string) bool {
	return b == "compose.yaml" || b == "compose.yml" || strings.HasPrefix(b, "docker-compose") && (strings.HasSuffix(b, ".yaml") || strings.HasSuffix(b, ".yml"))
}
func isActions(p string) bool {
	p = strings.ToLower(filepath.ToSlash(p))
	return strings.Contains(p, "/.github/workflows/") || strings.HasPrefix(p, ".github/workflows/")
}
func isGitLab(b string) bool {
	return b == ".gitlab-ci.yml" || b == ".gitlab-ci.yaml" || strings.HasSuffix(b, ".gitlab-ci.yml") || strings.HasSuffix(b, ".gitlab-ci.yaml")
}
func isAzure(b string) bool {
	return strings.HasPrefix(b, "azure-pipelines") && (strings.HasSuffix(b, ".yaml") || strings.HasSuffix(b, ".yml"))
}
