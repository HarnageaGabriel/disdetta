package detect

import (
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
	case kind == "application":
		s.scanArgo(nodeAt(root, "spec"))
	case kind == "applicationset":
		s.scanArgo(nodeAt(root, "spec", "template", "spec"))
	case isKubernetesKind(kind):
		s.scanPodSpecs(root, kind)
	case base == "kustomization.yaml" || base == "kustomization.yml":
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
	if evidence != nil {
		reference = strings.TrimSpace(evidence.Value)
	} else {
		evidence, reference, confidence = bitnamiAnnotationImage(nodeAt(root, "annotations", "images"))
	}
	if evidence == nil {
		return
	}
	impact := diag.ImpactUnknown
	if component != "" {
		impact = catalog.Impact(component)
	}
	s.out.Findings = append(s.out.Findings, diag.Finding{RuleID: "DSD-CHT-002", Severity: diag.SeverityMedium, Confidence: confidence, Impact: impact, Component: component, Location: loc(s.path, evidence.Line, evidence.Column), Reference: reference, Original: reference, Attributes: []string{"chart"}})
}

func isBitnamiChartsURL(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "/")
	return v == "https://github.com/bitnami/charts" || strings.HasPrefix(v, "https://github.com/bitnami/charts/")
}

// bitnamiAnnotationImage returns the images node, the first Bitnami image in an
// annotations.images list, and its confidence. One finding per chart, never one
// per annotation line.
func bitnamiAnnotationImage(n *yaml.Node) (*yaml.Node, string, diag.Confidence) {
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
		confidence := diag.ConfidenceConfirmed
		if r.Registry != "docker.io" && !r.Templated {
			confidence = diag.ConfidenceInferred
		}
		return evidence, r.Safe, confidence
	}
	return nil, "", ""
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
		if v := nodeAt(src, "helm", "values"); v != nil && v.Kind == yaml.ScalarNode {
			var embedded yaml.Node
			if yaml.Unmarshal([]byte(v.Value), &embedded) == nil && len(embedded.Content) > 0 {
				s.scanImagesAt(embedded.Content[0], true, v.Line, v.Column, map[*yaml.Node]bool{}, new(int))
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
	s.scanImagesAt(n, embedded, 0, 0, map[*yaml.Node]bool{}, new(int))
}
func (s *walkState) scanImagesAt(n *yaml.Node, embedded bool, useLine, useCol int, seen map[*yaml.Node]bool, budget *int) {
	if n == nil || *budget >= maxAliasNodes {
		return
	}
	*budget++
	if n.Kind == yaml.AliasNode {
		if seen[n.Alias] {
			return
		}
		seen[n.Alias] = true
		s.scanImagesAt(n.Alias, embedded, n.Line, n.Column, seen, budget)
		delete(seen, n.Alias)
		return
	}
	if n.Kind == yaml.MappingNode {
		if isImageTriple(n) {
			s.scanSplitImage(n, embedded, useLine, useCol)
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "<<" {
				s.scanImagesAt(v, embedded, k.Line, k.Column, seen, budget)
			} else if k.Value == "image" && v.Kind == yaml.ScalarNode {
				line, col := v.Line, v.Column
				if useLine > 0 {
					line, col = useLine, useCol
				}
				s.addImage(v.Value, line, col, embedded)
			} else {
				s.scanImagesAt(v, embedded, useLine, useCol, seen, budget)
			}
		}
		return
	}
	for _, c := range n.Content {
		s.scanImagesAt(c, embedded, useLine, useCol, seen, budget)
	}
}
func (s *walkState) scanSplitImage(n *yaml.Node, embedded bool, line, col int) {
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
	rn := nodeAt(n, "repository")
	if line == 0 {
		line, col = rn.Line, rn.Column
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
