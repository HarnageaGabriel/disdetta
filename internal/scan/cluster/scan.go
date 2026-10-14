package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"github.com/HarnageaGabriel/disdetta/internal/diag"
	"github.com/HarnageaGabriel/disdetta/internal/imageref"
)

// ListLimit is the page size every list uses (spec v0.2 section 4). It is
// exported so the client and its tests agree on pagination.
const ListLimit = 500

// Tier 2 label keys (spec v0.2 section 2).
const (
	labelChart    = "helm.sh/chart"
	labelRelease  = "meta.helm.sh/release-name"
	labelInstance = "app.kubernetes.io/instance"
)

// Options controls a cluster scan (spec v0.2 section 1).
type Options struct {
	Context         string
	Kubeconfig      string
	Namespaces      []string
	ReadHelmSecrets bool
	Timeout         time.Duration
}

// chartMetadata is the subset of Helm chart metadata the scan reads, from the
// release JSON (research notes section 9).
type chartMetadata struct {
	name        string
	version     string
	home        string
	sources     []string
	annotations map[string]string
}

// decodedRelease is the subset of a decoded Helm release JSON document the scan
// reads (research notes section 9). No field is ever printed.
type decodedRelease struct {
	Chart struct {
		Metadata struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Home        string            `json:"home"`
			Sources     []string          `json:"sources"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	} `json:"chart"`
	Config json.RawMessage `json:"config"`
}

// Scan reads the cluster through source and returns a deterministic report
// (spec v0.2). source issues read-only list calls only (ADR 0007). The returned
// error is non-nil only when ctx is cancelled; a list that fails is a
// DSD-SCN-010 diagnostic and the scan continues.
func Scan(ctx context.Context, source Source, opts Options) (diag.Report, error) {
	var out diag.Report
	mandatoryIncomplete := false

	workloads, failures := source.ListWorkloads(ctx, opts.Namespaces)
	for _, f := range failures {
		out.Diagnostics = append(out.Diagnostics, listDiagnostic(f))
		if f.Forbidden && f.Tier <= 2 {
			mandatoryIncomplete = true
		}
	}
	// summary.filesScanned counts the cluster objects read (spec v0.2 section 3).
	out.Summary.FilesScanned += len(workloads.Templates) + len(workloads.Pods)

	registries := runningImageRegistries(workloads.Pods)
	for _, w := range workloads.Templates {
		out.Findings = append(out.Findings, workloadFindings(opts.Context, w, registries)...)
	}
	for _, p := range workloads.Pods {
		if p.Owned {
			// A pod with a controller owner is not a template source (spec 2).
			continue
		}
		out.Findings = append(out.Findings, podFindings(opts.Context, p, registries)...)
	}

	if opts.ReadHelmSecrets {
		releases, relFailures := source.ListReleases(ctx, opts.Namespaces)
		for _, f := range relFailures {
			out.Diagnostics = append(out.Diagnostics, listDiagnostic(f))
		}
		out.Summary.FilesScanned += len(releases)
		for _, rel := range releases {
			findings, diagnostic := releaseFindings(opts.Context, rel)
			out.Findings = append(out.Findings, findings...)
			if diagnostic != nil {
				out.Diagnostics = append(out.Diagnostics, *diagnostic)
			}
		}
	}

	out.Findings = dedupeCluster(out.Findings)
	sortClusterFindings(out.Findings)
	assignFingerprints(out.Findings)
	out.Summary.Releases, out.Groups = diag.ClusterSummary(out.Findings)
	out.Summary.Findings = countSeverities(out.Findings)
	sortDiagnostics(out.Diagnostics)
	out.Summary.Diagnostics = len(out.Diagnostics)
	out.Summary.Complete = !mandatoryIncomplete
	for _, d := range out.Diagnostics {
		if d.Level == diag.LevelError {
			out.Summary.Complete = false
		}
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// workloadFindings scans every container of one workload template (spec v0.2
// section 3).
func workloadFindings(context string, w Workload, registries map[string]map[string]bool) []diag.Finding {
	return containerFindings(context, w.Namespace, w.Kind, w.Name, w.Labels, w.Containers, registries)
}

// podFindings scans a standalone pod's containers (spec v0.2 section 3).
func podFindings(context string, p Pod, registries map[string]map[string]bool) []diag.Finding {
	return containerFindings(context, p.Namespace, "Pod", p.Name, p.Labels, p.Containers, registries)
}

// containerFindings classifies the containers of one object with the v0.1 rule
// selection (spec v0.1 section 2.1) and stamps the cluster location and the
// tier 2 attributes (spec v0.2 section 3).
func containerFindings(context, namespace, kind, name string, labels map[string]string, containers []Container, registries map[string]map[string]bool) []diag.Finding {
	chart, release := chartLabels(labels)
	path := clusterPath(namespace, kind, name)
	out := make([]diag.Finding, 0, len(containers))
	for _, c := range sortedContainers(containers) {
		ref := imageref.Parse(c.Image)
		class, ok, _ := detect.ClassifyReference(ref, false, false)
		if !ok {
			continue
		}
		attrs := append([]string{}, class.Attributes...)
		if mirrored(registries, namespace, c.Image, ref.Registry) && !contains(attrs, "mirror") {
			attrs = append(attrs, "mirror")
		}
		sort.Strings(attrs)
		out = append(out, diag.Finding{
			RuleID:     class.Rule,
			Severity:   class.Severity,
			Confidence: class.Confidence,
			Impact:     class.Impact,
			Component:  class.Component,
			Location:   diag.Location{Path: path},
			Reference:  class.Reference,
			Original:   class.Original,
			Attributes: attrs,
			Resource:   &diag.Resource{Context: context, Namespace: namespace, Kind: kind, Name: name, Container: c.Name, Release: release, Chart: chart},
		})
	}
	return out
}

// releaseFindings decodes one Helm release payload and scans its chart metadata
// (DSD-CHT-002) and user values (DSD-CFG-001, images, fallbacks). The decoded
// config is used and discarded; no value reaches the report (spec v0.2 sections
// 3, 4). A payload over a cap or not decodable is DSD-SCN-009.
func releaseFindings(context string, rel Release) ([]diag.Finding, *diag.Diagnostic) {
	path := clusterPath(rel.Namespace, "Secret", rel.Name)
	decoded, err := DecodeReleasePayload(rel.Payload)
	if err != nil {
		return nil, &diag.Diagnostic{Code: "DSD-SCN-009", Level: diag.LevelError, Message: "helm release payload over a size or ratio cap, or not decodable", Location: diag.Location{Path: path}}
	}
	var document decodedRelease
	if err := json.Unmarshal(decoded, &document); err != nil {
		return nil, &diag.Diagnostic{Code: "DSD-SCN-009", Level: diag.LevelError, Message: "helm release payload is not decodable JSON", Location: diag.Location{Path: path}}
	}
	meta := chartMetadata{
		name:        document.Chart.Metadata.Name,
		version:     document.Chart.Metadata.Version,
		home:        document.Chart.Metadata.Home,
		sources:     document.Chart.Metadata.Sources,
		annotations: document.Chart.Metadata.Annotations,
	}
	resource := func(container string) *diag.Resource {
		return &diag.Resource{Context: context, Namespace: rel.Namespace, Kind: "Secret", Name: rel.Name, Container: container, Release: rel.Name, Chart: chartVersion(meta)}
	}
	var out []diag.Finding
	if metaDocument := chartMetadataDocument(meta); len(metaDocument) > 0 {
		for _, f := range detect.ChartMetadata(path, metaDocument).Findings {
			f.Location = diag.Location{Path: path}
			f.Resource = resource("")
			out = append(out, f)
		}
	}
	if len(document.Config) > 0 {
		for _, f := range detect.Values(path, document.Config).Findings {
			f.Location = diag.Location{Path: path}
			f.Resource = resource("")
			out = append(out, f)
		}
	}
	return out, nil
}

// chartMetadataDocument renders Helm chart metadata as a Chart.yaml-shaped JSON
// document so the v0.1 vendored-chart detector can run on it (spec v0.2
// section 3).
func chartMetadataDocument(m chartMetadata) []byte {
	if m.name == "" && m.home == "" && len(m.sources) == 0 && len(m.annotations) == 0 {
		return nil
	}
	document := map[string]any{"name": m.name, "version": m.version, "home": m.home, "sources": m.sources}
	if len(m.annotations) > 0 {
		document["annotations"] = map[string]any{"images": m.annotations["images"]}
	}
	data, err := json.Marshal(document)
	if err != nil {
		return nil
	}
	return data
}

// chartVersion renders the tier 2 or 3 chart reference "<name>-<version>".
func chartVersion(m chartMetadata) string {
	if m.name == "" {
		return m.version
	}
	if m.version == "" {
		return m.name
	}
	return m.name + "-" + m.version
}

// chartLabels reads the tier 2 labels (spec v0.2 section 2).
func chartLabels(labels map[string]string) (chart, release string) {
	if labels == nil {
		return "", ""
	}
	chart = labels[labelChart]
	release = labels[labelRelease]
	if release == "" {
		release = labels[labelInstance]
	}
	return chart, release
}

// runningImageRegistries maps (namespace, template image) to the registries
// observed in the imageID of running containers (spec v0.2 section 2, tier 1).
func runningImageRegistries(pods []Pod) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, p := range pods {
		for _, status := range p.Status {
			if status.Image == "" || status.ImageID == "" {
				continue
			}
			if registry := imageIDRegistry(status.ImageID); registry != "" {
				key := p.Namespace + "\x00" + status.Image
				set := out[key]
				if set == nil {
					set = map[string]bool{}
					out[key] = set
				}
				set[registry] = true
			}
		}
	}
	return out
}

// mirrored reports whether a running container resolved the template image to a
// different registry, so the mirror attribute is added (spec v0.2 section 3).
func mirrored(registries map[string]map[string]bool, namespace, image, registry string) bool {
	for observed := range registries[namespace+"\x00"+image] {
		if observed != registry {
			return true
		}
	}
	return false
}

// imageIDRegistry returns the registry of a runtime imageID after stripping the
// CRI scheme prefix, or "" when none is present. Digests are never used to guess
// a tag (spec v0.2 section 3).
func imageIDRegistry(id string) string {
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			id = id[len(prefix):]
			break
		}
	}
	return imageref.Parse(id).Registry
}

// clusterPath is the finding location of a cluster object (spec v0.2 section 3):
// cluster/<namespace>/<Kind>/<name>, with line and column 0.
func clusterPath(namespace, kind, name string) string {
	return "cluster/" + namespace + "/" + kind + "/" + name
}

// sortedContainers orders containers by name then image so output does not
// depend on API list order (CONVENTIONS.md).
func sortedContainers(in []Container) []Container {
	out := append([]Container(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Image < out[j].Image
	})
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// dedupeCluster drops exact repeats. Unlike the repository scanner, two
// containers of one workload are distinct findings, so the container is part of
// the identity (spec v0.2 section 3).
func dedupeCluster(in []diag.Finding) []diag.Finding {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, f := range in {
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + f.Reference + "\x00" + f.Original + "\x00" + string(f.Confidence) + "\x00" + container(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// sortClusterFindings applies the cluster order: severity, impact, path,
// container, rule, reference (spec v0.2 section 3).
func sortClusterFindings(findings []diag.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if diag.SeverityRank(a.Severity) != diag.SeverityRank(b.Severity) {
			return diag.SeverityRank(a.Severity) < diag.SeverityRank(b.Severity)
		}
		if diag.ImpactRank(a.Impact) != diag.ImpactRank(b.Impact) {
			return diag.ImpactRank(a.Impact) < diag.ImpactRank(b.Impact)
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if container(a) != container(b) {
			return container(a) < container(b)
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Reference < b.Reference
	})
}

func container(f diag.Finding) string {
	if f.Resource == nil {
		return ""
	}
	return f.Resource.Container
}

// assignFingerprints numbers occurrences in sorted order and hashes them, using
// the v0.1 key with the cluster path in place of the file path (spec v0.2
// section 3).
func assignFingerprints(findings []diag.Finding) {
	occurrence := map[string]int{}
	for i := range findings {
		f := &findings[i]
		key := f.RuleID + "\x00" + f.Location.Path + "\x00" + f.Reference
		n := occurrence[key]
		occurrence[key] = n + 1
		if f.Fingerprint == "" {
			sum := sha256.Sum256([]byte(key + "\x00" + strconv.Itoa(n)))
			f.Fingerprint = fmt.Sprintf("%x", sum[:8])
		}
		if f.Attributes == nil {
			f.Attributes = []string{}
		}
	}
}

func countSeverities(findings []diag.Finding) diag.FindingCounts {
	var counts diag.FindingCounts
	for _, f := range findings {
		switch f.Severity {
		case diag.SeverityHigh:
			counts.High++
		case diag.SeverityMedium:
			counts.Medium++
		case diag.SeverityLow:
			counts.Low++
		}
	}
	return counts
}

// listDiagnostic renders one failed list as DSD-SCN-010 (spec v0.2 sections 4,
// 5). A forbidden list is a warning; any other failure is an error. No API error
// text is echoed.
func listDiagnostic(f ListFailure) diag.Diagnostic {
	level, reason := diag.LevelError, "failed"
	if f.Forbidden {
		level, reason = diag.LevelWarning, "is forbidden by RBAC"
	}
	namespace := f.Namespace
	if namespace == "" {
		namespace = "all"
	}
	return diag.Diagnostic{
		Code:     "DSD-SCN-010",
		Level:    level,
		Message:  fmt.Sprintf("tier %d list of %s in namespace %s %s; the tier is not fully scanned", f.Tier, f.Resource, namespace, reason),
		Location: diag.Location{Path: "cluster/" + namespace + "/" + f.Resource},
	}
}

func sortDiagnostics(in []diag.Diagnostic) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Location.Path != in[j].Location.Path {
			return in[i].Location.Path < in[j].Location.Path
		}
		if in[i].Location.Line != in[j].Location.Line {
			return in[i].Location.Line < in[j].Location.Line
		}
		return in[i].Code < in[j].Code
	})
}
