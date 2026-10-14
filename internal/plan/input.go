package plan

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// FindRepoRelease inspects Kubernetes YAML documents and returns one Flux
// HelmRelease or Argo Application whose effective release name matches name.
func FindRepoRelease(name string, files map[string][]byte, valueFiles [][]byte) (Input, error) {
	var matches []Input
	for file, data := range files {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var doc map[string]any
			err := dec.Decode(&doc)
			if err == io.EOF {
				break
			}
			if err != nil {
				return Input{}, fmt.Errorf("parse %s: %w", file, err)
			}
			if len(doc) == 0 {
				continue
			}
			kind, _ := doc["kind"].(string)
			meta, _ := doc["metadata"].(map[string]any)
			metadataName, _ := meta["name"].(string)
			spec, _ := doc["spec"].(map[string]any)
			switch kind {
			case "HelmRelease":
				releaseName := metadataName
				if s, ok := spec["releaseName"].(string); ok && s != "" {
					releaseName = s
				}
				if releaseName != name {
					continue
				}
				chartSpec, _ := nestedMap(spec, "chart", "spec")
				chart, _ := chartSpec["chart"].(string)
				version, _ := chartSpec["version"].(string)
				vals, _ := spec["values"].(map[string]any)
				matches = append(matches, Input{name, chart, version, clone(vals)})
			case "Application":
				source, _ := spec["source"].(map[string]any)
				helm, _ := source["helm"].(map[string]any)
				releaseName := metadataName
				if s, ok := helm["releaseName"].(string); ok && s != "" {
					releaseName = s
				}
				if releaseName != name {
					continue
				}
				chart, _ := source["chart"].(string)
				version, _ := source["targetRevision"].(string)
				vals := map[string]any{}
				if raw, ok := helm["values"].(string); ok && strings.TrimSpace(raw) != "" {
					if err := yaml.Unmarshal([]byte(raw), &vals); err != nil {
						return Input{}, fmt.Errorf("parse Argo helm.values in %s: %w", file, err)
					}
				}
				if obj, ok := helm["valuesObject"].(map[string]any); ok {
					merge(vals, obj)
				}
				matches = append(matches, Input{name, chart, version, vals})
			}
		}
	}
	if len(matches) == 0 {
		return Input{}, fmt.Errorf("release %q not found", name)
	}
	if len(matches) > 1 {
		return Input{}, fmt.Errorf("release %q is ambiguous (%d definitions)", name, len(matches))
	}
	in := matches[0]
	if in.Chart == "" || in.ChartVersion == "" {
		return Input{}, fmt.Errorf("release %q has no chart name or exact version", name)
	}
	for i, data := range valueFiles {
		var vals map[string]any
		if err := yaml.Unmarshal(data, &vals); err != nil {
			return Input{}, fmt.Errorf("parse --values %d: %w", i+1, err)
		}
		merge(in.Values, vals)
	}
	return in, nil
}

func MergeValues(dst map[string]any, src map[string]any) { merge(dst, src) }
func merge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				merge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}
func clone(src map[string]any) map[string]any { out := map[string]any{}; merge(out, src); return out }
func nestedMap(m map[string]any, keys ...string) (map[string]any, bool) {
	var cur any = m
	for _, k := range keys {
		x, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = x[k]
		if !ok {
			return nil, false
		}
	}
	out, ok := cur.(map[string]any)
	return out, ok
}
