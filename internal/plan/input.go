package plan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/HarnageaGabriel/disdetta/internal/detect"
	"gopkg.in/yaml.v3"
)

// FindRepoRelease inspects Kubernetes YAML documents and returns one Flux
// HelmRelease or Argo Application whose effective release name matches name.
func FindRepoRelease(name string, files map[string][]byte, valueFiles [][]byte) (Input, error) {
	extra := make([]map[string]any, 0, len(valueFiles))
	for i, data := range valueFiles {
		vals, err := decodeOneMap(data)
		if err != nil {
			return Input{}, fmt.Errorf("parse --values %d: invalid or unsafe YAML", i+1)
		}
		extra = append(extra, vals)
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var matches []Input
	for _, file := range paths {
		docs, err := decodeMaps(files[file])
		if err != nil {
			return Input{}, fmt.Errorf("parse %s: invalid or unsafe YAML", file)
		}
		for _, doc := range docs {
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
				inline, _ := spec["values"].(map[string]any)
				rawValuesFrom, hasValuesFrom := spec["valuesFrom"]
				if hasValuesFrom {
					valuesFrom, ok := rawValuesFrom.([]any)
					if !ok {
						return Input{}, fmt.Errorf("valuesFrom must be a list")
					}
					if len(extra) == 0 {
						return Input{}, fmt.Errorf("valuesFrom is not resolved; pass the referenced values with --values")
					}
					for _, raw := range valuesFrom {
						entry, _ := raw.(map[string]any)
						if target, _ := entry["targetPath"].(string); target != "" {
							return Input{}, fmt.Errorf("valuesFrom targetPath is not reproduced by --values")
						}
					}
				}
				vals := map[string]any{}
				for _, layer := range extra {
					merge(vals, layer)
				}
				merge(vals, inline) // Flux applies spec.values after valuesFrom.
				matches = append(matches, Input{name, chart, version, vals})
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
					parsed, err := decodeOneMap([]byte(raw))
					if err != nil {
						return Input{}, fmt.Errorf("parse Argo helm.values in %s: invalid or unsafe YAML", file)
					}
					merge(vals, parsed)
				}
				if obj, ok := helm["valuesObject"].(map[string]any); ok {
					merge(vals, obj)
				}
				for _, layer := range extra {
					merge(vals, layer)
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
	return in, nil
}

func decodeMaps(data []byte) ([]map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []map[string]any
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		if len(doc.Content) == 0 {
			continue
		}
		if err := detect.GuardYAML(doc.Content[0]); err != nil {
			return nil, err
		}
		var value map[string]any
		if err := doc.Content[0].Decode(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
}

func decodeOneMap(data []byte) (map[string]any, error) {
	docs, err := decodeMaps(data)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return map[string]any{}, nil
	}
	return docs[0], nil
}

func MergeValues(dst map[string]any, src map[string]any) { merge(dst, src) }
func merge(dst, src map[string]any) {
	for k, v := range src {
		if v == nil {
			delete(dst, k)
			continue
		}
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				merge(dm, sm)
				continue
			}
			child := map[string]any{}
			merge(child, sm)
			dst[k] = child
			continue
		}
		dst[k] = v
	}
}
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
