package plan

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/HarnageaGabriel/disdetta/internal/report"
	"gopkg.in/yaml.v3"
)

func JSON(p Plan) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
func TargetYAML(p Plan) ([]byte, error) { return yaml.Marshal(p.Target) }
func UnmappedYAML(p Plan) ([]byte, error) {
	return yaml.Marshal(map[string]any{"coverage": fmt.Sprintf("mapped %d of %d user-set keys; derived %d parser items", p.Coverage.Mapped, p.Coverage.Total, p.Coverage.Derived), "unmapped": p.Unmapped})
}
func ChecklistMarkdown(p Plan) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Migration checklist: %s\n\n", report.SafeText(p.Release))
	for _, x := range p.Checklist {
		fmt.Fprintf(&b, "- [ ] %s ([source](%s))\n", report.SafeText(x.Text), report.SafeText(x.Source))
	}
	return b.Bytes()
}
func Table(p Plan) ([]byte, error) {
	target, err := TargetYAML(p)
	if err != nil {
		return nil, err
	}
	unmapped, err := UnmappedYAML(p)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.WriteString("# target.yaml\n")
	b.Write(target)
	b.WriteString("---\n# unmapped\n")
	b.Write(unmapped)
	b.WriteString("---\n# checklist.md\n")
	b.Write(ChecklistMarkdown(p))
	fmt.Fprintf(&b, "\n# mapped %d of %d user-set keys; derived %d parser items\n", p.Coverage.Mapped, p.Coverage.Total, p.Coverage.Derived)
	return b.Bytes(), nil
}
