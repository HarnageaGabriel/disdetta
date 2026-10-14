package detect

import (
	"errors"

	"gopkg.in/yaml.v3"
)

var (
	ErrYAMLDepth = errors.New("YAML depth limit reached")
	ErrYAMLAlias = errors.New("alias expansion limit reached")
)

// GuardYAML applies the repository scanner's depth and alias-expansion limits
// before a caller decodes a node into recursive Go values.
func GuardYAML(root *yaml.Node) error {
	aliases := 0
	var walk func(*yaml.Node, int, map[*yaml.Node]bool) error
	walk = func(node *yaml.Node, depth int, stack map[*yaml.Node]bool) error {
		if node == nil {
			return nil
		}
		if depth > maxYAMLDepth {
			return ErrYAMLDepth
		}
		if node.Kind == yaml.AliasNode {
			aliases++
			if aliases > maxAliasNodes {
				return ErrYAMLAlias
			}
			if node.Alias == nil || stack[node.Alias] {
				return nil
			}
			stack[node.Alias] = true
			err := walk(node.Alias, depth+1, stack)
			delete(stack, node.Alias)
			return err
		}
		for _, child := range node.Content {
			if err := walk(child, depth+1, stack); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0, map[*yaml.Node]bool{})
}
