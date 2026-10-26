package parser

import (
	"fmt"
	"slices"

	"go.yaml.in/yaml/v3"
)

// maxYAMLKeyComparisons caps the duplicate-key comparisons yaml.v3 makes while
// decoding. Each decoded mapping costs the square of its key count.
const maxYAMLKeyComparisons = 100_000_000

// parseYAML parses untrusted YAML into a node tree without decoding it, which
// takes time linear in the input. It returns nil for an empty document.
func parseYAML(data []byte) (root *yaml.Node, err error) {
	defer recoverYAML(&err)
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil
	}
	return doc.Content[0], nil
}

// decodeYAML decodes untrusted YAML into typed dst. keep, when non-empty,
// drops every other top-level key before decoding.
func decodeYAML(data []byte, dst any, keep ...string) error {
	root, err := parseYAML(data)
	if err != nil || root == nil {
		return err
	}
	if len(keep) > 0 && root.Kind == yaml.MappingNode {
		root = onlyKeys(root, keep)
	}
	var d yamlDecoder
	return d.decode(root, dst)
}

// onlyKeys returns a copy of mapping m holding only the pairs whose scalar key
// is in keep.
func onlyKeys(m *yaml.Node, keep []string) *yaml.Node {
	pruned := *m
	pruned.Content = nil
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Kind == yaml.ScalarNode && slices.Contains(keep, k.Value) {
			pruned.Content = append(pruned.Content, k, m.Content[i+1])
		}
	}
	return &pruned
}

// yamlDecoder decodes untrusted node trees under one shared
// maxYAMLKeyComparisons budget.
type yamlDecoder struct {
	comparisons int64
}

// decode checks n against the budget and decodes it into dst, turning any
// decoder panic into an error. Aliases are rejected: lockfiles never use them,
// and expanding them multiplies decoding work.
func (d *yamlDecoder) decode(n *yaml.Node, dst any) (err error) {
	defer recoverYAML(&err)
	if err := d.check(n); err != nil {
		return err
	}
	return n.Decode(dst)
}

func (d *yamlDecoder) check(n *yaml.Node) error {
	switch n.Kind {
	case yaml.AliasNode:
		return fmt.Errorf("line %d: YAML aliases are not supported in lockfiles", n.Line)
	case yaml.MappingNode:
		pairs := int64(len(n.Content) / 2)
		d.comparisons += pairs * pairs
		if d.comparisons > maxYAMLKeyComparisons {
			return fmt.Errorf("line %d: YAML mapping too large to decode", n.Line)
		}
	}
	for _, c := range n.Content {
		if err := d.check(c); err != nil {
			return err
		}
	}
	return nil
}

func recoverYAML(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("YAML decoder failed: %v", r)
	}
}
