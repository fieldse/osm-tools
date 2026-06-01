package parser

// Dedupe collapses identical name+version+ecosystem entries, preserving first
// occurrence order.
func Dedupe(pkgs []Package) []Package {
	seen := make(map[Package]bool, len(pkgs))
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
