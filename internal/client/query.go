package client

// Query describes a single check-malicious lookup. Type is the CLI-facing type
// (package, domain, ip, docker); it is mapped to the API's report_type at the
// request boundary.
type Query struct {
	Type       string // package | domain | ip | docker
	Identifier string // package name, domain, IP, or image reference
	Ecosystem  string // optional; only meaningful for packages
	Version    string // optional
}

// reportType maps the CLI type to the API's report_type value. The CLI exposes
// "docker" but the API names the category "container"; this is the one place
// that translation happens.
func reportType(cliType string) string {
	if cliType == "docker" {
		return "container"
	}
	return cliType
}
