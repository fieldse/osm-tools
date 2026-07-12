package report

import "strings"

// templateText is the canonical blank report template. Every field the parser
// recognizes appears here with an inline <...> placeholder hint, and the whole
// document round-trips through ParseTemplate to an empty Report.
const templateText = `# <title / one-line summary>

- Type: <package|container|repository|url|domain|ip|wallet>
- Resource: <resource identifier>
- Package name: <optional>
- Registry: <npm|pypi|...>
- Publisher: <optional>
- Contact: <email, optional>
- Affected versions: <comma-separated, optional>
- Severity: <critical|high|medium|low>
- First seen: <ISO 8601, optional>
- Last seen: <ISO 8601, optional>
- OSV: <advisory url, optional>
- Tags: <comma-separated, optional>

## Description
<threat_description — required>

## Payload / IOCs
<payload_description — the only defanged field, optional>

## Evidence
- <url one per line, optional>
`

// Template returns the canonical blank report template (markdown). `osm submit
// --template` prints this, so the file itself documents the good-report shape.
// Every field the parser recognizes appears here with an inline hint.
func Template() string {
	return templateText
}

// ParseTemplate parses a filled-in template file into a Report. It is lenient
// about ordering and whitespace and tolerant of missing sections (validation,
// not parsing, decides what is required). Unrecognized lines are ignored rather
// than rejected — the template is a human-authored convenience format.
func ParseTemplate(src []byte) (Report, error) {
	var r Report

	// section is the current H2 body we are accumulating into: "" (the
	// field/header region), "description", "payload", or "evidence".
	section := ""
	var descBody, payloadBody []string

	for _, raw := range strings.Split(string(src), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		// H2 section headings switch the accumulation target. Matching is
		// tolerant of case and internal spacing so a near-miss like
		// "## Payload/IOCs" doesn't silently drop the IOC field.
		if strings.HasPrefix(trimmed, "## ") {
			switch normalizeHeading(trimmed[3:]) {
			case "description":
				section = "description"
			case "payload/iocs", "payload":
				section = "payload"
			case "evidence":
				section = "evidence"
			default:
				section = "unknown"
			}
			continue
		}
		// H1 title is cosmetic.
		if strings.HasPrefix(trimmed, "# ") {
			continue
		}

		switch section {
		case "", "unknown":
			// Field/header region: `- Key: value` lines map to fields.
			if k, v, ok := splitKeyValue(trimmed); ok {
				applyField(&r, k, v)
			}
		case "description":
			descBody = append(descBody, line)
		case "payload":
			payloadBody = append(payloadBody, line)
		case "evidence":
			if strings.HasPrefix(trimmed, "- ") {
				if item := cleanValue(trimmed[2:]); item != "" {
					r.EvidenceRefs = append(r.EvidenceRefs, item)
				}
			}
		}
	}

	r.Description = cleanBody(descBody)
	r.PayloadDescription = cleanBody(payloadBody)
	return r, nil
}

// normalizeHeading lowercases a section heading and strips spaces so
// "Payload / IOCs", "Payload/IOCs", and "payload / iocs" all match.
func normalizeHeading(h string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(h)), " ", "")
}

// splitKeyValue parses a `- Key: value` bullet line. It reports ok=false for
// lines that are not `- `-prefixed key/value pairs.
func splitKeyValue(line string) (key, value string, ok bool) {
	if !strings.HasPrefix(line, "- ") {
		return "", "", false
	}
	rest := line[2:]
	i := strings.IndexByte(rest, ':')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:]), true
}

// applyField maps a template key (case-insensitive) onto the matching Report
// field. Unrecognized keys are ignored.
func applyField(r *Report, key, value string) {
	v := cleanValue(value)
	switch strings.ToLower(key) {
	case "type":
		r.Type = v
	case "resource":
		r.ResourceID = v
	case "package name":
		r.PackageName = v
	case "registry":
		r.Registry = v
	case "publisher":
		r.Publisher = v
	case "contact":
		r.ContactEmail = v
	case "affected versions":
		r.VersionInfo = v
	case "severity":
		r.SeverityLevel = v
	case "first seen":
		r.FirstSeen = v
	case "last seen":
		r.LastSeen = v
	case "osv":
		r.OSVAdvisoryURL = v
	case "tags":
		r.Tags = splitCSV(v)
	}
}

// splitCSV splits a comma-separated value, trimming each element and dropping
// blanks. An empty input yields a nil slice.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// cleanBody joins accumulated section lines, trims surrounding whitespace, and
// treats a lone placeholder hint as empty.
func cleanBody(lines []string) string {
	return cleanValue(strings.TrimSpace(strings.Join(lines, "\n")))
}

// cleanValue returns v trimmed, or "" if v is an angle-bracket placeholder hint
// (starts with "<" and ends with ">").
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return ""
	}
	return v
}
