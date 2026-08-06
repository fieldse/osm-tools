package report

import "testing"

// TestParseTemplate_HeaderVariants_F6 asserts the payload/evidence section
// headers are matched tolerantly (case and internal spacing), so a slightly
// off heading like "## Payload/IOCs" does not silently drop the IOC field.
func TestParseTemplate_HeaderVariants_F6(t *testing.T) {
	src := `# t

- Type: package
- Resource: evil-pkg

## description
does bad things

## Payload/IOCs
beacon to evil.com

## evidence
- https://osv.dev/x
`
	got, err := ParseTemplate([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "does bad things" {
		t.Errorf("Description = %q; header-variant '## description' dropped the body", got.Description)
	}
	if got.PayloadDescription != "beacon to evil.com" {
		t.Errorf("PayloadDescription = %q; header-variant '## Payload/IOCs' dropped the IOC field", got.PayloadDescription)
	}
	if len(got.EvidenceRefs) != 1 {
		t.Errorf("EvidenceRefs = %v; header-variant '## evidence' dropped evidence", got.EvidenceRefs)
	}
}
