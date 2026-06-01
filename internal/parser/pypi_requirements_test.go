package parser

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/fieldse/osm-tools/internal/ecosystem"
)

func TestParseRequirements(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []Package
	}{
		{
			name: "basic mixed file",
			path: "testdata/requirements_basic.txt",
			want: []Package{
				// Sorted by Name. Range specifiers and bare names have empty Version.
				{Name: "django", Version: "", Ecosystem: ecosystem.PyPI},
				{Name: "flask", Version: "2.3.0", Ecosystem: ecosystem.PyPI},
				{Name: "numpy", Version: "", Ecosystem: ecosystem.PyPI},
				{Name: "pytest", Version: "", Ecosystem: ecosystem.PyPI},
				{Name: "pyyaml", Version: "", Ecosystem: ecosystem.PyPI},
				{Name: "requests", Version: "2.31.0", Ecosystem: ecosystem.PyPI},
				{Name: "six", Version: "", Ecosystem: ecosystem.PyPI},
				{Name: "typing-extensions", Version: "4.5.0", Ecosystem: ecosystem.PyPI},
				{Name: "urllib3", Version: "", Ecosystem: ecosystem.PyPI},
			},
		},
		{
			name: "only comments options and blanks",
			path: "testdata/requirements_empty.txt",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRequirements(tt.path)
			if err != nil {
				t.Fatalf("parseRequirements(%q) returned error: %v", tt.path, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseRequirements(%q)\n got: %#v\nwant: %#v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseRequirementsMissingFile(t *testing.T) {
	_, err := parseRequirements("testdata/does_not_exist.txt")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected wrapped fs.ErrNotExist, got: %v", err)
	}
}

func TestParseRequirementLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantPkg Package
		wantOK  bool
	}{
		{"exact pin", "flask==2.3.0", Package{Name: "flask", Version: "2.3.0", Ecosystem: ecosystem.PyPI}, true},
		{"bare name", "pyyaml", Package{Name: "pyyaml", Ecosystem: ecosystem.PyPI}, true},
		{"ge specifier", "django>=4.0", Package{Name: "django", Ecosystem: ecosystem.PyPI}, true},
		{"compatible release", "numpy~=1.24", Package{Name: "numpy", Ecosystem: ecosystem.PyPI}, true},
		{"not equal", "urllib3!=1.26.0", Package{Name: "urllib3", Ecosystem: ecosystem.PyPI}, true},
		{"extras stripped", "requests[security]==2.0", Package{Name: "requests", Version: "2.0", Ecosystem: ecosystem.PyPI}, true},
		{"env marker stripped", "foo==1.0; python_version<'3.9'", Package{Name: "foo", Version: "1.0", Ecosystem: ecosystem.PyPI}, true},
		{"inline comment stripped", "bar==3.1  # pinned", Package{Name: "bar", Version: "3.1", Ecosystem: ecosystem.PyPI}, true},
		{"surrounding whitespace", "  baz==1.2  ", Package{Name: "baz", Version: "1.2", Ecosystem: ecosystem.PyPI}, true},
		{"blank line", "", Package{}, false},
		{"full-line comment", "# a comment", Package{}, false},
		{"include option", "-r other.txt", Package{}, false},
		{"constraint option", "-c constraints.txt", Package{}, false},
		{"editable install", "-e git+https://x/y.git#egg=z", Package{}, false},
		{"hash option", "--hash=sha256:abc", Package{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, ok := parseRequirementLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("parseRequirementLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if ok && !reflect.DeepEqual(pkg, tt.wantPkg) {
				t.Errorf("parseRequirementLine(%q)\n got: %#v\nwant: %#v", tt.line, pkg, tt.wantPkg)
			}
		})
	}
}
