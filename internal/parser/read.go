package parser

import (
	"fmt"
	"io"
	"os"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// maxManifestBytes caps how much of any manifest or lockfile is read.
const maxManifestBytes = 64 << 20

// readManifest reads a manifest that may come from an untrusted repository. It
// refuses anything but a regular file (symlinks, devices, FIFOs) and fails
// once the file exceeds maxManifestBytes.
func readManifest(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, osmerr.Usagef("%s is not a regular file; symlinks, devices and pipes are not read", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("%s changed while it was being opened", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%s is larger than the %d MiB manifest limit", path, maxManifestBytes>>20)
	}
	return data, nil
}
