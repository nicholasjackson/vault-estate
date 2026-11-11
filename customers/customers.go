// Package customers holds the example customers, embedded so vault-estate
// can lay them out from any directory, and from its container image.
package customers

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed *.xcl
var files embed.FS

// Extract writes the example customers to a new temporary folder and
// returns it, with a function that removes it.
func Extract() (string, func(), error) {
	dir, err := os.MkdirTemp("", "vault-estate-customers-")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() { _ = os.RemoveAll(dir) }

	names, err := fs.Glob(files, "*.xcl")
	if err != nil {
		cleanup()
		return "", nil, err
	}

	for _, name := range names {
		b, err := files.ReadFile(name)
		if err != nil {
			cleanup()
			return "", nil, err
		}

		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			cleanup()
			return "", nil, err
		}
	}

	return dir, cleanup, nil
}
