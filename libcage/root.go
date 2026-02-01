package libcage

import (
	"errors"
	"os"
	"path/filepath"
)

// FindRoot walks upwards from start (which may be a file or directory) looking for
// a directory that contains a ".cage" directory.
func FindRoot(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}

	st, err := os.Stat(abs)
	if err == nil && !st.IsDir() {
		abs = filepath.Dir(abs)
	}

	d := abs
	for {
		cand := filepath.Join(d, ".cage")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			return d, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", errors.New("cage root not found (no .cage directory in parents)")
}

// RequireExplicitRoot checks that dir contains a .cage directory.
func RequireExplicitRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(filepath.Join(abs, ".cage"))
	if err != nil || !fi.IsDir() {
		return "", errors.New("-wd must point at a directory that contains .cage")
	}
	return abs, nil
}
