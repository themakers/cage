package libcage

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const gitignoreHeader = "# Managed by cage — regenerated on encrypt/decrypt from cage.yaml dirs. Do not edit.\n"

// cageGitignore — content of .cage/.gitignore: local state and every
// plaintext directory (nested ones are covered by their parents).
func (c *Cage) cageGitignore() string {
	dirs := []string{"local"}
	for _, rel := range c.Cfg.Dirs {
		if in, err := plaintextDirInCage(rel); err == nil {
			dirs = append(dirs, in)
		}
	}
	sort.Strings(dirs)
	var kept []string
	for _, d := range dirs {
		covered := false
		for _, k := range kept {
			if d == k || strings.HasPrefix(d, k+"/") {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, d)
		}
	}
	var b strings.Builder
	b.WriteString(gitignoreHeader)
	for _, d := range kept {
		b.WriteString("/" + d + "/\n")
	}
	return b.String()
}

// WriteGitignore rewrites .cage/.gitignore if its content changed.
func (c *Cage) WriteGitignore() error {
	p := filepath.Join(c.CageDir(), ".gitignore")
	want := c.cageGitignore()
	if b, err := os.ReadFile(p); err == nil && string(b) == want {
		return nil
	}
	if err := AtomicWriteFile(p, []byte(want), 0o644); err != nil {
		return err
	}
	c.Logger.Info("updated .cage/.gitignore")
	return nil
}
