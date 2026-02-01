package libcage

import (
	"fmt"
	"path/filepath"
	"strings"
)

type SecretRef struct {
	Dir  string
	Name string
}

func (r SecretRef) String() string {
	if r.Dir == "default" {
		return r.Name
	}
	return r.Dir + ":" + r.Name
}

// ParseSecretRef parses a reference like "name.env" or "alias:name.env".
// Name must be a basename (no path separators).
func ParseSecretRef(spec string) (SecretRef, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return SecretRef{}, fmt.Errorf("empty secret ref")
	}
	var dir, name string
	if i := strings.IndexByte(s, ':'); i >= 0 {
		dir, name = s[:i], s[i+1:]
		if dir == "" || name == "" {
			return SecretRef{}, fmt.Errorf("invalid secret ref %q", spec)
		}
	} else {
		dir, name = "default", s
	}
	if strings.ContainsRune(name, filepath.Separator) || strings.Contains(name, "/") {
		return SecretRef{}, fmt.Errorf("secret name must be a basename, got %q", name)
	}
	return SecretRef{Dir: dir, Name: name}, nil
}
