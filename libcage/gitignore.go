package libcage

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type GitignoreStatus struct {
	Path          string
	Exists        bool
	IgnoresAll    bool
	KeepsSelfOnly bool
}

// CheckGitignore inspects <dir>/.gitignore and returns a best-effort assessment.
// Intended for warnings only.
func CheckGitignore(dir string) (GitignoreStatus, error) {
	p := filepath.Join(dir, ".gitignore")
	st := GitignoreStatus{Path: p}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	st.Exists = true

	ignoreAll := false
	keepGitignore := false

	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip inline comments (best-effort; .gitignore doesn't have quoting)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		switch line {
		case "*", "/*", "**", "/**":
			ignoreAll = true
		}
		if strings.HasPrefix(line, "!") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "!"))
			if v == ".gitignore" || v == "/.gitignore" {
				keepGitignore = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return st, err
	}

	st.IgnoresAll = ignoreAll
	st.KeepsSelfOnly = ignoreAll && keepGitignore
	return st, nil
}
