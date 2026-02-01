package libcage

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var sshKeyLineRe = regexp.MustCompile(`^(?:sk-)?ssh-(?:ed25519|rsa)(?:@openssh\.com)?\s+`)

func LooksLikeSSHPublicKeyLine(s string) bool {
	return sshKeyLineRe.MatchString(strings.TrimSpace(s))
}

// ResolveRecipientRefs resolves a list of recipient references to concrete SSH public key lines.
// Each string may be:
//   - a SSH public key line
//   - a reference to cfg.Recipients group
//
// Cycles are tolerated: recursion stops when a group is seen again.
func ResolveRecipientRefs(cfg *Config, refs []string) ([]string, error) {
	seen := map[string]bool{}
	inStack := map[string]bool{}
	outSet := map[string]struct{}{}
	var out []string

	var walk func(string) error
	walk = func(ref string) error {
		r := strings.TrimSpace(ref)
		if r == "" {
			return nil
		}
		if LooksLikeSSHPublicKeyLine(r) {
			if _, ok := outSet[r]; !ok {
				outSet[r] = struct{}{}
				out = append(out, r)
			}
			return nil
		}

		group := r
		if inStack[group] {
			// Cycle: stop descent.
			return nil
		}
		vals, ok := cfg.Recipients[group]
		if !ok {
			return fmt.Errorf("unknown recipient reference %q", group)
		}
		if seen[group] {
			return nil
		}
		seen[group] = true
		inStack[group] = true
		defer func() { inStack[group] = false }()
		for _, v := range vals {
			if err := walk(v); err != nil {
				return err
			}
		}
		return nil
	}

	for _, r := range refs {
		if err := walk(r); err != nil {
			return nil, err
		}
	}

	// Stable output: sort.
	sort.Strings(out)
	return out, nil
}
