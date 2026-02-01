package libcage

import (
	"bytes"
	"os"
	"sort"
	"strings"
)

func ReadFileIfExists(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return b, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func BytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

func EqualStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func NormalizeRecipientLines(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
