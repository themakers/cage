package libcage

import (
	"bytes"
	"fmt"
	"strings"
)

// ParseDotenv parses a minimal .env format (KEY=VALUE lines, optional leading 'export').
// It is intentionally strict about key names to catch typos early.
func ParseDotenv(b []byte) (map[string]string, error) {
	out := map[string]string{}
	lines := bytes.Split(b, []byte("\n"))
	for i, raw := range lines {
		line := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r", ""))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.IndexByte(line, '=')
		if idx < 1 {
			return nil, fmt.Errorf("dotenv line %d: expected KEY=VALUE", i+1)
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if k == "" {
			return nil, fmt.Errorf("dotenv line %d: empty key", i+1)
		}
		if strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") && len(v) >= 2 {
			v = strings.TrimSuffix(strings.TrimPrefix(v, "\""), "\"")
		}
		if strings.HasPrefix(v, "'") && strings.HasSuffix(v, "'") && len(v) >= 2 {
			v = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
		}
		out[k] = v
	}
	return out, nil
}
