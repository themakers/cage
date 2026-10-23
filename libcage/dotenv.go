package libcage

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/direnv/direnv/v2/pkg/dotenv"
)

// ParseDotenvGPT parses a minimal .env format (KEY=VALUE lines, optional leading 'export').
// It is intentionally strict about key names to catch typos early.
func ParseDotenvGPT(b []byte) (map[string]string, error) {
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

func ParseDotenv(b []byte) (map[string]string, error) {
	//> Whole-line comments are dropped first: the underlying parser takes a
	//> comment like `# without "="` for an unclosed quoted value.
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines[i] = ""
		}
	}
	m, err := dotenv.Parse(strings.Join(lines, "\n"))
	if err != nil {
		return nil, sanitizeDotenvError(err, lines)
	}
	return m, nil
}

// sanitizeDotenvError replaces the parser error, which quotes the offending
// line verbatim (possibly a secret value), with its line number.
func sanitizeDotenvError(err error, lines []string) error {
	if bad, ok := strings.CutPrefix(err.Error(), "invalid line: "); ok {
		for i, l := range lines {
			if l == bad {
				return fmt.Errorf("invalid dotenv syntax at line %d (content not shown)", i+1)
			}
		}
		return fmt.Errorf("invalid dotenv syntax (content not shown)")
	}
	if strings.Contains(err.Error(), "unclosed quoted value") {
		return fmt.Errorf("invalid dotenv syntax: unclosed quoted value (content not shown)")
	}
	return fmt.Errorf("invalid dotenv syntax (content not shown)")
}
