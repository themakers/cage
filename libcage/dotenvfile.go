package libcage

import (
	"fmt"
	"regexp"
	"strings"
)

// MaskMarker replaces secret values in masked output. A fixed length keeps
// the length of the value private; no real secret consists of asterisks.
const MaskMarker = "****************"

// assignRe matches "KEY=VALUE" lines, also commented ("# KEY=VALUE") and
// with spaces around "=" or an "export" prefix.
var assignRe = regexp.MustCompile(`^(\s*)(#\s*)?(export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)

// DotenvLine — one line of a .env file as written.
type DotenvLine struct {
	Raw string
	// Key is set for assignment lines (active or commented).
	Key       string
	Commented bool
	// RHS is the right-hand side as written (quotes included).
	RHS string
}

// IsAssign reports whether the line assigns a variable.
func (l DotenvLine) IsAssign() bool { return l.Key != "" }

// IsComment reports whether the line is a comment that is not a commented
// assignment.
func (l DotenvLine) IsComment() bool {
	return l.Key == "" && strings.HasPrefix(strings.TrimSpace(l.Raw), "#")
}

// Value parses the right-hand side with the same parser run/dump use.
func (l DotenvLine) Value() (string, error) {
	if !l.IsAssign() {
		return "", fmt.Errorf("not an assignment")
	}
	m, err := ParseDotenv([]byte(l.Key + "=" + strings.TrimLeft(l.RHS, " \t")))
	if err != nil {
		return "", err
	}
	return m[l.Key], nil
}

// DotenvFile — a .env file kept line by line: edits preserve comments,
// order and formatting of untouched lines.
type DotenvFile struct {
	Lines []DotenvLine
}

func ParseDotenvFile(b []byte) *DotenvFile {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	f := &DotenvFile{}
	if s == "" {
		return f
	}
	for _, raw := range strings.Split(s, "\n") {
		f.Lines = append(f.Lines, parseDotenvLine(raw))
	}
	return f
}

func parseDotenvLine(raw string) DotenvLine {
	m := assignRe.FindStringSubmatch(raw)
	if m == nil {
		return DotenvLine{Raw: raw}
	}
	return DotenvLine{Raw: raw, Key: m[4], Commented: m[2] != "", RHS: m[5]}
}

func (f *DotenvFile) Bytes() []byte {
	if len(f.Lines) == 0 {
		return nil
	}
	var b strings.Builder
	for _, l := range f.Lines {
		b.WriteString(l.Raw)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// active returns the index of the effective (last active) assignment of key.
func (f *DotenvFile) active(key string) int {
	idx := -1
	for i, l := range f.Lines {
		if l.Key == key && !l.Commented {
			idx = i
		}
	}
	return idx
}

func (f *DotenvFile) commented(key string) int {
	for i, l := range f.Lines {
		if l.Key == key && l.Commented {
			return i
		}
	}
	return -1
}

// Has reports whether key has an active assignment.
func (f *DotenvFile) Has(key string) bool { return f.active(key) >= 0 }

// Get returns the effective value of key.
func (f *DotenvFile) Get(key string) (string, bool, error) {
	i := f.active(key)
	if i < 0 {
		return "", false, nil
	}
	v, err := f.Lines[i].Value()
	return v, true, err
}

// Set assigns key (replacing its effective line or appending a new one).
func (f *DotenvFile) Set(key, value string) error {
	if strings.Contains(value, MaskMarker) {
		return fmt.Errorf("%s: value contains the mask marker %q — a masked value, not the secret", key, MaskMarker)
	}
	line, err := FormatDotenvLine(key, value)
	if err != nil {
		return err
	}
	if i := f.active(key); i >= 0 {
		f.Lines[i] = parseDotenvLine(line)
		return nil
	}
	f.Lines = append(f.Lines, parseDotenvLine(line))
	return nil
}

// Remove deletes all active assignments of key.
func (f *DotenvFile) Remove(key string) bool {
	var out []DotenvLine
	removed := false
	for _, l := range f.Lines {
		if l.Key == key && !l.Commented {
			removed = true
			continue
		}
		out = append(out, l)
	}
	f.Lines = out
	return removed
}

// RemoveCommented deletes all commented-out assignments of key.
func (f *DotenvFile) RemoveCommented(key string) bool {
	var out []DotenvLine
	removed := false
	for _, l := range f.Lines {
		if l.Key == key && l.Commented {
			removed = true
			continue
		}
		out = append(out, l)
	}
	f.Lines = out
	return removed
}

// Disable comments out the effective assignment of key.
func (f *DotenvFile) Disable(key string) error {
	i := f.active(key)
	if i < 0 {
		return fmt.Errorf("%s: no active assignment", key)
	}
	f.Lines[i] = parseDotenvLine("#" + f.Lines[i].Raw)
	return nil
}

// Enable uncomments the first commented assignment of key.
func (f *DotenvFile) Enable(key string) error {
	if f.active(key) >= 0 {
		return fmt.Errorf("%s: already has an active assignment", key)
	}
	i := f.commented(key)
	if i < 0 {
		return fmt.Errorf("%s: no commented assignment", key)
	}
	raw := strings.TrimLeft(f.Lines[i].Raw, " \t")
	raw = strings.TrimLeft(strings.TrimPrefix(raw, "#"), " \t")
	f.Lines[i] = parseDotenvLine(raw)
	return nil
}

// Annotate puts "# text" right above the assignment of key (active, or the
// first commented one), replacing the comment block directly above it.
func (f *DotenvFile) Annotate(key, text string) error {
	i := f.active(key)
	if i < 0 {
		i = f.commented(key)
	}
	return f.annotateAt(i, key, text)
}

// AnnotateCommented is Annotate for the first commented-out assignment
// (a disabled block next to an active value).
func (f *DotenvFile) AnnotateCommented(key, text string) error {
	return f.annotateAt(f.commented(key), key, text)
}

func (f *DotenvFile) annotateAt(i int, key, text string) error {
	if i < 0 {
		return fmt.Errorf("%s: no assignment", key)
	}
	start := i
	for start > 0 && f.Lines[start-1].IsComment() {
		start--
	}
	var block []DotenvLine
	for _, t := range strings.Split(strings.TrimSpace(text), "\n") {
		block = append(block, DotenvLine{Raw: "# " + strings.TrimSpace(t)})
	}
	out := append([]DotenvLine{}, f.Lines[:start]...)
	out = append(out, block...)
	out = append(out, f.Lines[i:]...)
	f.Lines = out
	return nil
}

// Validate parses the whole file with the run/dump parser.
func (f *DotenvFile) Validate() error {
	_, err := ParseDotenv(f.Bytes())
	return err
}

var bareValueRe = regexp.MustCompile(`^[A-Za-z0-9_./:@%+,=\-]*$`)

// FormatDotenvLine renders KEY=VALUE quoted as needed. Multi-line values
// are rejected (consumers parse .env files differently).
func FormatDotenvLine(key, value string) (string, error) {
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) {
		return "", fmt.Errorf("invalid variable name %q", key)
	}
	if strings.ContainsAny(value, "\n\r") {
		return "", fmt.Errorf("%s: multi-line values are not supported", key)
	}
	switch {
	case bareValueRe.MatchString(value):
		return key + "=" + value, nil
	case !strings.Contains(value, "'"):
		return key + "='" + value + "'", nil
	default:
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")
		return key + `="` + r.Replace(value) + `"`, nil
	}
}
