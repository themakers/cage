package libcage

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// minMaskLen — shorter values are not masked: they are not secrets
// (ENV=dev, flags, ports) and would garble unrelated output.
const minMaskLen = 8

// MaskPatterns returns the byte sequences that reveal the given values: the
// value itself and its base64 / URL-escaped forms. For URIs only the
// password is secret (hosts and databases are not); URIs without a
// password are not masked at all.
func MaskPatterns(values []string) [][]byte {
	set := map[string]bool{}
	addForms := func(v string, min int) {
		if len(v) < min {
			return
		}
		set[v] = true
		for _, f := range []string{
			base64.StdEncoding.EncodeToString([]byte(v)),
			base64.RawStdEncoding.EncodeToString([]byte(v)),
			base64.URLEncoding.EncodeToString([]byte(v)),
			base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v),
			url.PathEscape(v),
		} {
			set[f] = true
		}
	}
	for _, v := range values {
		if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" && !strings.ContainsAny(v, " \t") {
			if p, ok := u.User.Password(); ok {
				addForms(p, 6)
			}
			continue
		}
		addForms(v, minMaskLen)
	}
	out := make([][]byte, 0, len(set))
	for s := range set {
		out = append(out, []byte(s))
	}
	//> Longest first: a value and its prefix-sharing forms mask fully.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return bytes.Compare(out[i], out[j]) < 0
	})
	return out
}

// MaskWriter replaces patterns in a byte stream with MaskMarker. Matches
// split across writes are handled: a tail that may begin a pattern is held
// until more data arrives or Close.
type MaskWriter struct {
	mu      sync.Mutex
	w       io.Writer
	pats    [][]byte
	pending []byte
}

func NewMaskWriter(w io.Writer, patterns [][]byte) *MaskWriter {
	return &MaskWriter{w: w, pats: patterns}
}

func (m *MaskWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending = append(m.pending, p...)
	if err := m.flush(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes the held tail.
func (m *MaskWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flush(true)
}

func (m *MaskWriter) flush(final bool) error {
	buf := m.pending
	var out bytes.Buffer
	i := 0
scan:
	for i < len(buf) {
		rest := buf[i:]
		for _, p := range m.pats {
			if bytes.HasPrefix(rest, p) {
				out.WriteString(MaskMarker)
				i += len(p)
				continue scan
			}
		}
		if !final {
			for _, p := range m.pats {
				if len(rest) < len(p) && bytes.HasPrefix(p, rest) {
					break scan
				}
			}
		}
		out.WriteByte(buf[i])
		i++
	}
	m.pending = append(m.pending[:0], buf[i:]...)
	if out.Len() == 0 {
		return nil
	}
	_, err := m.w.Write(out.Bytes())
	return err
}

// MaskString masks a complete string.
func MaskString(s string, patterns [][]byte) string {
	var b bytes.Buffer
	m := NewMaskWriter(&b, patterns)
	_, _ = m.Write([]byte(s))
	_ = m.Close()
	return b.String()
}
