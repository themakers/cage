package libcage

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Line-based merge of text secrets, git style: non-overlapping changes of
// both sides apply, overlapping ones are written with conflict markers.

const (
	markerLocal = "<<<<<<< local"
	markerSep   = "======="
	markerStore = ">>>>>>> store"
)

// isText — secrets that can be merged line by line.
func isText(b []byte) bool {
	return utf8.Valid(b) && !strings.ContainsRune(string(b), 0)
}

// hasConflictMarkers — a plaintext still has unresolved cage conflicts.
func hasConflictMarkers(b []byte) bool {
	for _, l := range strings.Split(string(b), "\n") {
		if l == markerLocal || l == markerStore {
			return true
		}
	}
	return false
}

type lines struct {
	l           []string
	trailingEOL bool
}

func splitLines(b []byte) lines {
	s := string(b)
	if s == "" {
		return lines{}
	}
	eol := strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	return lines{l: strings.Split(s, "\n"), trailingEOL: eol}
}

// lcsMatch returns, for each line of a, the index of the matched line of b
// in a longest common subsequence (-1 if unmatched).
func lcsMatch(a, b []string) []int {
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	match := make([]int, n)
	for i := range match {
		match[i] = -1
	}
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case a[i] == b[j]:
			match[i] = j
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return match
}

func equalLines(a, b []string) bool {
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

// MergeResult — merged text and the conflicting chunks (local/store lines).
type MergeResult struct {
	Text      []byte
	Conflicts [][2][]string
}

// merge3 merges local and store against base. Without a base (base == nil)
// the common lines of local and store act as the base and every differing
// chunk is a conflict: nothing is guessed, nothing is lost.
func merge3(base, local, store []byte) MergeResult {
	o, t := splitLines(local), splitLines(store)
	strict := base == nil
	var b []string
	if strict {
		mo := lcsMatch(o.l, t.l)
		for i, j := range mo {
			if j >= 0 {
				b = append(b, o.l[i])
			}
		}
	} else {
		b = splitLines(base).l
	}
	mo, mt := lcsMatch(b, o.l), lcsMatch(b, t.l)

	var out []string
	var res MergeResult
	emit := func(bb, oo, tt []string) {
		switch {
		case equalLines(oo, tt):
			out = append(out, oo...)
		case !strict && equalLines(oo, bb):
			out = append(out, tt...)
		case !strict && equalLines(tt, bb):
			out = append(out, oo...)
		default:
			out = append(out, markerLocal)
			out = append(out, oo...)
			out = append(out, markerSep)
			out = append(out, tt...)
			out = append(out, markerStore)
			res.Conflicts = append(res.Conflicts, [2][]string{oo, tt})
		}
	}

	bi, oi, ti := 0, 0, 0
	for bi < len(b) {
		if mo[bi] == oi && mt[bi] == ti {
			out = append(out, b[bi])
			bi, oi, ti = bi+1, oi+1, ti+1
			continue
		}
		// Next base line matched on both sides — the end of this chunk.
		next := bi
		for next < len(b) && !(mo[next] >= 0 && mt[next] >= 0) {
			next++
		}
		oe, te := len(o.l), len(t.l)
		if next < len(b) {
			oe, te = mo[next], mt[next]
		}
		emit(b[bi:next], o.l[oi:oe], t.l[ti:te])
		bi, oi, ti = next, oe, te
	}
	if oi < len(o.l) || ti < len(t.l) {
		emit(nil, o.l[oi:], t.l[ti:])
	}

	text := strings.Join(out, "\n")
	if len(out) > 0 && (o.trailingEOL || t.trailingEOL) {
		text += "\n"
	}
	res.Text = []byte(text)
	return res
}

// conflictKeys — variable names in conflicting chunks (for reports; never
// values).
func conflictKeys(res MergeResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range res.Conflicts {
		for _, side := range c {
			for _, l := range side {
				if k := parseDotenvLine(l).Key; k != "" && !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
	}
	return out
}

// resolveMarkers keeps one side in every conflict chunk.
func resolveMarkers(b []byte, keepLocal bool) ([]byte, error) {
	ls := splitLines(b)
	var out []string
	state := 0 // 0 outside, 1 local part, 2 store part
	for _, l := range ls.l {
		switch {
		case l == markerLocal && state == 0:
			state = 1
		case l == markerSep && state == 1:
			state = 2
		case l == markerStore && state == 2:
			state = 0
		case state == 0 || (state == 1 && keepLocal) || (state == 2 && !keepLocal):
			out = append(out, l)
		}
	}
	if state != 0 {
		return nil, fmt.Errorf("unbalanced conflict markers")
	}
	text := strings.Join(out, "\n")
	if len(out) > 0 && ls.trailingEOL {
		text += "\n"
	}
	return []byte(text), nil
}
