package token

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	Prefix      = "REDACTED["
	Suffix      = "]"
	MinValueLen = 3
)

var (
	Pattern     = regexp.MustCompile(`REDACTED\[([A-Z][A-Z0-9_]*)\]`)
	namePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	prefix      = []byte(Prefix)
)

func ValidName(name string) bool {
	return namePattern.MatchString(name)
}

func CheckValue(value string) error {
	switch {
	case len(value) < MinValueLen:
		return fmt.Errorf("must be at least %d bytes", MinValueLen)
	case !utf8.ValidString(value):
		return errors.New("must be valid UTF-8")
	case strings.IndexByte(value, 0) >= 0:
		return errors.New("must not contain NUL bytes")
	case strings.Contains(value, Prefix):
		return fmt.Errorf("must not contain %q", Prefix)
	}
	return nil
}

func Format(name string) string {
	return Prefix + name + Suffix
}

func Names(text []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range Pattern.FindAllSubmatch(text, -1) {
		n := string(m[1])
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

type Lines []int

func NewLines(text []byte) Lines {
	starts := Lines{0}
	for i, c := range text {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func (l Lines) Position(text []byte, off int) (int, int) {
	i, found := slices.BinarySearch(l, off)
	if !found {
		i--
	}
	return i + 1, utf8.RuneCount(text[l[i]:off]) + 1
}

func DescribeMalformed(lines []int) string {
	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = fmt.Sprint(l)
	}
	word := "line "
	if len(lines) > 1 {
		word = "lines "
	}
	return fmt.Sprintf("malformed %s…%s marker on %s%s; names use A-Z, 0-9 and _, as in %s", Prefix, Suffix, word, strings.Join(parts, ", "), Format("SYS_USER"))
}

func Malformed(text []byte) []int {
	valid := Pattern.FindAllIndex(text, -1)
	var lines Lines
	var out []int
	k := 0
	for off := 0; ; {
		i := bytes.Index(text[off:], prefix)
		if i < 0 {
			break
		}
		at := off + i
		for k < len(valid) && valid[k][0] < at {
			k++
		}
		if k >= len(valid) || valid[k][0] != at {
			if lines == nil {
				lines = NewLines(text)
			}
			line, _ := lines.Position(text, at)
			if len(out) == 0 || out[len(out)-1] != line {
				out = append(out, line)
			}
		}
		off = at + len(prefix)
	}
	return out
}

func Mask(text []byte) []byte {
	out := bytes.Clone(text)
	for _, loc := range Pattern.FindAllIndex(text, -1) {
		for j := loc[0]; j < loc[1]; j++ {
			out[j] = 0
		}
	}
	return out
}

type entry struct {
	value []byte
	token []byte
	name  string
}

type Lexicon struct {
	byFirst map[byte][]entry
	entries []entry
	current map[string]string
}

func NewLexicon(valueToName, current map[string]string) *Lexicon {
	lx := &Lexicon{byFirst: map[byte][]entry{}, current: current}
	for v, n := range valueToName {
		if v == "" {
			continue
		}
		e := entry{value: []byte(v), token: []byte(Format(n)), name: n}
		lx.byFirst[v[0]] = append(lx.byFirst[v[0]], e)
		lx.entries = append(lx.entries, e)
	}
	for k := range lx.byFirst {
		slices.SortFunc(lx.byFirst[k], func(a, b entry) int {
			if c := cmp.Compare(len(b.value), len(a.value)); c != 0 {
				return c
			}
			return bytes.Compare(a.value, b.value)
		})
	}
	slices.SortFunc(lx.entries, func(a, b entry) int { return bytes.Compare(a.value, b.value) })
	return lx
}

type AmbiguityError struct {
	Line, Column int
	Reason       string
}

func (e *AmbiguityError) Error() string {
	return fmt.Sprintf("line %d, column %d: %s", e.Line, e.Column, e.Reason)
}

type LeakError struct {
	Line, Column int
	Name         string
	Self         bool
}

func (e *LeakError) Error() string {
	if e.Self {
		return fmt.Sprintf("line %d, column %d: two copies of the value of %s overlap here, so part of one would be committed in clear", e.Line, e.Column, e.Name)
	}
	return fmt.Sprintf("line %d, column %d: the value of %s overlaps another stored value here, so part of it would be committed in clear", e.Line, e.Column, e.Name)
}

const (
	reasonFormsMarker = "a value would form a new " + Prefix + "…" + Suffix + " marker with the text around it"
	reasonRunsInto    = "a stored value runs into a " + Prefix + "…" + Suffix + " marker"
	reasonMerges      = "a token would merge with the text around it"
	reasonUnstable    = "the text does not settle: replacing retired values keeps changing it"
)

type problem struct {
	off    int
	reason string
	leak   string
	self   bool
}

type edit struct {
	dst, dstEnd, src, srcEnd int
	name                     string
}

type mapping []edit

func (m mapping) back(off int) int {
	i := sort.Search(len(m), func(i int) bool { return m[i].dstEnd > off })
	if i < len(m) && m[i].dst <= off {
		return m[i].src
	}
	if i == 0 {
		return off
	}
	return m[i-1].srcEnd + off - m[i-1].dstEnd
}

type Result struct {
	Clean    []byte
	Hydrated []byte
	Missing  []string
}

const maxRounds = 8

func back(off int, chain []mapping) int {
	for i := len(chain) - 1; i >= 0; i-- {
		off = chain[i].back(off)
	}
	return off
}

func Tokenise(text []byte, lx *Lexicon) (*Result, error) {
	fail := func(p *problem) error {
		line, col := NewLines(text).Position(text, min(p.off, len(text)))
		if p.leak != "" {
			return &LeakError{Line: line, Column: col, Name: p.leak, Self: p.self}
		}
		return &AmbiguityError{Line: line, Column: col, Reason: p.reason}
	}
	if p := lx.overlap(text, pairs(Pattern.FindAllIndex(text, -1))); p != nil {
		return nil, fail(p)
	}
	cur, hm, kept, _ := hydrate(text, lx.current)
	chain := []mapping{hm}
	for range maxRounds {
		if at, ok := mismatch(pairs(Pattern.FindAllIndex(cur, -1)), kept); ok {
			return nil, fail(&problem{off: back(at, chain), reason: reasonFormsMarker})
		}
		out, tm, p := lx.tokenise(cur)
		if p != nil {
			p.off = back(p.off, chain)
			return nil, fail(p)
		}
		next, fm, nextKept, missing := hydrate(out, lx.current)
		if bytes.Equal(next, cur) {
			return &Result{Clean: out, Hydrated: cur, Missing: missing}, nil
		}
		chain = append(chain, tm, fm)
		cur, kept = next, nextKept
	}
	return nil, fail(&problem{off: back(0, chain), reason: reasonUnstable})
}

func (lx *Lexicon) overlap(text []byte, markers [][2]int) *problem {
	if len(markers) == 0 {
		return nil
	}
	for _, en := range lx.entries {
		for off := 0; ; {
			i := bytes.Index(text[off:], en.value)
			if i < 0 {
				break
			}
			s, e := off+i, off+i+len(en.value)
			k := sort.Search(len(markers), func(k int) bool { return markers[k][1] > s })
			for ; k < len(markers) && markers[k][0] < e; k++ {
				inside := s >= markers[k][0] && e <= markers[k][1]
				if !inside {
					return &problem{off: max(s, markers[k][0]), reason: reasonRunsInto}
				}
			}
			off = s + 1
		}
	}
	return nil
}

func mismatch(found, want [][2]int) (int, bool) {
	for k := 0; k < len(found) || k < len(want); k++ {
		switch {
		case k >= len(found):
			return want[k][0], true
		case k >= len(want):
			return found[k][0], true
		case found[k][0] != want[k][0] || found[k][1] != want[k][1]:
			return min(found[k][0], want[k][0]), true
		}
	}
	return 0, false
}

func pairs(locs [][]int) [][2]int {
	out := make([][2]int, len(locs))
	for i, l := range locs {
		out[i] = [2]int{l[0], l[1]}
	}
	return out
}

func (lx *Lexicon) tokenise(text []byte) ([]byte, mapping, *problem) {
	existing := pairs(Pattern.FindAllIndex(text, -1))
	if p := lx.overlap(text, existing); p != nil {
		return nil, nil, p
	}
	out := make([]byte, 0, len(text))
	var spans [][2]int
	var m mapping
	next := 0
	for i := 0; i < len(text); {
		if next < len(existing) && existing[next][0] == i {
			end := existing[next][1]
			spans = append(spans, [2]int{len(out), len(out) + end - i})
			out = append(out, text[i:end]...)
			i = end
			next++
			continue
		}
		limit := len(text)
		if next < len(existing) {
			limit = existing[next][0]
		}
		matched := false
		for _, e := range lx.byFirst[text[i]] {
			if i+len(e.value) <= limit && bytes.HasPrefix(text[i:], e.value) {
				spans = append(spans, [2]int{len(out), len(out) + len(e.token)})
				m = append(m, edit{dst: len(out), dstEnd: len(out) + len(e.token), src: i, srcEnd: i + len(e.value), name: e.name})
				out = append(out, e.token...)
				i += len(e.value)
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, text[i])
			i++
		}
	}
	if at, ok := mismatch(pairs(Pattern.FindAllIndex(out, -1)), spans); ok {
		return nil, nil, &problem{off: m.back(at), reason: reasonMerges}
	}
	if p := lx.uncovered(text, existing, m); p != nil {
		return nil, nil, p
	}
	return out, m, nil
}

func (lx *Lexicon) uncovered(text []byte, existing [][2]int, m mapping) *problem {
	covered := make([]bool, len(text))
	for _, e := range existing {
		for j := e[0]; j < e[1]; j++ {
			covered[j] = true
		}
	}
	for _, ed := range m {
		for j := ed.src; j < ed.srcEnd; j++ {
			covered[j] = true
		}
	}
	for _, en := range lx.entries {
		for off := 0; ; {
			i := bytes.Index(text[off:], en.value)
			if i < 0 {
				break
			}
			s := off + i
			if slices.Contains(covered[s:s+len(en.value)], false) {
				return &problem{off: s, leak: en.name, self: overlapsOnlyItself(m, s, s+len(en.value), en.name)}
			}
			off = s + 1
		}
	}
	return nil
}

func overlapsOnlyItself(m mapping, s, e int, name string) bool {
	k := sort.Search(len(m), func(k int) bool { return m[k].srcEnd > s })
	found := false
	for ; k < len(m) && m[k].src < e; k++ {
		if m[k].name != name {
			return false
		}
		found = true
	}
	return found
}

func hydrate(text []byte, values map[string]string) ([]byte, mapping, [][2]int, []string) {
	locs := Pattern.FindAllSubmatchIndex(text, -1)
	out := make([]byte, 0, len(text))
	var m mapping
	var kept [][2]int
	missing := map[string]bool{}
	prev := 0
	for _, loc := range locs {
		out = append(out, text[prev:loc[0]]...)
		name := string(text[loc[2]:loc[3]])
		if v, ok := values[name]; ok {
			m = append(m, edit{dst: len(out), dstEnd: len(out) + len(v), src: loc[0], srcEnd: loc[1]})
			out = append(out, v...)
		} else {
			kept = append(kept, [2]int{len(out), len(out) + loc[1] - loc[0]})
			out = append(out, text[loc[0]:loc[1]]...)
			missing[name] = true
		}
		prev = loc[1]
	}
	out = append(out, text[prev:]...)
	names := make([]string, 0, len(missing))
	for n := range missing {
		names = append(names, n)
	}
	slices.Sort(names)
	return out, m, kept, names
}

func Hydrate(text []byte, values map[string]string) ([]byte, []string) {
	out, _, _, missing := hydrate(text, values)
	return out, missing
}
