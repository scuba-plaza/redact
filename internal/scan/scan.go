package scan

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
)

const (
	binarySniff       = 8000
	minLineNeedle     = 8
	minUnboundedValue = 12
	minBinaryNeedle   = 8
)

type Finding struct {
	Path        string `json:"path"`
	Commit      string `json:"commit,omitempty"`
	Blob        string `json:"blob,omitempty"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Match       string `json:"match"`
	start, end  int
	priority    int
	plain       string
}

type needle struct {
	text  []byte
	plain string
	desc  string
	id    string
	wide  bool
}

type Scanner struct {
	needles []needle
	binary  []needle
	allow   []*regexp.Regexp
	reveal  bool
}

func utf16Forms(s string) [][]byte {
	units := utf16.Encode([]rune(s))
	le := make([]byte, 0, 2*len(units))
	be := make([]byte, 0, 2*len(units))
	for _, u := range units {
		le = binary.LittleEndian.AppendUint16(le, u)
		be = binary.BigEndian.AppendUint16(be, u)
	}
	return [][]byte{le, be}
}

type Options struct {
	Secrets []store.Secret
	Allow   []*regexp.Regexp
	Reveal  bool
}

func New(opts Options) *Scanner {
	s := &Scanner{allow: opts.Allow, reveal: opts.Reveal}
	seen := map[string]bool{}
	add := func(text, desc, id string) {
		if len(text) < token.MinValueLen || seen[text] {
			return
		}
		seen[text] = true
		n := needle{text: []byte(text), plain: text, desc: desc, id: id}
		s.needles = append(s.needles, n)
		if len(text) >= minBinaryNeedle {
			s.binary = append(s.binary, n)
			for _, wide := range utf16Forms(text) {
				s.binary = append(s.binary, needle{text: wide, plain: text, desc: desc + " (UTF-16)", id: id, wide: true})
			}
		}
	}
	for _, sec := range opts.Secrets {
		desc, id := "value of "+sec.Name, "value"
		if sec.Retired {
			desc, id = "retired value of "+sec.Name, "retired-value"
		}
		add(sec.Value, desc, id)
	}
	for _, sec := range opts.Secrets {
		if !strings.Contains(sec.Value, "\n") {
			continue
		}
		desc, id := "a line of "+sec.Name, "value"
		if sec.Retired {
			desc, id = "a line of retired "+sec.Name, "retired-value"
		}
		for _, line := range strings.Split(sec.Value, "\n") {
			line = strings.TrimSpace(line)
			if len(line) >= minLineNeedle {
				add(line, desc, id)
			}
		}
	}
	slices.SortStableFunc(s.needles, func(a, b needle) int { return cmp.Compare(len(b.text), len(a.text)) })
	return s
}

func ParseAllow(r io.Reader) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, err := regexp.Compile(`^(?:` + line + `)$`)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, re)
	}
	return out, sc.Err()
}

func Binary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), binarySniff)], 0) >= 0
}

func (s *Scanner) Scan(path string, data []byte, strict bool) []Finding {
	binary := Binary(data)
	needles := s.needles
	if binary {
		strict = true
		needles = s.binary
	}
	var found []Finding
	masked := token.Mask(data)
	for _, n := range needles {
		unbounded := strict || len(n.text) >= minUnboundedValue
		for off := 0; off < len(masked); {
			i := bytes.Index(masked[off:], n.text)
			if i < 0 {
				break
			}
			start, end := off+i, off+i+len(n.text)
			off = start + 1
			if !unbounded && (ascii(before(masked, start)) || ascii(after(masked, end))) {
				continue
			}
			found = append(found, Finding{Rule: n.id, Description: n.desc, start: start, end: end, priority: 0, plain: n.plain})
		}
	}
	for _, r := range builtinRules {
		if binary {
			break
		}
		for _, loc := range r.re.FindAllIndex(masked, -1) {
			start, end := loc[0], loc[1]
			if r.accept != nil && !r.accept(masked, start, end) {
				continue
			}
			match := string(masked[start:end])
			if r.allowed != nil && r.allowed(match) {
				continue
			}
			if s.allowed(match) {
				continue
			}
			found = append(found, Finding{Rule: r.id, Description: r.desc, start: start, end: end, priority: r.priority})
		}
	}
	if len(found) == 0 {
		return nil
	}
	slices.SortStableFunc(found, func(a, b Finding) int {
		if c := cmp.Compare(a.priority, b.priority); c != 0 {
			return c
		}
		return cmp.Compare(a.start, b.start)
	})
	covered := make([]bool, len(data))
	var kept []Finding
	for _, f := range found {
		if slices.Contains(covered[f.start:f.end], true) {
			continue
		}
		for j := f.start; j < f.end; j++ {
			covered[j] = true
		}
		kept = append(kept, f)
	}
	slices.SortFunc(kept, func(a, b Finding) int { return cmp.Compare(a.start, b.start) })
	lines := token.NewLines(data)
	for i := range kept {
		f := &kept[i]
		f.Path = path
		f.Line, f.Column = lines.Position(data, f.start)
		f.Match = string(data[f.start:f.end])
		if f.plain != "" {
			f.Match = f.plain
		}
		if !s.reveal {
			f.Match = Mask(f.Match)
		}
	}
	return kept
}

func (s *Scanner) allowed(match string) bool {
	for _, re := range s.allow {
		if re.MatchString(match) {
			return true
		}
	}
	return false
}

func Mask(s string) string {
	n := utf8.RuneCountInString(s)
	show := min(n/4, 3)
	runes := []rune(s)
	return fmt.Sprintf("%s… (%d chars)", string(runes[:show]), n)
}

type Item struct {
	Path   string
	Blob   string
	Commit string
	Data   []byte
	Strict bool
}

type Source func(ctx context.Context, emit func(Item) error) error

func (s *Scanner) Run(ctx context.Context, src Source) ([]Finding, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	items := make(chan Item, 64)
	var srcErr error
	go func() {
		defer close(items)
		srcErr = src(ctx, func(it Item) error {
			select {
			case items <- it:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	var mu sync.Mutex
	var all []Finding
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range items {
				fs := s.Scan(it.Path, it.Data, it.Strict)
				for i := range fs {
					fs[i].Blob, fs[i].Commit = it.Blob, it.Commit
				}
				if len(fs) > 0 {
					mu.Lock()
					all = append(all, fs...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if srcErr != nil {
		return nil, srcErr
	}
	Sort(all)
	return all, nil
}

func Sort(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(a.Path, b.Path),
			cmp.Compare(a.Blob, b.Blob),
			cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Column, b.Column),
			cmp.Compare(a.Rule, b.Rule),
		)
	})
}
