package token

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func lex(pairs ...string) (*Lexicon, map[string]string) {
	v2n := map[string]string{}
	n2v := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v2n[pairs[i+1]] = pairs[i]
		n2v[pairs[i]] = pairs[i+1]
	}
	return NewLexicon(v2n, n2v), n2v
}

func clean(t *testing.T, text string, lx *Lexicon) *Result {
	t.Helper()
	res, err := Tokenise([]byte(text), lx)
	if err != nil {
		t.Fatalf("Tokenise(%q): %v", text, err)
	}
	return res
}

func TestTokenise(t *testing.T) {
	cases := []struct {
		name  string
		pairs []string
		in    string
		want  string
	}{
		{"simple", []string{"USER", "alice"}, `user = "alice";`, `user = "REDACTED[USER]";`},
		{"adjacent to letters", []string{"USER", "alice"}, `aliceabc`, `REDACTED[USER]abc`},
		{"inside a word", []string{"USER", "alice"}, `malice`, `mREDACTED[USER]`},
		{"longest first", []string{"A", "abc", "B", "abcdef"}, `abcdef abc`, `REDACTED[B] REDACTED[A]`},
		{"value inside a marker name", []string{"V", "USER"}, `REDACTED[GIT_USER_1] USER`, `REDACTED[GIT_USER_1] REDACTED[V]`},
		{"multi-line", []string{"SSH", "Host a\n  User b"}, "x\nHost a\n  User b\ny", "x\nREDACTED[SSH]\ny"},
		{"no values", nil, "alice", "alice"},
		{"handles and emails", []string{"H", "@alice", "E", "alice@corp.example"}, "@alice <alice@corp.example>", "REDACTED[H] <REDACTED[E]>"},
		{"brackets in values", []string{"ADDR", "[::1]:22"}, "listen [::1]:22;", "listen REDACTED[ADDR];"},
		{"unterminated marker", []string{"U", "alice"}, "REDACTED[ABalice", "REDACTED[ABREDACTED[U]"},
		{"marker without a name", []string{"U", "alice"}, "REDACTED[alice]", "REDACTED[REDACTED[U]]"},
		{"repeated", []string{"U", "aaa"}, "aaaaaa", "REDACTED[U]REDACTED[U]"},
		{"markers are normalised to what a checkout shows", []string{"DOMAIN", "corp.example", "EMAIL", "alice@corp.example"}, `alice@REDACTED[DOMAIN]`, `REDACTED[EMAIL]`},
		{"missing values keep their marker", []string{"U", "alice"}, "REDACTED[NOPE] alice", "REDACTED[NOPE] REDACTED[U]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lx, values := lex(c.pairs...)
			res := clean(t, c.in, lx)
			if string(res.Clean) != c.want {
				t.Fatalf("Clean = %q, want %q", res.Clean, c.want)
			}
			want, _ := Hydrate([]byte(c.in), values)
			if !bytes.Equal(res.Hydrated, want) {
				t.Fatalf("Hydrated = %q, want %q", res.Hydrated, want)
			}
		})
	}
}

func TestTokeniseRewritesRetiredValues(t *testing.T) {
	lx := NewLexicon(map[string]string{"old-secret": "PW", "new-secret": "PW"}, map[string]string{"PW": "new-secret"})
	res := clean(t, "pw = old-secret\nx = REDACTED[GONE]\n", lx)
	if string(res.Clean) != "pw = REDACTED[PW]\nx = REDACTED[GONE]\n" {
		t.Fatalf("clean %q", res.Clean)
	}
	if string(res.Hydrated) != "pw = new-secret\nx = REDACTED[GONE]\n" || !slices.Equal(res.Missing, []string{"GONE"}) {
		t.Fatalf("hydrated %q missing %v", res.Hydrated, res.Missing)
	}
}

func TestTokeniseRefuses(t *testing.T) {
	cases := []struct {
		name    string
		values  map[string]string
		current map[string]string
		in      string
		reason  string
		line    int
		col     int
	}{
		{
			name:    "a value running into a marker",
			values:  map[string]string{"secretREDACTED": "S", "abc": "A"},
			current: map[string]string{"S": "secretREDACTED", "A": "abc"},
			in:      "first\nsecretREDACTED[A]",
			reason:  reasonRunsInto, line: 2, col: 7,
		},
		{
			name:    "a value running into a marker after hydration",
			values:  map[string]string{"secretRED": "S", "secret": "A"},
			current: map[string]string{"S": "secretRED", "A": "secret"},
			in:      "x REDACTED[A]REDACTED[M]",
			reason:  reasonRunsInto, line: 1, col: 14,
		},
		{
			name:    "a value forming a new marker",
			values:  map[string]string{"XY]": "A"},
			current: map[string]string{"A": "XY]"},
			in:      "line one\nREDACTED[REDACTED[A]",
			reason:  reasonFormsMarker, line: 2, col: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Tokenise([]byte(c.in), NewLexicon(c.values, c.current))
			var amb *AmbiguityError
			if !errors.As(err, &amb) {
				t.Fatalf("got %v", err)
			}
			if amb.Reason != c.reason || amb.Line != c.line || amb.Column != c.col {
				t.Fatalf("got %+v", amb)
			}
		})
	}
}

func TestOverlappingValuesAreRefused(t *testing.T) {
	cases := []struct {
		values map[string]string
		in     string
		line   int
		col    int
	}{
		{map[string]string{"HOST": "db.lan", "PASS": "n0-SuperSecretPassword"}, `url = "db.laREDACTED[PASS]";`, 1, 13},
		{map[string]string{"A": "box", "B": "xS3cretValue"}, "x\nboxS3cretValue", 2, 3},
		{map[string]string{"U": "aaa"}, "aaaaaaa", 1, 5},
	}
	for _, c := range cases {
		v2n := map[string]string{}
		for n, v := range c.values {
			v2n[v] = n
		}
		_, err := Tokenise([]byte(c.in), NewLexicon(v2n, c.values))
		var leak *LeakError
		if !errors.As(err, &leak) || leak.Line != c.line || leak.Column != c.col {
			t.Fatalf("%q: got %v", c.in, err)
		}
		if self := len(c.values) == 1; leak.Self != self {
			t.Fatalf("%q: self overlap reported as %v: %v", c.in, leak.Self, err)
		}
	}
}

func TestPositionsReferToTheWorkingTree(t *testing.T) {
	lx := NewLexicon(map[string]string{"one\ntwo\nthree": "M", "XY]": "A"}, map[string]string{"M": "one\ntwo\nthree", "A": "XY]"})
	_, err := Tokenise([]byte("one\ntwo\nthree\nok REDACTED[REDACTED[A]"), lx)
	var amb *AmbiguityError
	if !errors.As(err, &amb) || amb.Line != 4 || amb.Column != 4 {
		t.Fatalf("got %v", err)
	}
}

func TestCheckValue(t *testing.T) {
	for _, v := range []string{"abc", "a@b", "@alice", "alice@", "a@@b", "[::1]", "Host x\n  User y", "ünï", "REDACTED"} {
		if err := CheckValue(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	for _, v := range []string{"", "ab", "xREDACTED[A]y", "REDACTED[", "a\x00b", "\xff\xfe\xfd"} {
		if CheckValue(v) == nil {
			t.Errorf("%q should be rejected", v)
		}
	}
}

func TestHydrate(t *testing.T) {
	values := map[string]string{"A": "x[B]y", "B": "never"}
	got, missing := Hydrate([]byte("REDACTED[A] REDACTED[C] REDACTED[C] REDACTED[lower]"), values)
	if string(got) != "x[B]y REDACTED[C] REDACTED[C] REDACTED[lower]" {
		t.Fatalf("got %q", got)
	}
	if !slices.Equal(missing, []string{"C"}) {
		t.Fatalf("missing %v", missing)
	}
}

func TestNames(t *testing.T) {
	got := Names([]byte("REDACTED[B] REDACTED[A_1] REDACTED[B] REDACTED[a] REDACTED[1A] REDACTED[REDACTED[C]"))
	if !slices.Equal(got, []string{"A_1", "B", "C"}) {
		t.Fatalf("got %v", got)
	}
}

func TestMalformed(t *testing.T) {
	text := "REDACTED[sys_user]\nok REDACTED[A]\nREDACTED[\nfine\nREDACTED[B REDACTED[C]\n"
	if got := Malformed([]byte(text)); !slices.Equal(got, []int{1, 3, 5}) {
		t.Fatalf("got %v", got)
	}
	if got := Malformed([]byte("REDACTED[A] REDACTED[B_2]")); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"A", "SYS_USER", "GIT_EMAIL_1"} {
		if !ValidName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "a", "1A", "_A", "A-B", "A B", "A\tB", "Ä", "A]"} {
		if ValidName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

func TestMaskKeepsOffsets(t *testing.T) {
	in := []byte("ab REDACTED[X] cd")
	m := Mask(in)
	if len(m) != len(in) || string(m[:3]) != "ab " || string(m[14:]) != " cd" || m[3] != 0 || m[13] != 0 {
		t.Fatalf("got %q", m)
	}
}

func TestLines(t *testing.T) {
	text := []byte("one\nünï two\n")
	l := NewLines(text)
	if line, col := l.Position(text, bytes.Index(text, []byte("two"))); line != 2 || col != 5 {
		t.Fatalf("got %d:%d", line, col)
	}
	if line, col := l.Position(text, 0); line != 1 || col != 1 {
		t.Fatalf("got %d:%d", line, col)
	}
}

func FuzzTokenise(f *testing.F) {
	f.Add("user = alice; email = alice@example.com", "alice", "alice@example.com", "lice@x", "old")
	f.Add("REDACTED[A]aliceali", "ali", "alice", "xREDACTED", "REDACTED")
	f.Add("aaaa", "aa0", "aaa", "aaaa", "aaaaa")
	f.Add("REDACTED[ABalice]REDACTED[", "alice", "]RED", "ACTED[", "XY]")
	f.Add("[x] REDACTED[X]]] [[REDACTED[Y]", "[x]", "X]]", "[[R", "REDACTED[C]")
	f.Add("alice@REDACTED[A] REDACTED[REDACTED[C]", "corp.example", "alice@corp.example", "XY]", "secretRED")
	f.Add("a0aa0aa0aa000000a00a0 000", "000", "00001", "0", "0a0")
	f.Fuzz(func(t *testing.T, text, v1, v2, v3, retired string) {
		v2n := map[string]string{}
		current := map[string]string{}
		for i, v := range []string{v1, v2, v3} {
			if CheckValue(v) != nil || v2n[v] != "" {
				continue
			}
			name := string(rune('A' + i))
			v2n[v] = name
			current[name] = v
		}
		hasRetired := false
		if CheckValue(retired) == nil && v2n[retired] == "" && len(current) > 0 {
			v2n[retired] = "A"
			if _, ok := current["A"]; ok {
				hasRetired = true
			} else {
				delete(v2n, retired)
			}
		}
		lx := NewLexicon(v2n, current)
		res, err := Tokenise([]byte(text), lx)
		if err != nil {
			var amb *AmbiguityError
			var leak *LeakError
			if !errors.As(err, &amb) && !errors.As(err, &leak) {
				t.Fatalf("untyped error for %q: %v", text, err)
			}
			unstable := hasRetired && amb != nil && amb.Reason == reasonUnstable
			if amb != nil && !strings.Contains(text, Prefix) && !unstable {
				t.Fatalf("ambiguity error for text without a marker %q: %v", text, err)
			}
			return
		}
		masked := Mask(res.Clean)
		for v := range v2n {
			if bytes.Contains(masked, []byte(v)) {
				t.Fatalf("value %q is visible in %q (from %q)", v, res.Clean, text)
			}
		}
		again, err := Tokenise(res.Hydrated, lx)
		if err != nil || !bytes.Equal(again.Clean, res.Clean) || !bytes.Equal(again.Hydrated, res.Hydrated) {
			t.Fatalf("not stable under checkout: %q -> %q -> %+v (%v)", text, res.Clean, again, err)
		}
		if back, _ := Hydrate(res.Clean, current); !bytes.Equal(back, res.Hydrated) {
			t.Fatalf("Hydrated does not match a checkout: %q vs %q", back, res.Hydrated)
		}
		if !hasRetired && !strings.Contains(text, Prefix) && !bytes.Equal(res.Hydrated, []byte(text)) {
			t.Fatalf("lossy without markers or retired values: %q -> %q -> %q", text, res.Clean, res.Hydrated)
		}
	})
}
