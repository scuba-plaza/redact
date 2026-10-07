package store

import (
	"slices"
	"strings"
	"testing"

	"github.com/scuba-plaza/redact/internal/token"
)

func TestEncodeIsDeterministicAndRoundTrips(t *testing.T) {
	s := New()
	mustSet(t, s, "B", "bravo")
	mustSet(t, s, "A", "alpha")
	mustSet(t, s, "A", "alpha2")
	s.Recipients = []string{"z", "a", "z"}
	enc := s.Encode()
	if string(enc) != string(s.Clone().Encode()) {
		t.Fatal("encoding is not deterministic")
	}
	back, err := Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(s) {
		t.Fatalf("round trip changed the store:\n%s\n%s", enc, back.Encode())
	}
	if !strings.Contains(string(enc), `"version": 1`) || !strings.Contains(string(enc), `"recipients": [
    "a",
    "z"
  ]`) {
		t.Fatalf("unexpected encoding:\n%s", enc)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"bad json":      `{`,
		"wrong version": `{"version":2,"values":{}}`,
		"unknown field": `{"version":1,"values":{},"extra":1}`,
		"bad name":      `{"version":1,"values":{"lower":"value"}}`,
		"bad retired":   `{"version":1,"values":{},"retired":{"a":["xyz"]}}`,
	}
	for name, in := range cases {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestInvalidValuesLoadButCannotBeWritten(t *testing.T) {
	s, err := Decode([]byte(`{"version":1,"values":{"A":"ab","B":"fine"},"retired":{"C":["xREDACTED[D]y"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Validate()
	if err == nil || !strings.Contains(err.Error(), "redact set A") || !strings.Contains(err.Error(), "redact unset --forget C") {
		t.Fatalf("got %v", err)
	}
	if _, err := s.Set("A", "repaired"); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired["A"]) != 0 {
		t.Fatal("an invalid old value was retired")
	}
	s.Unset("C", true)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSetRetiresOldValues(t *testing.T) {
	s := New()
	if changed := mustSet(t, s, "PW", "first"); !changed {
		t.Fatal("expected a change")
	}
	if changed := mustSet(t, s, "PW", "first"); changed {
		t.Fatal("expected no change")
	}
	mustSet(t, s, "PW", "second")
	mustSet(t, s, "PW", "third")
	if !slices.Equal(s.Retired["PW"], []string{"first", "second"}) {
		t.Fatalf("retired %v", s.Retired["PW"])
	}
	mustSet(t, s, "PW", "first")
	if !slices.Equal(s.Retired["PW"], []string{"second", "third"}) {
		t.Fatalf("a value that came back should leave the retired list: %v", s.Retired["PW"])
	}
}

func TestSetValidates(t *testing.T) {
	s := New()
	for _, c := range [][2]string{{"lower", "value"}, {"A", "ab"}, {"A", "aREDACTED[B]"}, {"A", "REDACTED[x"}} {
		if _, err := s.Set(c[0], c[1]); err == nil {
			t.Errorf("Set(%q, %q) should fail", c[0], c[1])
		}
	}
	if len(s.Values) != 0 {
		t.Fatal("a rejected value was stored")
	}
}

func TestUnset(t *testing.T) {
	s := New()
	mustSet(t, s, "A", "alpha")
	if !s.Unset("A", false) {
		t.Fatal("expected A to exist")
	}
	if _, ok := s.Values["A"]; ok || !slices.Equal(s.Retired["A"], []string{"alpha"}) {
		t.Fatalf("unset should retire: %+v", s)
	}
	mustSet(t, s, "B", "bravo")
	mustSet(t, s, "B", "bravo2")
	if !s.Unset("B", true) {
		t.Fatal("expected B to exist")
	}
	if _, ok := s.Retired["B"]; ok {
		t.Fatal("forget should drop retired values")
	}
	if s.Unset("NOPE", false) {
		t.Fatal("unset of a missing name reported a change")
	}
}

func TestLexiconPrefersCurrentValues(t *testing.T) {
	s := New()
	mustSet(t, s, "A", "shared")
	mustSet(t, s, "A", "alpha")
	mustSet(t, s, "B", "shared")
	res, err := token.Tokenise([]byte("shared alpha"), s.Lexicon())
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Clean) != "REDACTED[B] REDACTED[A]" {
		t.Fatalf("got %q", res.Clean)
	}
}

func TestUnionLexiconMapsOldValuesToTheirNames(t *testing.T) {
	before := New()
	mustSet(t, before, "A", "alpha")
	after := before.Clone()
	after.Unset("A", true)
	res, err := token.Tokenise([]byte("alpha"), UnionLexicon(after, before))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Clean) != "REDACTED[A]" {
		t.Fatalf("got %q", res.Clean)
	}
}

func TestSecrets(t *testing.T) {
	s := New()
	mustSet(t, s, "A", "one")
	mustSet(t, s, "A", "two")
	got := s.Secrets()
	want := []Secret{{Name: "A", Value: "two"}, {Name: "A", Value: "one", Retired: true}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if s.RetiredCount() != 1 {
		t.Fatal("retired count")
	}
}

func mustSet(t *testing.T, s *Store, name, value string) bool {
	t.Helper()
	changed, err := s.Set(name, value)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}
