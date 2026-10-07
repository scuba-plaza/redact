package store

import (
	"slices"
	"testing"
)

func build(t *testing.T, recipients []string, pairs ...string) *Store {
	t.Helper()
	s := New()
	for i := 0; i+1 < len(pairs); i += 2 {
		mustSet(t, s, pairs[i], pairs[i+1])
	}
	s.Recipients = recipients
	return s
}

func TestMergeCombinesIndependentChanges(t *testing.T) {
	base := build(t, []string{"r1"}, "A", "alpha", "B", "bravo", "C", "charlie")
	ours := base.Clone()
	mustSet(t, ours, "A", "alpha2")
	mustSet(t, ours, "D", "delta")
	theirs := base.Clone()
	mustSet(t, theirs, "B", "bravo2")
	theirs.Unset("C", false)
	theirs.Recipients = []string{"r1", "r2"}
	got, conflicts := Merge(base, ours, theirs)
	if len(conflicts) != 0 {
		t.Fatalf("conflicts %v", conflicts)
	}
	want := map[string]string{"A": "alpha2", "B": "bravo2", "D": "delta"}
	if len(got.Values) != len(want) {
		t.Fatalf("values %v", got.Values)
	}
	for n, v := range want {
		if got.Values[n] != v {
			t.Fatalf("%s = %q", n, got.Values[n])
		}
	}
	for n, v := range map[string]string{"A": "alpha", "B": "bravo", "C": "charlie"} {
		if !slices.Contains(got.Retired[n], v) {
			t.Fatalf("%s's old value %q was not retired: %v", n, v, got.Retired)
		}
	}
	if !slices.Equal(got.Recipients, []string{"r1", "r2"}) {
		t.Fatalf("recipients %v", got.Recipients)
	}
}

func TestMergeReportsConflictsAndKeepsBothValues(t *testing.T) {
	base := build(t, []string{"r1", "r2"}, "A", "alpha")
	ours := base.Clone()
	mustSet(t, ours, "A", "ours-value")
	ours.Recipients = []string{"r1"}
	theirs := base.Clone()
	mustSet(t, theirs, "A", "theirs-value")
	got, conflicts := Merge(base, ours, theirs)
	if !slices.Equal(conflicts, []Conflict{{Name: "A", KeptOurs: true}}) || got.Values["A"] != "ours-value" {
		t.Fatalf("%v %v", conflicts, got.Values)
	}
	if !slices.Contains(got.Retired["A"], "theirs-value") || !slices.Contains(got.Retired["A"], "alpha") {
		t.Fatalf("retired %v", got.Retired)
	}
	if !slices.Equal(got.Recipients, []string{"r1"}) {
		t.Fatalf("a recipient removed on one side came back: %v", got.Recipients)
	}
}

func TestMergeKeepsForgottenValuesForgotten(t *testing.T) {
	base := build(t, nil, "A", "alpha", "B", "bravo")
	ours := build(t, nil, "B", "bravo")
	theirs := build(t, nil, "A", "alpha", "B", "bravo2")
	got, conflicts := Merge(base, ours, theirs)
	if len(conflicts) != 0 || got.Values["B"] != "bravo2" {
		t.Fatalf("%v %v", conflicts, got.Values)
	}
	if _, ok := got.Values["A"]; ok || len(got.Retired["A"]) != 0 {
		t.Fatalf("a value forgotten on our side came back: %+v", got)
	}
	both, _ := Merge(base, build(t, nil, "B", "bravo"), build(t, nil, "B", "bravo"))
	if len(both.Retired["A"]) != 0 {
		t.Fatalf("a value both sides forgot came back: %+v", both.Retired)
	}
}

func TestMergeConflictWhereOurSideDeleted(t *testing.T) {
	base := build(t, nil, "A", "alpha")
	theirs := build(t, nil, "A", "alpha2")
	ours := New()
	ours.Retired["A"] = []string{"alpha"}
	got, conflicts := Merge(base, ours, theirs)
	if !slices.Equal(conflicts, []Conflict{{Name: "A", KeptOurs: false}}) || got.Values["A"] != "alpha2" {
		t.Fatalf("%v %v", conflicts, got.Values)
	}
}

func TestDuplicatesAreReportedNotRefused(t *testing.T) {
	s := New()
	s.Values["A"] = "same-value"
	s.Values["B"] = "same-value"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if d := s.Duplicates(); len(d) != 1 || d[0] != [2]string{"A", "B"} {
		t.Fatalf("got %v", d)
	}
}

func TestMergeWithAnEmptyBase(t *testing.T) {
	got, conflicts := Merge(New(), build(t, nil, "A", "one"), build(t, nil, "B", "two"))
	if len(conflicts) != 0 || got.Values["A"] != "one" || got.Values["B"] != "two" {
		t.Fatalf("%v %v", conflicts, got.Values)
	}
}
