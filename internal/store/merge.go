package store

import (
	"maps"
	"slices"
)

type Conflict struct {
	Name     string
	KeptOurs bool
}

func (s *Store) knows(name, value string) bool {
	return s.Values[name] == value || slices.Contains(s.Retired[name], value)
}

func Merge(base, ours, theirs *Store) (*Store, []Conflict) {
	out := New()
	var conflicts []Conflict
	names := map[string]bool{}
	for _, s := range []*Store{base, ours, theirs} {
		for n := range s.Values {
			names[n] = true
		}
	}
	for _, n := range slices.Sorted(maps.Keys(names)) {
		b, inB := base.Values[n]
		o, inO := ours.Values[n]
		t, inT := theirs.Values[n]
		switch {
		case inO == inT && o == t:
			if inO {
				out.Values[n] = o
			}
		case inO == inB && o == b:
			if inT {
				out.Values[n] = t
			}
		case inT == inB && t == b:
			if inO {
				out.Values[n] = o
			}
		default:
			conflicts = append(conflicts, Conflict{Name: n, KeptOurs: inO})
			if inO {
				out.Values[n] = o
			} else {
				out.Values[n] = t
			}
		}
	}
	forgotten := func(name, value string) bool {
		return base.knows(name, value) && (!ours.knows(name, value) || !theirs.knows(name, value))
	}
	for _, s := range []*Store{base, ours, theirs} {
		for _, sec := range s.Secrets() {
			if out.Values[sec.Name] != sec.Value && !forgotten(sec.Name, sec.Value) {
				out.retire(sec.Name, sec.Value)
			}
		}
	}
	out.Recipients = mergeSets(base.Recipients, ours.Recipients, theirs.Recipients)
	return out, conflicts
}

func mergeSets(base, ours, theirs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range append(append(slices.Clone(ours), theirs...), base...) {
		if seen[r] {
			continue
		}
		seen[r] = true
		inB, inO, inT := slices.Contains(base, r), slices.Contains(ours, r), slices.Contains(theirs, r)
		keep := inO
		if inO != inT && inO == inB {
			keep = inT
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}
