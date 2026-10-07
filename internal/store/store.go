package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/scuba-plaza/redact/internal/token"
)

const Version = 1

type Store struct {
	Values     map[string]string   `json:"values"`
	Retired    map[string][]string `json:"retired"`
	Recipients []string            `json:"recipients"`
}

type document struct {
	Version int `json:"version"`
	Store
}

func New() *Store {
	return &Store{Values: map[string]string{}, Retired: map[string][]string{}}
}

func Decode(data []byte) (*Store, error) {
	var doc document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("store is not valid: %w", err)
	}
	if doc.Version != Version {
		return nil, fmt.Errorf("store version %d is not supported (this redact understands version %d)", doc.Version, Version)
	}
	s := &doc.Store
	if s.Values == nil {
		s.Values = map[string]string{}
	}
	if s.Retired == nil {
		s.Retired = map[string][]string{}
	}
	var errs []error
	for n := range s.Values {
		errs = append(errs, CheckName(n))
	}
	for n := range s.Retired {
		errs = append(errs, CheckName(n))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("store is not valid: %w", err)
	}
	return s, nil
}

func (s *Store) Encode() []byte {
	data, err := json.MarshalIndent(document{Version: Version, Store: *s.normalised()}, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

func (s *Store) normalised() *Store {
	c := s.Clone()
	for n, vs := range c.Retired {
		if len(vs) == 0 {
			delete(c.Retired, n)
		}
	}
	slices.Sort(c.Recipients)
	c.Recipients = slices.Compact(c.Recipients)
	if c.Recipients == nil {
		c.Recipients = []string{}
	}
	return c
}

func (s *Store) Clone() *Store {
	c := &Store{
		Values:     maps.Clone(s.Values),
		Retired:    make(map[string][]string, len(s.Retired)),
		Recipients: slices.Clone(s.Recipients),
	}
	if c.Values == nil {
		c.Values = map[string]string{}
	}
	for n, vs := range s.Retired {
		c.Retired[n] = slices.Clone(vs)
	}
	return c
}

func (s *Store) Equal(o *Store) bool {
	return bytes.Equal(s.Encode(), o.Encode())
}

func (s *Store) Validate() error {
	var errs []error
	for _, n := range s.Names() {
		if err := CheckEntry(n, s.Values[n]); err != nil {
			errs = append(errs, fmt.Errorf("%w (fix it with redact set %s)", err, n))
		}
	}
	for _, n := range slices.Sorted(maps.Keys(s.Retired)) {
		if !token.ValidName(n) {
			errs = append(errs, fmt.Errorf("retired name %q is not valid", n))
		}
		for _, v := range s.Retired[n] {
			if err := token.CheckValue(v); err != nil {
				errs = append(errs, fmt.Errorf("a retired value of %s %w (drop it with redact unset --forget %s)", n, err, n))
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Store) Duplicates() [][2]string {
	var out [][2]string
	seen := map[string]string{}
	for _, n := range s.Names() {
		v := s.Values[n]
		if other, dup := seen[v]; dup {
			out = append(out, [2]string{other, n})
			continue
		}
		seen[v] = n
	}
	return out
}

func CheckName(name string) error {
	if !token.ValidName(name) {
		return fmt.Errorf("name %q is not valid: use capital letters, digits and underscores, starting with a letter", name)
	}
	return nil
}

func CheckEntry(name, value string) error {
	if err := CheckName(name); err != nil {
		return err
	}
	if err := token.CheckValue(value); err != nil {
		return fmt.Errorf("value of %s %w", name, err)
	}
	return nil
}

func (s *Store) Set(name, value string) (bool, error) {
	if err := CheckEntry(name, value); err != nil {
		return false, err
	}
	if other := s.holder(value); other != "" && other != name {
		return false, fmt.Errorf("%s already holds this value; use %s instead of a second name", other, token.Format(other))
	}
	old, ok := s.Values[name]
	if ok && old == value {
		return false, nil
	}
	if ok && token.CheckValue(old) == nil {
		s.retire(name, old)
	}
	s.Retired[name] = slices.DeleteFunc(s.Retired[name], func(v string) bool { return v == value })
	s.Values[name] = value
	return true, nil
}

func (s *Store) holder(value string) string {
	for _, n := range s.Names() {
		if s.Values[n] == value {
			return n
		}
	}
	return ""
}

func (s *Store) Unset(name string, forget bool) bool {
	old, ok := s.Values[name]
	_, hadRetired := s.Retired[name]
	delete(s.Values, name)
	if forget {
		delete(s.Retired, name)
		return ok || hadRetired
	}
	if ok {
		s.retire(name, old)
	}
	return ok
}

func (s *Store) retire(name, value string) {
	if !slices.Contains(s.Retired[name], value) {
		s.Retired[name] = append(s.Retired[name], value)
	}
}

func (s *Store) Names() []string {
	return slices.Sorted(maps.Keys(s.Values))
}

func (s *Store) RetiredCount() int {
	n := 0
	for _, vs := range s.Retired {
		n += len(vs)
	}
	return n
}

func (s *Store) Lexicon() *token.Lexicon {
	return token.NewLexicon(s.valueToName(), s.Values)
}

func (s *Store) valueToName() map[string]string {
	m := map[string]string{}
	for _, n := range slices.Sorted(maps.Keys(s.Retired)) {
		for _, v := range s.Retired[n] {
			if _, taken := m[v]; !taken {
				m[v] = n
			}
		}
	}
	for _, n := range s.Names() {
		m[s.Values[n]] = n
	}
	return m
}

func UnionLexicon(current *Store, others ...*Store) *token.Lexicon {
	m := map[string]string{}
	for i := len(others) - 1; i >= 0; i-- {
		maps.Copy(m, others[i].valueToName())
	}
	maps.Copy(m, current.valueToName())
	return token.NewLexicon(m, current.Values)
}

type Secret struct {
	Name    string
	Value   string
	Retired bool
}

func (s *Store) Secrets() []Secret {
	var out []Secret
	for _, n := range s.Names() {
		out = append(out, Secret{Name: n, Value: s.Values[n]})
	}
	for _, n := range slices.Sorted(maps.Keys(s.Retired)) {
		for _, v := range s.Retired[n] {
			out = append(out, Secret{Name: n, Value: v, Retired: true})
		}
	}
	return out
}
