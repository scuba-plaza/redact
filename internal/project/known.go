package project

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/scuba-plaza/redact/internal/fsutil"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
	"github.com/scuba-plaza/redact/internal/vault"
)

type KnownState int

const (
	KnownMissing KnownState = iota
	KnownReadable
	KnownUnreadable
)

func (p *Project) knownPath() string {
	return filepath.Join(p.Repo.CommonDir, "redact", "known.age")
}

func (p *Project) loadKnown(kr *vault.Keyring) (*store.Store, KnownState) {
	ct, err := os.ReadFile(p.knownPath())
	if errors.Is(err, fs.ErrNotExist) {
		return store.New(), KnownMissing
	}
	if err != nil {
		return store.New(), KnownUnreadable
	}
	pt, err := vault.Decrypt(ct, kr)
	if err != nil {
		return store.New(), KnownUnreadable
	}
	known, err := store.Decode(pt)
	if err != nil {
		return store.New(), KnownUnreadable
	}
	return known, KnownReadable
}

var errNoOwnRecipient = errors.New("no recipient can be derived from this identity")

func ownRecipients(kr *vault.Keyring) ([]vault.Recipient, error) {
	texts := kr.Recipients
	var pq []string
	for _, t := range texts {
		if strings.HasPrefix(t, "age1pq1") {
			pq = append(pq, t)
		}
	}
	if len(pq) > 0 {
		texts = pq
	}
	if len(texts) == 0 {
		return nil, errNoOwnRecipient
	}
	return parseRecipients(texts)
}

func (p *Project) saveKnown(kr *vault.Keyring, known *store.Store, state KnownState) error {
	recs, err := ownRecipients(kr)
	if err != nil {
		return err
	}
	ct, err := vault.Encrypt(known.Encode(), recs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.knownPath()), 0o700); err != nil {
		return err
	}
	if state == KnownUnreadable {
		if err := os.Rename(p.knownPath(), p.knownPath()+".unreadable"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return fsutil.WriteFileAtomic(p.knownPath(), ct, 0o600)
}

func remember(known *store.Store, stores []*store.Store) bool {
	changed := false
	for _, s := range stores {
		for _, sec := range s.Secrets() {
			if !slices.Contains(known.Retired[sec.Name], sec.Value) {
				known.Retired[sec.Name] = append(known.Retired[sec.Name], sec.Value)
				changed = true
			}
		}
	}
	return changed
}

func vocabulary(current *store.Store, previous []*store.Store, known *store.Store) (*token.Lexicon, []store.Secret) {
	all := append(append([]*store.Store{current}, previous...), known)
	var secrets []store.Secret
	seen := map[string]bool{}
	for _, s := range all {
		for _, sec := range s.Secrets() {
			if !seen[sec.Value] {
				seen[sec.Value] = true
				secrets = append(secrets, sec)
			}
		}
	}
	return store.UnionLexicon(current, all[1:]...), secrets
}

func (p *Project) Vocabulary(kr *vault.Keyring, current *store.Store, previous ...*store.Store) (*token.Lexicon, []store.Secret, error) {
	unlock, err := p.lock()
	if err != nil {
		known, _ := p.loadKnown(kr)
		lx, secrets := vocabulary(current, previous, known)
		return lx, secrets, fmt.Errorf("cannot update the cache of values seen before: %w", err)
	}
	defer unlock()
	known, state := p.loadKnown(kr)
	stores := append([]*store.Store{current}, previous...)
	var warning error
	if remember(known, stores) && state != KnownUnreadable {
		if err := p.saveKnown(kr, known, state); err != nil && !errors.Is(err, errNoOwnRecipient) {
			warning = fmt.Errorf("cannot update the cache of values seen before: %w", err)
		}
	}
	lx, secrets := vocabulary(current, previous, known)
	return lx, secrets, warning
}

func (p *Project) Recall(kr *vault.Keyring, current *store.Store, previous ...*store.Store) *token.Lexicon {
	known, _ := p.loadKnown(kr)
	lx, _ := vocabulary(current, previous, known)
	return lx
}

func (p *Project) Forget(kr *vault.Keyring, name string) (bool, error) {
	unlock, err := p.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	known, state := p.loadKnown(kr)
	if state == KnownUnreadable {
		return false, errors.New("the cache of values seen before cannot be read with this identity")
	}
	if _, ok := known.Retired[name]; !ok {
		return false, nil
	}
	delete(known.Retired, name)
	return true, p.saveKnown(kr, known, state)
}

func (p *Project) trust(kr *vault.Keyring, recipients []string) ([]string, error) {
	known, state := p.loadKnown(kr)
	if state == KnownUnreadable {
		return nil, errors.New("this clone's list of trusted recipients cannot be read with this identity; review .redact/recipients and run redact rekey")
	}
	if len(known.Recipients) == 0 {
		known.Recipients = slices.Clone(recipients)
		if err := p.saveKnown(kr, known, state); err != nil {
			if errors.Is(err, errNoOwnRecipient) {
				return nil, nil
			}
			return nil, err
		}
		return recipients, nil
	}
	var unknown []string
	for _, r := range recipients {
		if !slices.Contains(known.Recipients, r) {
			unknown = append(unknown, vault.Abbreviate(r))
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("the store is encrypted to recipients this clone has not trusted yet: %s\nif you expect them, review .redact/recipients and run redact rekey", strings.Join(unknown, ", "))
	}
	return nil, nil
}

func (p *Project) approve(kr *vault.Keyring, recipients []string) error {
	known, state := p.loadKnown(kr)
	known.Recipients = slices.Clone(recipients)
	if err := p.saveKnown(kr, known, state); err != nil && !errors.Is(err, errNoOwnRecipient) {
		return err
	}
	return nil
}

func (p *Project) trusted(kr *vault.Keyring, fallback []string) ([]string, []string, error) {
	known, state := p.loadKnown(kr)
	if state == KnownUnreadable {
		return nil, nil, errors.New("this clone's list of trusted recipients cannot be read with this identity; run redact rekey")
	}
	if len(known.Recipients) > 0 {
		return known.Recipients, nil, nil
	}
	if err := p.approve(kr, fallback); err != nil {
		return nil, nil, err
	}
	return fallback, fallback, nil
}

func (p *Project) TrustStore(kr *vault.Keyring, s *store.Store) ([]string, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	known, state := p.loadKnown(kr)
	if state == KnownReadable && len(known.Recipients) > 0 {
		return nil, nil
	}
	if err := p.approve(kr, s.Recipients); err != nil {
		return nil, err
	}
	return s.Recipients, nil
}

type KnownHealth struct {
	State     KnownState
	Values    int
	Trusted   bool
	Untrusted []string
}

func (p *Project) KnownHealth(kr *vault.Keyring, s *store.Store) KnownHealth {
	known, state := p.loadKnown(kr)
	h := KnownHealth{State: state, Values: known.RetiredCount(), Trusted: len(known.Recipients) > 0}
	if state == KnownReadable && h.Trusted {
		for _, r := range s.Recipients {
			if !slices.Contains(known.Recipients, r) {
				h.Untrusted = append(h.Untrusted, vault.Abbreviate(r))
			}
		}
	}
	return h
}
