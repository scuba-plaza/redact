package project

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/scuba-plaza/redact/internal/fsutil"
	"github.com/scuba-plaza/redact/internal/git"
	"github.com/scuba-plaza/redact/internal/scan"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
	"github.com/scuba-plaza/redact/internal/vault"
)

const (
	Dir            = ".redact"
	StoreFile      = ".redact/secrets.age"
	RecipientsFile = ".redact/recipients"
	AllowFile      = ".redact/allow"
	Attributes     = ".gitattributes"
	FilterName     = "redact"
	ScanAttr       = "redact-scan"
	CleanCommand   = "redact clean -- %f"
	SmudgeCommand  = "redact smudge -- %f"
	MergeDriver    = "redact-store"
	MergeCommand   = "redact merge-store -- %O %A %B"
)

var ErrNoStore = errors.New("no store")

type Project struct {
	Repo *git.Repo
}

func Open(ctx context.Context, dir string) (*Project, error) {
	r, err := git.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	return &Project{Repo: r}, nil
}

func (p *Project) Path(rel string) string {
	return filepath.Join(p.Repo.Root, filepath.FromSlash(rel))
}

func (p *Project) StoreExists() bool {
	_, err := os.Stat(p.Path(StoreFile))
	return err == nil
}

func (p *Project) Recipients() ([]vault.Recipient, error) {
	f, err := os.Open(p.Path(RecipientsFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	recs, err := vault.ParseRecipients(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RecipientsFile, err)
	}
	return recs, nil
}

func (p *Project) LoadStore(kr *vault.Keyring) (*store.Store, error) {
	ct, err := os.ReadFile(p.Path(StoreFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s (run: redact init)", ErrNoStore, StoreFile)
	}
	if err != nil {
		return nil, err
	}
	pt, err := vault.Decrypt(ct, kr)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s: %w", StoreFile, err)
	}
	return store.Decode(pt)
}

func (p *Project) lock() (func(), error) {
	return fsutil.Lock(filepath.Join(p.Repo.CommonDir, "redact.lock"))
}

func parseRecipients(texts []string) ([]vault.Recipient, error) {
	return vault.ParseRecipients(strings.NewReader(strings.Join(texts, "\n")))
}

func (p *Project) write(kr *vault.Keyring, s *store.Store, recs []vault.Recipient) error {
	return writeStore(kr, s, recs, p.Path(StoreFile))
}

func writeStore(kr *vault.Keyring, s *store.Store, recs []vault.Recipient, path string) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("refusing to write %s: %w", StoreFile, err)
	}
	s.Recipients = s.Recipients[:0]
	for _, r := range recs {
		s.Recipients = append(s.Recipients, r.Text)
	}
	plaintext := s.Encode()
	ct, err := vault.Encrypt(plaintext, recs)
	if err != nil {
		return fmt.Errorf("cannot encrypt %s: %w", StoreFile, err)
	}
	back, err := vault.Decrypt(ct, kr)
	if err != nil || !bytes.Equal(back, plaintext) {
		return fmt.Errorf("refusing to write a store you could not read back: add your recipient (%s) to %s and run redact rekey", strings.Join(kr.Recipients, ", "), RecipientsFile)
	}
	return fsutil.WriteFileAtomic(path, ct, 0o644)
}

func loadStoreFile(kr *vault.Keyring, path string) (*store.Store, error) {
	ct, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 {
		return store.New(), nil
	}
	pt, err := vault.Decrypt(ct, kr)
	if err != nil {
		return nil, err
	}
	return store.Decode(pt)
}

type MergeResult struct {
	Conflicts []store.Conflict
	Trusted   []string
	Dropped   []string
}

func (p *Project) MergeFiles(kr *vault.Keyring, basePath, oursPath, theirsPath string) (*MergeResult, error) {
	var sides [3]*store.Store
	for i, path := range []string{basePath, oursPath, theirsPath} {
		s, err := loadStoreFile(kr, path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", []string{"the common ancestor", "our side", "their side"}[i], err)
		}
		sides[i] = s
	}
	merged, conflicts := store.Merge(sides[0], sides[1], sides[2])
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	trusted, approved, err := p.trusted(kr, sides[1].Recipients)
	if err != nil {
		return nil, err
	}
	res := &MergeResult{Conflicts: conflicts, Trusted: approved}
	var keep []string
	for _, r := range merged.Recipients {
		if slices.Contains(trusted, r) {
			keep = append(keep, r)
		} else {
			res.Dropped = append(res.Dropped, vault.Abbreviate(r))
		}
	}
	recs, err := parseRecipients(keep)
	if err != nil {
		return nil, err
	}
	if err := writeStore(kr, merged, recs, oursPath); err != nil {
		return nil, err
	}
	return res, nil
}

func (p *Project) EnsureStoreAttributes(ctx context.Context) (bool, error) {
	attrs, err := p.Repo.Attributes(ctx, []string{StoreFile}, false, "merge")
	if err != nil {
		return false, err
	}
	if attrs[StoreFile]["merge"] == MergeDriver {
		return false, nil
	}
	return fsutil.AppendLines(p.Path(Attributes), "/"+StoreFile+" merge="+MergeDriver)
}

type Change struct {
	Before   *store.Store
	After    *store.Store
	Written  bool
	Approved []string
}

func (p *Project) Update(kr *vault.Keyring, fn func(*store.Store) error) (*Change, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	before, err := p.LoadStore(kr)
	if err != nil {
		return nil, err
	}
	after := before.Clone()
	if err := fn(after); err != nil {
		return nil, err
	}
	ch := &Change{Before: before, After: after}
	if before.Equal(after) {
		return ch, nil
	}
	if len(before.Recipients) == 0 {
		return nil, fmt.Errorf("%s does not record its recipients; run redact rekey", StoreFile)
	}
	if ch.Approved, err = p.trust(kr, before.Recipients); err != nil {
		return nil, err
	}
	recs, err := parseRecipients(before.Recipients)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", StoreFile, err)
	}
	if err := p.write(kr, after, recs); err != nil {
		return nil, err
	}
	ch.Written = true
	return ch, nil
}

type Rekeyed struct {
	Recipients []string
	Added      []string
	Removed    []string
}

func (p *Project) Rekey(kr *vault.Keyring) (*Rekeyed, error) {
	unlock, err := p.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	s, err := p.LoadStore(kr)
	if err != nil {
		return nil, err
	}
	recs, err := p.Recipients()
	if err != nil {
		return nil, err
	}
	before := slices.Clone(s.Recipients)
	if err := p.write(kr, s, recs); err != nil {
		return nil, err
	}
	added, removed := diff(before, s.Recipients)
	if err := p.approve(kr, s.Recipients); err != nil {
		return nil, err
	}
	return &Rekeyed{Recipients: s.Recipients, Added: added, Removed: removed}, nil
}

func diff(before, after []string) ([]string, []string) {
	var added, removed []string
	for _, a := range after {
		if !slices.Contains(before, a) {
			added = append(added, a)
		}
	}
	for _, b := range before {
		if !slices.Contains(after, b) {
			removed = append(removed, b)
		}
	}
	return added, removed
}

func (p *Project) RecipientDrift(s *store.Store) ([]string, []string, error) {
	recs, err := p.Recipients()
	if err != nil {
		return nil, nil, err
	}
	var file []string
	for _, r := range recs {
		file = append(file, r.Text)
	}
	added, removed := diff(s.Recipients, file)
	return added, removed, nil
}

func (p *Project) Create(kr *vault.Keyring) error {
	unlock, err := p.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if p.StoreExists() {
		return nil
	}
	if err := os.MkdirAll(p.Path(Dir), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(p.Path(RecipientsFile)); errors.Is(err, fs.ErrNotExist) {
		if len(kr.Recipients) == 0 {
			return fmt.Errorf("cannot derive a recipient from %s; write %s yourself", kr.Path, RecipientsFile)
		}
		content := strings.Join(kr.Recipients, "\n") + "\n"
		if err := fsutil.WriteFileAtomic(p.Path(RecipientsFile), []byte(content), 0o644); err != nil {
			return err
		}
	}
	recs, err := p.Recipients()
	if err != nil {
		return err
	}
	s := store.New()
	if err := p.write(kr, s, recs); err != nil {
		return err
	}
	return p.approve(kr, s.Recipients)
}

func (p *Project) Allow() ([]*regexp.Regexp, error) {
	f, err := os.Open(p.Path(AllowFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	allow, err := scan.ParseAllow(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", AllowFile, err)
	}
	return allow, nil
}

func (p *Project) FilterConfigured(ctx context.Context) (bool, error) {
	return p.configured(ctx, map[string]string{
		"filter." + FilterName + ".clean":    CleanCommand,
		"filter." + FilterName + ".smudge":   SmudgeCommand,
		"filter." + FilterName + ".required": "true",
	})
}

func (p *Project) MergeConfigured(ctx context.Context) (bool, error) {
	return p.configured(ctx, map[string]string{"merge." + MergeDriver + ".driver": MergeCommand})
}

func (p *Project) configured(ctx context.Context, want map[string]string) (bool, error) {
	for k, v := range want {
		got, ok, err := p.Repo.ConfigGet(ctx, k, false)
		if err != nil {
			return false, err
		}
		if !ok || got != v {
			return false, nil
		}
	}
	return true, nil
}

func (p *Project) ConfigureFilter(ctx context.Context) error {
	for _, kv := range [][2]string{
		{"filter." + FilterName + ".clean", CleanCommand},
		{"filter." + FilterName + ".smudge", SmudgeCommand},
		{"filter." + FilterName + ".required", "true"},
		{"merge." + MergeDriver + ".name", "redact store merge"},
		{"merge." + MergeDriver + ".driver", MergeCommand},
	} {
		if err := p.Repo.ConfigSetLocal(ctx, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

func (p *Project) ExcludeTempFiles(ctx context.Context) error {
	path, err := p.Repo.GitPath(ctx, "info/exclude")
	if err != nil {
		return err
	}
	_, err = fsutil.AppendLines(path, fsutil.TempPattern)
	return err
}

func (p *Project) FilteredFiles(ctx context.Context) ([]string, error) {
	tracked, err := p.Repo.Tracked(ctx)
	if err != nil {
		return nil, err
	}
	return p.filtered(ctx, tracked)
}

func (p *Project) filtered(ctx context.Context, paths []string) ([]string, error) {
	attrs, err := p.Repo.Attributes(ctx, paths, false, "filter")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, path := range paths {
		if attrs[path]["filter"] == FilterName {
			out = append(out, path)
		}
	}
	return out, nil
}

func (p *Project) IsFiltered(ctx context.Context, path string) (bool, error) {
	got, err := p.filtered(ctx, []string{path})
	return len(got) == 1, err
}

type Hydration struct {
	Changed   []string
	Missing   map[string][]string
	Malformed map[string][]int
	Skipped   []string
}

func (h *Hydration) MissingNames() []string {
	names := make([]string, 0, len(h.Missing))
	for n := range h.Missing {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func (p *Project) Rehydrate(ctx context.Context, lx *token.Lexicon, dryRun bool) (*Hydration, error) {
	files, err := p.FilteredFiles(ctx)
	if err != nil {
		return nil, err
	}
	h := &Hydration{Missing: map[string][]string{}, Malformed: map[string][]int{}}
	for _, rel := range files {
		abs := p.Path(rel)
		info, err := os.Lstat(abs)
		if errors.Is(err, fs.ErrNotExist) {
			h.Skipped = append(h.Skipped, rel)
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			h.Skipped = append(h.Skipped, rel)
			continue
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			return nil, err
		}
		res, err := token.Tokenise(data, lx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		out := res.Hydrated
		for _, n := range res.Missing {
			h.Missing[n] = append(h.Missing[n], rel)
		}
		if lines := token.Malformed(out); len(lines) > 0 {
			h.Malformed[rel] = lines
		}
		if bytes.Equal(out, data) {
			continue
		}
		h.Changed = append(h.Changed, rel)
		if dryRun {
			continue
		}
		if err := fsutil.ReplaceFile(abs, out); err != nil {
			return nil, err
		}
	}
	if !dryRun && len(h.Changed) > 0 {
		if err := p.RefreshIndex(ctx, h.Changed...); err != nil {
			return nil, err
		}
	}
	return h, nil
}

func (p *Project) RefreshIndex(ctx context.Context, paths ...string) error {
	entries, err := p.Repo.Index(ctx, paths...)
	if err != nil {
		return err
	}
	if err := p.Repo.TouchIndexEntries(ctx, git.Refreshable(entries)); err != nil {
		return err
	}
	return p.Repo.RefreshIndex(ctx)
}

func (p *Project) Rel(cwd, arg string) (string, error) {
	abs := arg
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, arg)
	}
	abs = filepath.Clean(abs)
	root := p.Repo.Root
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(resolved, filepath.Base(abs))
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is outside the repository", arg)
	}
	return filepath.ToSlash(rel), nil
}
