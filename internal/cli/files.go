package cli

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/fsutil"
	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/scan"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
	"github.com/scuba-plaza/redact/internal/vault"
)

func shellCommand(ctx context.Context, cmdline string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", append([]string{"-c", cmdline, "sh"}, args...)...)
}

func (a *app) addCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "add <path>...",
		GroupID: "files",
		Short:   "Redact files: commit them tokenised from now on",
		Long: `Mark files as redacted and stage them through the filter.

Each path gets a "filter=redact" line in .gitattributes, then both are
staged with git add, so the index only ever receives the tokenised content.
Store the values first with redact set, or write REDACTED[NAME] tokens into the
file and let redact hydrate ask for the values.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runAdd(cmd.Context(), args)
		},
	}
}

func (a *app) runAdd(ctx context.Context, args []string) error {
	p, kr, s, err := a.open(ctx)
	if err != nil {
		return err
	}
	lx, secrets := a.vocabulary(p, kr, s)
	if ok, err := p.FilterConfigured(ctx); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("the git filter is not configured in this clone (run: redact init)")
	}
	base, err := a.workdir()
	if err != nil {
		return err
	}
	var paths, fresh []string
	for _, arg := range args {
		rel, err := p.Rel(base, arg)
		if err != nil {
			return err
		}
		if slices.Contains(paths, rel) {
			continue
		}
		if rel == project.Attributes || strings.HasPrefix(rel, project.Dir+"/") {
			return fmt.Errorf("%s belongs to redact itself and cannot be redacted", rel)
		}
		if err := checkPattern(rel); err != nil {
			return err
		}
		info, err := os.Lstat(p.Path(rel))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", rel)
		}
		data, err := os.ReadFile(p.Path(rel))
		if err != nil {
			return err
		}
		res, err := token.Tokenise(data, lx)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if bytes.Equal(res.Clean, data) && len(token.Names(data)) == 0 {
			a.ui.warn("%s holds no stored value and no REDACTED[NAME] token yet; store its values with redact set first", rel)
		}
		a.warnMalformed(rel, token.Malformed(data))
		filtered, err := p.IsFiltered(ctx, rel)
		if err != nil {
			return err
		}
		if !filtered {
			fresh = append(fresh, rel)
		}
		paths = append(paths, rel)
	}
	if len(fresh) > 0 {
		if err := appendAttributes(p.Path(project.Attributes), fresh); err != nil {
			return err
		}
		for _, rel := range fresh {
			filtered, err := p.IsFiltered(ctx, rel)
			if err != nil {
				return err
			}
			if !filtered {
				return fmt.Errorf("%s is still not filtered after updating %s; another attribute line overrides it", rel, project.Attributes)
			}
		}
	}
	staged := slices.Clone(paths)
	if fileExists(p.Path(project.Attributes)) {
		staged = append([]string{project.Attributes}, staged...)
	}
	if err := p.Repo.Add(ctx, staged...); err != nil {
		return err
	}
	if err := a.verifyStaged(ctx, p, secrets, paths); err != nil {
		return err
	}
	for _, rel := range paths {
		a.ui.ok("%s is redacted and staged", rel)
		a.warnHistory(ctx, p, secrets, rel)
	}
	return nil
}

func checkPattern(rel string) error {
	for _, r := range rel {
		if r <= ' ' || r == '"' || r == '\\' || r == 0x7f {
			return fmt.Errorf("%q contains characters .gitattributes cannot express; rename it or add a pattern for it yourself", rel)
		}
	}
	return nil
}

func appendAttributes(path string, rels []string) error {
	lines := make([]string, len(rels))
	for i, rel := range rels {
		escaped := strings.NewReplacer("*", `\*`, "?", `\?`, "[", `\[`).Replace(rel)
		lines[i] = fmt.Sprintf("/%s filter=%s", escaped, project.FilterName)
	}
	_, err := fsutil.AppendLines(path, lines...)
	return err
}

func (a *app) verifyStaged(ctx context.Context, p *project.Project, secrets []store.Secret, paths []string) error {
	entries, err := p.Repo.Index(ctx, paths...)
	if err != nil {
		return err
	}
	blobs, err := p.Repo.Blobs(ctx)
	if err != nil {
		return err
	}
	defer blobs.Close()
	sc := scan.New(scan.Options{Secrets: secrets})
	for _, e := range entries {
		data, err := blobs.Read(e.Blob)
		if err != nil {
			return err
		}
		for _, f := range sc.Scan(e.Path, data, true) {
			if f.Rule == "value" || f.Rule == "retired-value" {
				if err := p.Repo.Unstage(ctx, e.Path); err != nil {
					return fail(1, "%s was staged with a real value (%s at line %d) and could not be unstaged: %v; run git restore --staged %s", e.Path, f.Description, f.Line, err, e.Path)
				}
				return fail(1, "%s was staged with a real value (%s at line %d); unstaged it again", e.Path, f.Description, f.Line)
			}
		}
	}
	return nil
}

func (a *app) warnHistory(ctx context.Context, p *project.Project, secrets []store.Secret, rel string) {
	data, ok, err := p.Repo.RevBlob(ctx, "HEAD", rel)
	if err != nil || !ok {
		return
	}
	sc := scan.New(scan.Options{Secrets: secrets})
	if fs := sc.Scan(rel, data, true); len(fs) > 0 {
		a.ui.warn("HEAD already holds %s with real values (%s); they stay in history: rotate them, or rewrite history before you publish", rel, fs[0].Description)
	}
}

func (a *app) hydrateCommand() *cobra.Command {
	var noPrompt bool
	cmd := &cobra.Command{
		Use:     "hydrate",
		GroupID: "files",
		Short:   "Write the current values into the redacted files",
		Long: `Bring every redacted file in the working tree up to date with the store.

Old values (including retired ones, e.g. after a git pull changed a value)
are replaced with current ones, and your other edits are kept. Tokens
without a value are prompted for when stdin is a terminal.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := a.hydrate(cmd.Context(), !noPrompt)
			if err != nil {
				return err
			}
			if len(res.Missing) > 0 {
				return silent()
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "do not prompt for missing values")
	cmd.Flags().BoolVarP(&a.quiet, "quiet", "q", false, "only print warnings and errors")
	return cmd
}

func (a *app) hydrate(ctx context.Context, prompt bool) (*project.Hydration, error) {
	p, kr, s, err := a.open(ctx)
	if err != nil {
		return nil, err
	}
	lx, _ := a.vocabulary(p, kr, s)
	res, err := p.Rehydrate(ctx, lx, false)
	if err != nil {
		return nil, err
	}
	changed := res.Changed
	if len(res.Missing) > 0 && prompt && a.io.InTTY && a.io.ReadSecret != nil {
		values := map[string]string{}
		for _, name := range res.MissingNames() {
			v, err := a.io.ReadSecret(fmt.Sprintf("%s (used in %s, empty to skip): ", name, strings.Join(res.Missing[name], ", ")))
			if err != nil {
				return nil, err
			}
			if v == "" {
				continue
			}
			trial := s.Clone()
			for n, pv := range values {
				_, _ = trial.Set(n, pv)
			}
			if _, err := trial.Set(name, v); err != nil {
				a.ui.warn("%v; skipped", err)
				continue
			}
			values[name] = v
		}
		if len(values) > 0 {
			ch, err := p.Update(kr, func(st *store.Store) error {
				for n, v := range values {
					if _, err := st.Set(n, v); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			a.reportTrust(ch.Approved)
			a.ui.ok("saved %d value(s) to %s", len(values), project.StoreFile)
			lx, _ = a.vocabulary(p, kr, ch.After)
			if res, err = p.Rehydrate(ctx, lx, false); err != nil {
				return nil, err
			}
			changed = append(changed, res.Changed...)
		}
	}
	a.reportHydration(res, changed)
	if len(changed) > 0 {
		a.runPostHydrate(ctx, p)
	}
	return res, nil
}

func (a *app) reportHydration(res *project.Hydration, changed []string) {
	seen := map[string]bool{}
	for _, f := range changed {
		if !seen[f] {
			seen[f] = true
			a.ui.ok("hydrated %s", f)
		}
	}
	for _, f := range res.Skipped {
		a.ui.warn("%s is redacted but missing from the working tree", f)
	}
	for _, name := range res.MissingNames() {
		a.ui.warn("%s has no value (used in %s); run: redact set %s", token.Format(name), strings.Join(res.Missing[name], ", "), name)
	}
	for _, f := range slices.Sorted(maps.Keys(res.Malformed)) {
		a.warnMalformed(f, res.Malformed[f])
	}
	if len(changed) == 0 && len(res.Missing) == 0 {
		a.ui.ok("redacted files are up to date")
	}
}

func (a *app) warnMalformed(path string, lines []int) {
	if len(lines) > 0 {
		a.ui.warn("%s: %s", path, token.DescribeMalformed(lines))
	}
}

func (a *app) vocabulary(p *project.Project, kr *vault.Keyring, current *store.Store, previous ...*store.Store) (*token.Lexicon, []store.Secret) {
	lx, secrets, warning := p.Vocabulary(kr, current, previous...)
	if warning != nil {
		a.ui.warn("%v", warning)
	}
	return lx, secrets
}

func (a *app) rehydrateAfter(ctx context.Context, p *project.Project, kr *vault.Keyring, ch *project.Change, keep bool) error {
	latest, err := p.LoadStore(kr)
	if err != nil {
		latest = ch.After
	}
	var lx *token.Lexicon
	if keep {
		lx, _ = a.vocabulary(p, kr, latest, ch.Before)
	} else {
		lx = p.Recall(kr, latest, ch.Before)
	}
	res, err := p.Rehydrate(ctx, lx, false)
	if err != nil {
		return fail(1, "the store was saved, but the redacted files were not rehydrated: %v\nfix that and run redact hydrate", err)
	}
	for _, f := range res.Changed {
		a.ui.ok("rehydrated %s", f)
	}
	if len(res.Changed) > 0 {
		a.runPostHydrate(ctx, p)
	}
	return nil
}
