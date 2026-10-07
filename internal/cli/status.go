package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/hooks"
	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
	"github.com/scuba-plaza/redact/internal/vault"
)

type report struct {
	a        *app
	problems int
}

func (r *report) line(label, state string, good bool, detail string) {
	mark := r.a.out.paint("32", "✓")
	if !good {
		mark = r.a.out.paint("31", "✗")
		r.problems++
	}
	r.print(mark, label, state, detail)
}

func (r *report) warning(label, state, detail string) {
	r.print(r.a.out.paint("33", "!"), label, state, detail)
}

func (r *report) print(mark, label, state, detail string) {
	if detail != "" {
		detail = "  " + r.a.out.dim(detail)
	}
	fmt.Fprintf(r.a.io.Out, "%s %-11s %s%s\n", mark, label, state, detail)
}

func (a *app) statusCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		GroupID: "setup",
		Short:   "Show whether this clone is set up and every redacted file is hydrated",
		Long:    "Check the identity, the store, its recipients, the git filter, the hooks and every redacted file. Exits with status 1 when something needs attention.",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if n := a.runStatus(cmd.Context()); n > 0 {
				return silent()
			}
			return nil
		},
	}
}

func (a *app) runStatus(ctx context.Context) int {
	r := &report{a: a}
	p, err := a.project(ctx)
	if err != nil {
		r.line("repository", err.Error(), false, "")
		return r.problems
	}
	idPath, source, err := a.identityPath(ctx, p)
	var kr *vault.Keyring
	switch {
	case err != nil:
		r.line("identity", err.Error(), false, "")
	default:
		kr, err = vault.LoadKeyring(idPath)
		switch {
		case errors.Is(err, vault.ErrNoIdentity):
			r.line("identity", "missing", false, idPath+" ("+source+")")
		case err != nil:
			r.line("identity", err.Error(), false, "")
		default:
			detail := idPath
			if info, err := os.Stat(idPath); err == nil && info.Mode().Perm()&0o077 != 0 {
				r.line("identity", fmt.Sprintf("readable by others (mode %04o)", info.Mode().Perm()), false, "chmod 600 "+idPath)
			} else {
				r.line("identity", "ok", true, detail)
			}
		}
	}

	var s *store.Store
	var lx *token.Lexicon
	switch {
	case !p.StoreExists():
		r.line("store", "missing", false, "run: redact init")
	case kr == nil:
		r.line("store", "cannot be read without an identity", false, project.StoreFile)
	default:
		s, err = p.LoadStore(kr)
		if err == nil {
			lx, _ = a.vocabulary(p, kr, s)
		}
		if err != nil {
			s = nil
			r.line("store", err.Error(), false, "")
		} else {
			r.line("store", fmt.Sprintf("%d value(s), %d retired", len(s.Values), s.RetiredCount()), true, project.StoreFile)
			if err := s.Validate(); err != nil {
				for _, msg := range strings.Split(err.Error(), "\n") {
					r.line("store", "invalid entry", false, msg)
				}
			}
			for _, d := range s.Duplicates() {
				r.line("store", d[0]+" and "+d[1]+" hold the same value", false, "files using one of them never settle; set one of them to another value")
			}
		}
	}
	if s != nil {
		added, removed, err := p.RecipientDrift(s)
		health := p.KnownHealth(kr, s)
		healthy := true
		if err != nil {
			r.line("recipients", err.Error(), false, "")
			healthy = false
		} else if len(added)+len(removed) > 0 {
			r.line("recipients", fmt.Sprintf("%s lists %d more and %d fewer than the store", project.RecipientsFile, len(added), len(removed)), false, "review it, then run: redact rekey")
			healthy = false
		}
		if len(health.Untrusted) > 0 {
			r.line("recipients", "not trusted in this clone: "+strings.Join(health.Untrusted, ", "), false, "if you expect them, run: redact rekey")
			healthy = false
		}
		if health.State != project.KnownUnreadable && !health.Trusted {
			r.line("recipients", "this clone has not pinned the recipients it trusts", false, "run: redact init")
			healthy = false
		}
		if healthy {
			r.line("recipients", fmt.Sprintf("%d", len(s.Recipients)), true, project.RecipientsFile)
		}
		switch health.State {
		case project.KnownUnreadable:
			r.line("seen", "this identity cannot read the cache of values seen before", false, "run: redact rekey to start a new one")
		case project.KnownMissing:
			r.line("seen", "no values remembered yet", true, "")
		default:
			r.line("seen", fmt.Sprintf("%d value(s) remembered in this clone", health.Values), true, "")
		}
	}

	if ok, err := p.FilterConfigured(ctx); err != nil {
		r.line("filter", err.Error(), false, "")
	} else if ok {
		r.line("filter", "configured", true, "")
	} else {
		r.line("filter", "not configured", false, "run: redact init")
	}
	if ok, err := p.MergeConfigured(ctx); err != nil {
		r.line("merge", err.Error(), false, "")
	} else if !ok {
		r.line("merge", "the store merge driver is not configured", false, "run: redact init")
	}

	sts, err := hooks.Inspect(ctx, p.Repo)
	if err != nil {
		r.line("hooks", err.Error(), false, "")
	} else {
		var parts []string
		good := true
		for _, st := range sts {
			parts = append(parts, st.Hook.Name+" "+st.State.String())
			if st.State != hooks.Installed {
				good = false
			}
		}
		detail := ""
		if !good {
			detail = "run: redact init"
		}
		r.line("hooks", strings.Join(parts, ", "), good, detail)
	}

	files, err := p.FilteredFiles(ctx)
	if err != nil {
		r.line("files", err.Error(), false, "")
		return r.problems
	}
	if len(files) == 0 {
		r.line("files", "none redacted yet", true, "redact add <path>")
		return r.problems
	}
	for _, rel := range files {
		label := "file"
		data, err := os.ReadFile(p.Path(rel))
		switch {
		case errors.Is(err, os.ErrNotExist):
			r.line(label, rel, false, "missing from the working tree")
			continue
		case err != nil:
			r.line(label, rel, false, err.Error())
			continue
		case s == nil:
			r.line(label, rel, false, "unknown without a readable store")
			continue
		}
		res, err := token.Tokenise(data, lx)
		if err != nil {
			r.line(label, rel, false, err.Error())
			continue
		}
		var issues []string
		if len(res.Missing) > 0 {
			issues = append(issues, "no value for "+strings.Join(res.Missing, ", "))
		}
		if !bytes.Equal(res.Hydrated, data) {
			issues = append(issues, "stale; run: redact hydrate")
		}
		if len(issues) > 0 {
			r.line(label, rel, false, strings.Join(issues, "; "))
		} else {
			r.line(label, rel, true, "hydrated")
		}
		if lines := token.Malformed(res.Hydrated); len(lines) > 0 {
			r.warning("", rel, token.DescribeMalformed(lines))
		}
	}
	return r.problems
}
