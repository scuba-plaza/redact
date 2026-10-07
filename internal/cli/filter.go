package cli

import (
	"context"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/token"
)

func (a *app) cleanCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "clean [path]",
		Short:  "git clean filter: replace stored values with tokens",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := filterPath(args)
			data, err := io.ReadAll(a.io.In)
			if err != nil {
				return err
			}
			p, kr, s, err := a.open(cmd.Context())
			if err != nil {
				if len(args) == 1 && a.unchanged(cmd.Context(), args[0], data) {
					_, werr := a.io.Out.Write(data)
					return werr
				}
				return fail(1, "refusing to let git store %s: %v", path, err)
			}
			lx, _ := a.vocabulary(p, kr, s)
			res, err := token.Tokenise(data, lx)
			if err != nil {
				return fail(1, "refusing to let git store %s: %v", path, err)
			}
			_, err = a.io.Out.Write(res.Clean)
			return err
		},
	}
}

func (a *app) smudgeCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "smudge [path]",
		Short:  "git smudge filter: replace tokens with stored values",
		Hidden: true,
		Args:   cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := filterPath(args)
			data, err := io.ReadAll(a.io.In)
			if err != nil {
				return err
			}
			if len(token.Names(data)) == 0 {
				_, err = a.io.Out.Write(data)
				return err
			}
			_, _, s, err := a.open(cmd.Context())
			if err != nil {
				a.ui.warn("leaving %s tokenised: %v", path, err)
				_, err = a.io.Out.Write(data)
				return err
			}
			out, missing := token.Hydrate(data, s.Values)
			if len(missing) > 0 {
				a.ui.warn("%s: no value for %s (run: redact hydrate)", path, strings.Join(missing, ", "))
			}
			_, err = a.io.Out.Write(out)
			return err
		},
	}
}

func (a *app) mergeStoreCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "merge-store <base> <ours> <theirs>",
		Short:  "git merge driver: three-way merge of .redact/secrets.age",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := a.project(cmd.Context())
			if err != nil {
				return fail(1, "cannot merge %s: %v", project.StoreFile, err)
			}
			kr, err := a.keyring(cmd.Context(), p)
			if err != nil {
				return fail(1, "cannot merge %s: %v", project.StoreFile, err)
			}
			res, err := p.MergeFiles(kr, args[0], args[1], args[2])
			if err != nil {
				return fail(1, "cannot merge %s: %v", project.StoreFile, err)
			}
			a.reportTrust(res.Trusted)
			for _, c := range res.Conflicts {
				kept := "git's \"ours\" side (the branch you are on; in a rebase, the upstream)"
				if !c.KeptOurs {
					kept = "the side that still has a value"
				}
				a.ui.warn("both sides changed %s; kept %s and retired the other value", c.Name, kept)
			}
			if len(res.Dropped) > 0 {
				a.ui.warn("the other side encrypts the store to recipients this clone does not trust: %s\nthe merged store leaves them out; if you expect them, review %s and run redact rekey", strings.Join(res.Dropped, ", "), project.RecipientsFile)
			}
			if len(res.Conflicts) > 0 || len(res.Dropped) > 0 {
				a.ui.info("check with redact get NAME, fix with redact set NAME, then git add %s", project.StoreFile)
				return silent()
			}
			a.ui.ok("merged %s", project.StoreFile)
			return nil
		},
	}
}

func (a *app) unchanged(ctx context.Context, path string, data []byte) bool {
	p, err := a.project(ctx)
	if err != nil {
		return false
	}
	entries, err := p.Repo.Index(ctx, path)
	if err != nil {
		return false
	}
	id, err := p.Repo.BlobID(ctx, data)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Stage == 0 && e.Blob == id {
			return true
		}
	}
	return false
}

func filterPath(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return "this file"
}
