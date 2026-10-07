package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/fsutil"
	"github.com/scuba-plaza/redact/internal/hooks"
	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/vault"
)

func (a *app) initCommand() *cobra.Command {
	var classic, forceHooks, noPrompt bool
	cmd := &cobra.Command{
		Use:     "init",
		GroupID: "setup",
		Short:   "Set up redact in this repository or in a fresh clone",
		Long: `Set up redact. Safe to run any number of times.

In a repository without a store, init creates .redact/recipients and an
empty .redact/secrets.age, generating an identity first if you have none.

In every clone it configures the git filter, installs the pre-commit,
post-checkout and post-merge hooks, and hydrates the redacted files.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runInit(cmd.Context(), classic, forceHooks, noPrompt)
		},
	}
	cmd.Flags().BoolVar(&classic, "classic", false, "generate a classic X25519 identity instead of a post-quantum one")
	cmd.Flags().BoolVar(&forceHooks, "force-hooks", false, "replace existing hooks that redact did not write")
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "do not prompt for missing values")
	return cmd
}

func (a *app) runInit(ctx context.Context, classic, forceHooks, noPrompt bool) error {
	p, err := a.project(ctx)
	if err != nil {
		return err
	}
	if err := p.ConfigureFilter(ctx); err != nil {
		return err
	}
	if err := p.ExcludeTempFiles(ctx); err != nil {
		return err
	}
	a.ui.ok("configured the git filter and the store merge driver")
	if sts, err := hooks.Install(ctx, p.Repo, forceHooks); err != nil {
		a.ui.warn("could not install the hooks: %v", err)
	} else {
		a.reportHooks(sts)
	}
	idPath, source, err := a.identityPath(ctx, p)
	if err != nil {
		return err
	}
	kr, err := vault.LoadKeyring(idPath)
	if !p.StoreExists() {
		if errors.Is(err, vault.ErrNoIdentity) {
			if kr, err = a.generateIdentity(idPath, classic); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if err := p.Create(kr); err != nil {
			return err
		}
		a.ui.ok("created %s and %s", project.RecipientsFile, project.StoreFile)
		a.ui.info("  commit both; the store is useless without an identity listed in %s", project.RecipientsFile)
	} else {
		if errors.Is(err, vault.ErrNoIdentity) {
			return fmt.Errorf("%w (from %s); copy the identity you use for this repository there, or point --identity, REDACT_IDENTITY or git config redact.identity at it, then run redact init again\nuntil then git refuses to stage redacted files, so nothing can leak", err, source)
		}
		if err != nil {
			return err
		}
		s, err := p.LoadStore(kr)
		if err != nil {
			return fmt.Errorf("%w\nask someone who can read the store to add one of these to %s and run redact rekey:\n%s", err, project.RecipientsFile, strings.Join(kr.Recipients, "\n"))
		}
		a.ui.ok("%s can read %s", idPath, project.StoreFile)
		trusted, err := p.TrustStore(kr, s)
		if err != nil {
			return err
		}
		a.reportTrust(trusted)
	}
	if added, err := p.EnsureStoreAttributes(ctx); err != nil {
		return err
	} else if added {
		a.ui.ok("marked %s for the merge driver in %s; commit it", project.StoreFile, project.Attributes)
	}
	_, err = a.hydrate(ctx, !noPrompt)
	return err
}

func (a *app) generateIdentity(path string, classic bool) (*vault.Keyring, error) {
	file, recipient, err := vault.Generate(classic, time.Now())
	if err != nil {
		return nil, err
	}
	if err := fsutil.CreateExclusive(path, file, 0o600); err != nil {
		return nil, err
	}
	a.ui.ok("created identity %s", path)
	a.ui.warn("back it up: without it nobody can read the values in this store")
	a.ui.info("  public key: %s", vault.Abbreviate(recipient))
	kr, err := vault.ParseKeyring(file)
	if kr != nil {
		kr.Path = path
	}
	return kr, err
}

func (a *app) reportHooks(sts []hooks.Status) {
	for _, st := range sts {
		switch st.State {
		case hooks.Installed:
			a.ui.ok("%s hook installed", st.Hook.Name)
		case hooks.Updated:
			a.ui.ok("%s hook updated", st.Hook.Name)
		case hooks.Foreign:
			a.ui.warn("%s already exists and was left alone; add this line to it, or rerun with --force-hooks:\n  %s", st.Path, st.Hook.Line)
		case hooks.Unmanaged:
			a.ui.warn("core.hooksPath is set, so redact does not write %s; add this line to it yourself:\n  %s", st.Path, st.Hook.Line)
		}
	}
}

func (a *app) runPostHydrate(ctx context.Context, p *project.Project) {
	cmdline, ok, err := p.Repo.ConfigGet(ctx, "redact.postHydrate", false)
	if err != nil || !ok || strings.TrimSpace(cmdline) == "" {
		return
	}
	cmd := shellCommand(ctx, cmdline)
	cmd.Dir = p.Repo.Root
	cmd.Stdout = a.io.Err
	cmd.Stderr = a.io.Err
	if err := cmd.Run(); err != nil {
		a.ui.warn("redact.postHydrate (%s) failed: %v", cmdline, err)
		return
	}
	a.ui.ok("ran redact.postHydrate")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
