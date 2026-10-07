package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
)

func (a *app) completeNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	_, _, s, err := a.open(cmd.Context())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return s.Names(), cobra.ShellCompDirectiveNoFileComp
}

func nameArg(cmd *cobra.Command, args []string) error {
	if err := cobra.ExactArgs(1)(cmd, args); err != nil {
		return err
	}
	return store.CheckName(args[0])
}

func trimNewlines(s string) string {
	return strings.TrimRight(s, "\r\n")
}

func (a *app) setCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "set <NAME>",
		GroupID:           "values",
		Short:             "Store a value, read from stdin or a hidden prompt",
		Long:              "Store the value of REDACTED[NAME]. The value is read from stdin, without its trailing newlines, or from a hidden prompt when stdin is a terminal. The old value is kept as a retired value so it is still tokenised and scanned for, and redacted files are rehydrated.",
		Example:           "  redact set SYS_USER\n  redact set SSH_EXTRA_CONFIG < ~/.ssh/config.private",
		Args:              nameArg,
		ValidArgsFunction: a.completeNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			var value string
			if a.io.InTTY && a.io.ReadSecret != nil {
				v, err := a.io.ReadSecret(name + ": ")
				if err != nil {
					return err
				}
				value = v
			} else {
				b, err := io.ReadAll(a.io.In)
				if err != nil {
					return err
				}
				value = trimNewlines(string(b))
			}
			if value == "" {
				return fail(2, "empty value; nothing stored")
			}
			return a.store(cmd.Context(), name, value, nil)
		},
	}
}

type expectation struct {
	value   string
	existed bool
}

var errChanged = errors.New("changed while you were editing")

func (a *app) store(ctx context.Context, name, value string, expect *expectation) error {
	p, kr, _, err := a.open(ctx)
	if err != nil {
		return err
	}
	ch, err := p.Update(kr, func(s *store.Store) error {
		if expect != nil {
			if v, ok := s.Values[name]; ok != expect.existed || v != expect.value {
				return fmt.Errorf("%s %w; nothing saved (run redact edit %s again)", name, errChanged, name)
			}
		}
		_, err := s.Set(name, value)
		return err
	})
	if err != nil {
		return err
	}
	a.reportTrust(ch.Approved)
	if !ch.Written {
		a.ui.ok("%s is unchanged", name)
		return nil
	}
	if _, existed := ch.Before.Values[name]; existed {
		a.ui.ok("updated %s (the old value is retired)", name)
	} else {
		a.ui.ok("stored %s", name)
	}
	a.ui.info("  %s", a.ui.dim("commit "+project.StoreFile+" to share it"))
	return a.rehydrateAfter(ctx, p, kr, ch, true)
}

func (a *app) reportTrust(recipients []string) {
	if len(recipients) > 0 {
		a.ui.ok("this clone now trusts the %d recipient(s) the store is encrypted to; later changes need redact rekey", len(recipients))
	}
}

func (a *app) getCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "get <NAME>",
		GroupID:           "values",
		Short:             "Print a value",
		Args:              nameArg,
		ValidArgsFunction: a.completeNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, s, err := a.open(cmd.Context())
			if err != nil {
				return err
			}
			v, ok := s.Values[args[0]]
			if !ok {
				return fail(1, "%s has no value", args[0])
			}
			fmt.Fprint(a.io.Out, v)
			if a.io.OutTTY {
				fmt.Fprintln(a.io.Out)
			}
			return nil
		},
	}
}

func (a *app) editCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "edit <NAME>",
		GroupID:           "values",
		Short:             "Edit a value in $VISUAL or $EDITOR",
		Long:              "Open the raw value of REDACTED[NAME] in $VISUAL, $EDITOR or vi. The temporary file lives in $XDG_RUNTIME_DIR when set, is readable only by you and is removed afterwards. Nothing is saved if the editor fails or the value is unchanged.",
		Args:              nameArg,
		ValidArgsFunction: a.completeNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.runEdit(cmd.Context(), args[0])
		},
	}
}

func (a *app) runEdit(ctx context.Context, name string) error {
	_, _, s, err := a.open(ctx)
	if err != nil {
		return err
	}
	current, existed := s.Values[name]
	value, err := a.editValue(ctx, name, current)
	if err != nil {
		return err
	}
	if value == current {
		a.ui.ok("%s is unchanged", name)
		return nil
	}
	if value == "" {
		return fail(1, "the value is empty; nothing saved (use redact unset %s to remove it)", name)
	}
	err = a.store(ctx, name, value, &expectation{value: current, existed: existed})
	if errors.Is(err, errChanged) {
		return fail(1, "%v", err)
	}
	return err
}

func editorCommand() string {
	for _, v := range []string{"VISUAL", "EDITOR"} {
		if e := os.Getenv(v); e != "" {
			return e
		}
	}
	return "vi"
}

func (a *app) editValue(ctx context.Context, name, current string) (string, error) {
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" || !fileExists(base) {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "redact-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, name+".txt")
	initial := ""
	if current != "" {
		initial = current + "\n"
	}
	if err := os.WriteFile(file, []byte(initial), 0o600); err != nil {
		return "", err
	}
	editor := editorCommand()
	cmd := shellCommand(ctx, editor+` "$1"`, file)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.io.In, a.io.Out, a.io.Err
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var stopped os.Signal
	var mu sync.Mutex
	stop := func(sig os.Signal) {
		if sig != syscall.SIGTERM && sig != syscall.SIGHUP {
			return
		}
		mu.Lock()
		if stopped == nil {
			stopped = sig
		}
		mu.Unlock()
		_ = cmd.Process.Signal(sig)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case sig := <-sigs:
				stop(sig)
			case <-done:
				return
			}
		}
	}()
	waitErr := cmd.Wait()
	close(done)
	wg.Wait()
	for drained := false; !drained; {
		select {
		case sig := <-sigs:
			stop(sig)
		default:
			drained = true
		}
	}
	if stopped != nil {
		return "", fail(1, "stopped by %v; nothing saved", stopped)
	}
	if waitErr != nil {
		return "", fail(1, "%s exited with an error; nothing saved", editor)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	return trimNewlines(string(b)), nil
}

func (a *app) unsetCommand() *cobra.Command {
	var forget bool
	cmd := &cobra.Command{
		Use:               "unset <NAME>",
		GroupID:           "values",
		Short:             "Remove a value",
		Long:              "Remove the value of REDACTED[NAME]. Redacted files show the token again. The value is kept as a retired value, so it is still tokenised and scanned for, unless --forget is given.",
		Args:              nameArg,
		ValidArgsFunction: a.completeNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			p, kr, s, err := a.open(ctx)
			if err != nil {
				return err
			}
			a.vocabulary(p, kr, s)
			found := false
			ch, err := p.Update(kr, func(s *store.Store) error {
				found = s.Unset(name, forget)
				return nil
			})
			if err != nil {
				return err
			}
			a.reportTrust(ch.Approved)
			if !forget {
				if !found {
					return fail(1, "%s is not in the store", name)
				}
				a.ui.ok("removed %s (its value is retired, not forgotten)", name)
				return a.rehydrateAfter(ctx, p, kr, ch, true)
			}
			if err := a.rehydrateAfter(ctx, p, kr, ch, false); err != nil {
				return fail(1, "%v\n%s is still remembered by this clone, so it stays tokenised; run redact unset --forget %s again once hydrate succeeds", err, name, name)
			}
			forgotten, err := p.Forget(kr, name)
			if err != nil {
				return err
			}
			if !found && !forgotten {
				return fail(1, "%s is not in the store", name)
			}
			a.ui.ok("removed %s and forgot its old values", name)
			return nil
		},
	}
	cmd.Flags().BoolVar(&forget, "forget", false, "also drop its retired values; they will no longer be tokenised or scanned for")
	return cmd
}

func (a *app) listCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		GroupID: "values",
		Short:   "List names, where they are used and what is missing",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, kr, s, err := a.open(ctx)
			if err != nil {
				return err
			}
			lx, _ := a.vocabulary(p, kr, s)
			usage, err := tokenUsage(ctx, p, lx)
			if err != nil {
				return err
			}
			names := s.Names()
			for n := range usage {
				if _, ok := s.Values[n]; !ok {
					names = append(names, n)
				}
			}
			slices.Sort(names)
			if len(names) == 0 {
				a.ui.info("the store is empty; add values with redact set NAME")
				return nil
			}
			tw := tabwriter.NewWriter(a.io.Out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSTATE\tRETIRED\tUSED IN")
			for _, n := range names {
				_, has := s.Values[n]
				state := "ok"
				switch {
				case !has:
					state = "no value"
				case len(usage[n]) == 0:
					state = "unused"
				}
				used := strings.Join(usage[n], ", ")
				if used == "" {
					used = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", n, state, len(s.Retired[n]), used)
			}
			return tw.Flush()
		},
	}
}

func tokenUsage(ctx context.Context, p *project.Project, lx *token.Lexicon) (map[string][]string, error) {
	files, err := p.FilteredFiles(ctx)
	if err != nil {
		return nil, err
	}
	usage := map[string][]string{}
	for _, rel := range files {
		data, err := os.ReadFile(p.Path(rel))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		res, err := token.Tokenise(data, lx)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		for _, n := range token.Names(res.Clean) {
			usage[n] = append(usage[n], rel)
		}
	}
	return usage, nil
}

func (a *app) rekeyCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "rekey",
		GroupID: "setup",
		Short:   "Re-encrypt the store to the recipients in .redact/recipients",
		Long: `Re-encrypt the store to everyone listed in .redact/recipients and trust
exactly that list in this clone. This is the only command that changes who
can read the store: every other write keeps the recipients the store was
encrypted to. Removing a recipient does not take back what they could
already read, so rotate those values too.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, kr, _, err := a.open(cmd.Context())
			if err != nil {
				return err
			}
			res, err := p.Rekey(kr)
			if err != nil {
				return err
			}
			for _, r := range res.Added {
				a.ui.info("  + %s", r)
			}
			for _, r := range res.Removed {
				a.ui.info("  - %s", r)
			}
			a.ui.ok("re-encrypted %s to %d recipient(s)", project.StoreFile, len(res.Recipients))
			if len(res.Added)+len(res.Removed) > 0 {
				a.ui.info("  %s", a.ui.dim("commit "+project.StoreFile+" and "+project.RecipientsFile))
			}
			return nil
		},
	}
}
