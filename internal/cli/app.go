package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/project"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/vault"
)

var version = ""

func Version() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

type IO struct {
	In         io.Reader
	Out        io.Writer
	Err        io.Writer
	InTTY      bool
	OutTTY     bool
	ErrTTY     bool
	ReadSecret func(prompt string) (string, error)
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error {
	return e.err
}

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

func silent() error {
	return &exitError{code: 1}
}

type app struct {
	io       IO
	ui       *ui
	out      *ui
	dir      string
	identity string
	noColor  bool
	quiet    bool
	proj     *project.Project
}

func Run(ctx context.Context, args []string, stdio IO) int {
	a := &app{io: stdio}
	root := a.rootCommand()
	root.SetArgs(args)
	root.SetIn(stdio.In)
	root.SetOut(stdio.Out)
	root.SetErr(stdio.Err)
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return 0
	}
	if a.ui == nil {
		a.ui = newUI(stdio.Err, stdio.ErrTTY && os.Getenv("NO_COLOR") == "")
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			a.ui.error("%v", ee.err)
		}
		return ee.code
	}
	a.ui.error("%v", err)
	if cmd != nil {
		a.ui.info("Run '%s --help' for usage.", cmd.CommandPath())
	}
	return 2
}

func (a *app) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "redact",
		Short: "Keep private values out of a public git repository",
		Long: `redact keeps private values out of a public git repository while your
working tree keeps them.

Files marked with "filter=redact" in .gitattributes are committed with
REDACTED[NAME] tokens. A git clean filter replaces every stored value with its
token on the way into the index; a smudge filter puts the values back on
checkout. The values live in .redact/secrets.age, encrypted with age to the
recipients listed in .redact/recipients.`,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Version:           Version(),
		PersistentPreRunE: a.setup,
	}
	root.SetVersionTemplate("redact {{.Version}}\n")
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return err
	})
	pf := root.PersistentFlags()
	pf.StringVarP(&a.dir, "directory", "C", "", "run as if redact was started in `dir`")
	pf.StringVar(&a.identity, "identity", "", "age or SSH identity `file` (default: $REDACT_IDENTITY, git config redact.identity, ~/.config/redact/identity.txt)")
	pf.BoolVar(&a.noColor, "no-color", false, "disable coloured output")
	root.AddGroup(
		&cobra.Group{ID: "setup", Title: "Setting up:"},
		&cobra.Group{ID: "values", Title: "Managing values:"},
		&cobra.Group{ID: "files", Title: "Working with files:"},
		&cobra.Group{ID: "safety", Title: "Checking for leaks:"},
	)
	root.AddCommand(
		a.initCommand(),
		a.rekeyCommand(),
		a.setCommand(),
		a.getCommand(),
		a.editCommand(),
		a.unsetCommand(),
		a.listCommand(),
		a.addCommand(),
		a.hydrateCommand(),
		a.statusCommand(),
		a.checkCommand(),
		a.cleanCommand(),
		a.smudgeCommand(),
		a.mergeStoreCommand(),
		a.versionCommand(),
	)
	wrapErrors(root)
	return root
}

func wrapErrors(cmd *cobra.Command) {
	if run := cmd.RunE; run != nil {
		cmd.RunE = func(c *cobra.Command, args []string) error {
			err := run(c, args)
			var ee *exitError
			if err == nil || errors.As(err, &ee) {
				return err
			}
			return &exitError{code: 2, err: err}
		}
	}
	for _, sub := range cmd.Commands() {
		wrapErrors(sub)
	}
}

func (a *app) setup(cmd *cobra.Command, args []string) error {
	allowed := !a.noColor && os.Getenv("NO_COLOR") == ""
	a.ui = newUI(a.io.Err, allowed && a.io.ErrTTY)
	a.ui.quiet = a.quiet
	a.out = newUI(a.io.Out, allowed && a.io.OutTTY)
	return nil
}

func (a *app) workdir() (string, error) {
	if a.dir != "" {
		return filepath.Abs(a.dir)
	}
	return os.Getwd()
}

func (a *app) project(ctx context.Context) (*project.Project, error) {
	if a.proj != nil {
		return a.proj, nil
	}
	dir, err := a.workdir()
	if err != nil {
		return nil, err
	}
	p, err := project.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	a.proj = p
	return p, nil
}

func (a *app) identityPath(ctx context.Context, p *project.Project) (string, string, error) {
	if a.identity != "" {
		path, err := expandHome(a.identity)
		return path, "--identity", err
	}
	if v := os.Getenv("REDACT_IDENTITY"); v != "" {
		path, err := expandHome(v)
		return path, "REDACT_IDENTITY", err
	}
	if p != nil {
		v, ok, err := p.Repo.ConfigGet(ctx, "redact.identity", true)
		if err != nil {
			return "", "", err
		}
		if ok && v != "" {
			if !filepath.IsAbs(v) && !strings.HasPrefix(v, "~") {
				v = filepath.Join(p.Repo.MainRoot(), v)
			}
			path, err := expandHome(v)
			return path, "git config redact.identity", err
		}
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "redact", "identity.txt"), "default", nil
}

func expandHome(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, p[1:])
	}
	return filepath.Abs(p)
}

func (a *app) keyring(ctx context.Context, p *project.Project) (*vault.Keyring, error) {
	path, source, err := a.identityPath(ctx, p)
	if err != nil {
		return nil, err
	}
	kr, err := vault.LoadKeyring(path)
	if errors.Is(err, vault.ErrNoIdentity) {
		return nil, fmt.Errorf("%w (from %s); copy your identity there, or point --identity, REDACT_IDENTITY or git config redact.identity at it", err, source)
	}
	return kr, err
}

func (a *app) open(ctx context.Context) (*project.Project, *vault.Keyring, *store.Store, error) {
	p, err := a.project(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if !p.StoreExists() {
		return nil, nil, nil, fmt.Errorf("no store at %s (run: redact init)", project.StoreFile)
	}
	kr, err := a.keyring(ctx, p)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := p.LoadStore(kr)
	if err != nil {
		return nil, nil, nil, err
	}
	return p, kr, s, nil
}

func (a *app) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(a.io.Out, "redact %s\n", Version())
			return nil
		},
	}
}
