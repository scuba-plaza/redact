package cli

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/scuba-plaza/redact/internal/scan"
	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/token"
	"github.com/scuba-plaza/redact/internal/vault"
)

func (a *app) checkCommand() *cobra.Command {
	var staged, history, reveal, asJSON, noValues bool
	cmd := &cobra.Command{
		Use:     "check",
		GroupID: "safety",
		Short:   "Scan for private values that would be or have been committed",
		Long: `Scan for stored values, retired values and well-known secret shapes:
private keys, age identities, password hashes, SCRAM verifiers, API tokens,
home directories, email addresses, public IPs and UUIDs.

By default the working tree is scanned as it would be committed (redacted
files are tokenised first). --staged scans the index, which is what the
pre-commit hook runs. --history scans every blob reachable from any ref.

Exclude paths with "path -redact-scan" in .gitattributes. Allow matches
with one regular expression per line in .redact/allow.

Exits with status 1 when anything is found.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if staged && history {
				return fail(2, "--staged and --history cannot be combined")
			}
			p, err := a.project(ctx)
			if err != nil {
				return err
			}
			var secrets []store.Secret
			var lx *token.Lexicon
			switch {
			case noValues:
			case p.StoreExists():
				_, kr, s, err := a.open(ctx)
				switch {
				case err == nil:
					lx, secrets = a.vocabulary(p, kr, s)
				case errors.Is(err, vault.ErrNoIdentity) || errors.Is(err, vault.ErrNotRecipient):
					a.ui.warn("%v\nscanning for well-known secret shapes only", err)
				default:
					return fmt.Errorf("%w\n(use --no-values to scan without the store)", err)
				}
			default:
				if kr, err := a.keyring(ctx, p); err == nil {
					lx, secrets = a.vocabulary(p, kr, store.New())
				}
			}
			allow, err := p.Allow()
			if err != nil {
				return err
			}
			sc := scan.New(scan.Options{Secrets: secrets, Allow: allow, Reveal: reveal})
			mode, src := "working tree", p.WorktreeSource(lx)
			switch {
			case staged:
				mode, src = "index", p.IndexSource()
			case history:
				mode, src = "history", p.HistorySource()
			}
			findings, err := sc.Run(ctx, src)
			if err != nil {
				return err
			}
			if !staged && !history {
				for i := range findings {
					findings[i].Blob = ""
				}
			}
			if asJSON {
				if findings == nil {
					findings = []scan.Finding{}
				}
				enc := json.NewEncoder(a.io.Out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(findings); err != nil {
					return err
				}
			} else {
				for _, f := range findings {
					loc := fmt.Sprintf("%s:%d:%d", f.Path, f.Line, f.Column)
					if f.Commit != "" {
						loc = f.Commit[:min(12, len(f.Commit))] + ":" + loc
					}
					fmt.Fprintf(a.io.Out, "%s  %s  %s\n", a.out.bold(loc), f.Description, a.out.dim(f.Match))
				}
			}
			if len(findings) == 0 {
				a.ui.ok("no private values found in the %s", mode)
				return nil
			}
			a.ui.error("%d finding(s) in the %s", len(findings), mode)
			a.ui.info("Store private values with redact set NAME and reference them as REDACTED[NAME] in a redacted file (redact add PATH).")
			a.ui.info("Not a secret? Allow it in .redact/allow, or exclude the path with \"-redact-scan\" in .gitattributes.")
			return silent()
		},
	}
	f := cmd.Flags()
	f.BoolVar(&staged, "staged", false, "scan the index instead of the working tree")
	f.BoolVar(&history, "history", false, "scan every blob reachable from any ref")
	f.BoolVar(&reveal, "reveal", false, "print matches in full instead of masked")
	f.BoolVar(&asJSON, "json", false, "print findings as JSON")
	f.BoolVar(&noValues, "no-values", false, "do not read the store; only look for well-known secret shapes")
	return cmd
}
