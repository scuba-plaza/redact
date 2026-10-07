package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scuba-plaza/redact/internal/vault"
)

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "redact" {
		os.Exit(Main())
	}
	dir, err := os.MkdirTemp("", "redact-bin-")
	if err != nil {
		panic(err)
	}
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "redact")); err != nil {
		panic(err)
	}
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t    *testing.T
	home string
	root string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	e := &env{t: t, home: filepath.Join(base, "home"), root: filepath.Join(base, "repo")}
	for _, d := range []string{e.home, e.root} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitconfig := filepath.Join(e.home, ".gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[user]\n\tname = t\n\temail = t@example.invalid\n[init]\n\tdefaultBranch = main\n[advice]\n\tdetachedHead = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", e.home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(e.home, ".config"))
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("GIT_CONFIG_GLOBAL", gitconfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("NO_COLOR", "1")
	t.Setenv("REDACT_IDENTITY", "")
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	e.git(e.root, "init", "-q")
	return e
}

func (e *env) git(dir string, args ...string) string {
	e.t.Helper()
	out, err := e.gitErr(dir, args...)
	if err != nil {
		e.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func (e *env) gitErr(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type result struct {
	out  string
	err  string
	code int
}

type fakeTTY struct {
	answers map[string]string
	asked   []string
}

func (f *fakeTTY) read(prompt string) (string, error) {
	f.asked = append(f.asked, prompt)
	for k, v := range f.answers {
		if strings.HasPrefix(prompt, k) {
			return v, nil
		}
	}
	return "", nil
}

func (e *env) run(dir, stdin string, args ...string) result {
	return e.runTTY(dir, stdin, nil, args...)
}

func (e *env) runTTY(dir, stdin string, tty *fakeTTY, args ...string) result {
	e.t.Helper()
	var out, errb bytes.Buffer
	stdio := IO{In: strings.NewReader(stdin), Out: &out, Err: &errb}
	if tty != nil {
		stdio.InTTY = true
		stdio.ReadSecret = tty.read
	}
	code := Run(context.Background(), append([]string{"-C", dir}, args...), stdio)
	return result{out: out.String(), err: errb.String(), code: code}
}

func (e *env) ok(dir, stdin string, args ...string) result {
	e.t.Helper()
	r := e.run(dir, stdin, args...)
	if r.code != 0 {
		e.t.Fatalf("redact %v exited %d\nstdout:\n%s\nstderr:\n%s", args, r.code, r.out, r.err)
	}
	return r
}

func (e *env) write(dir, rel, content string) {
	e.t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(dir, rel string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *env) storeBytes(dir string) []byte {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".redact", "secrets.age"))
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

const settings = "{\n  username = \"alice\";\n  email = \"alice@corp.co.uk\";\n}\n"
const tokenised = "{\n  username = \"REDACTED[SYS_USER]\";\n  email = \"REDACTED[EMAIL]\";\n}\n"

func (e *env) bootstrap() {
	e.t.Helper()
	e.write(e.root, "local/settings.nix", settings)
	e.write(e.root, "README.md", "# config\n")
	e.ok(e.root, "", "init")
	e.ok(e.root, "alice\n", "set", "SYS_USER")
	e.ok(e.root, "alice@corp.co.uk", "set", "EMAIL")
	e.ok(e.root, "", "add", "local/settings.nix")
	e.git(e.root, "add", "-A")
	e.git(e.root, "commit", "-qm", "init")
}

func (e *env) clean(dir string) {
	e.t.Helper()
	if st := e.git(dir, "status", "--porcelain"); st != "" {
		e.t.Fatalf("expected a clean tree, got:\n%s", st)
	}
}

func (e *env) unmodified(dir string) {
	e.t.Helper()
	if d := e.git(dir, "diff", "--name-only", "--", ".", ":(exclude).redact"); d != "" {
		e.t.Fatalf("expected no unstaged changes, got:\n%s", d)
	}
}

func contains(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Fatalf("expected %q in:\n%s", n, haystack)
		}
	}
}

func writeStore(t *testing.T, e *env, identity, plaintext string) {
	t.Helper()
	data, err := os.ReadFile(identity)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := vault.ParseKeyring(data)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := vault.ParseRecipients(strings.NewReader(strings.Join(kr.Recipients, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(kr.Recipients))
	for i, r := range kr.Recipients {
		quoted[i] = `"` + r + `"`
	}
	plaintext = strings.ReplaceAll(plaintext, "RECIPIENTS", strings.Join(quoted, ","))
	ct, err := vault.Encrypt([]byte(plaintext), recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.root, ".redact", "secrets.age"), ct, 0o644); err != nil {
		t.Fatal(err)
	}
}
