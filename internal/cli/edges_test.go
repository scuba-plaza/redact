package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityFromGitConfig(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	moved := filepath.Join(e.home, "keys", "redact.txt")
	if err := os.MkdirAll(filepath.Dir(moved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(e.home, ".config", "redact", "identity.txt"), moved); err != nil {
		t.Fatal(err)
	}
	if r := e.run(e.root, "", "get", "SYS_USER"); r.code != 2 || !strings.Contains(r.err, "no identity at") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	e.git(e.root, "config", "redact.identity", "~/keys/redact.txt")
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("got %q", got)
	}
	if err := os.Chmod(moved, 0o644); err != nil {
		t.Fatal(err)
	}
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "readable by others") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
}

func TestForeignPreCommitHook(t *testing.T) {
	e := newEnv(t)
	hook := filepath.Join(e.root, ".git", "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := e.ok(e.root, "", "init")
	if !strings.Contains(r.err, "was left alone") || !strings.Contains(r.err, "redact check --staged || exit 1") {
		t.Fatalf("stderr:\n%s", r.err)
	}
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "pre-commit foreign") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	e.ok(e.root, "", "init", "--force-hooks")
	e.ok(e.root, "", "status")
}

func TestSymlinkTargetsAreScanned(t *testing.T) {
	e := newEnv(t)
	if err := os.Symlink("/home/alice/.ssh/config", filepath.Join(e.root, "link")); err != nil {
		t.Fatal(err)
	}
	r := e.run(e.root, "", "check")
	if r.code != 1 || !strings.Contains(r.out, "link:1:1  home directory") {
		t.Fatalf("%d\n%s", r.code, r.out)
	}
}

func TestEditUsesRuntimeDirAndCleansUp(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	runtime := filepath.Join(e.home, "run")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	script := filepath.Join(e.home, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncase \"$1\" in \""+runtime+"\"/*) printf 'carol\\n' > \"$1\" ;; *) exit 1 ;; esac\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", script)
	e.ok(e.root, "", "edit", "SYS_USER")
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "carol" {
		t.Fatalf("got %q", got)
	}
	if !strings.Contains(e.read(e.root, "local/settings.nix"), `"carol"`) {
		t.Fatal("not rehydrated")
	}
	entries, _ := os.ReadDir(runtime)
	if len(entries) != 0 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestMalformedMarkersAreReported(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init")
	e.ok(e.root, "box.lan", "set", "HOST")
	e.write(e.root, "ssh.conf", "Host REDACTED[HOST]\n  User REDACTED[ssh_user]\n")
	r := e.ok(e.root, "", "add", "ssh.conf")
	contains(t, r.err, "ssh.conf: malformed REDACTED[…] marker on line 2")
	h := e.ok(e.root, "", "hydrate")
	contains(t, h.err, "malformed REDACTED[…] marker on line 2")
	if got := e.read(e.root, "ssh.conf"); got != "Host box.lan\n  User REDACTED[ssh_user]\n" {
		t.Fatalf("got:\n%s", got)
	}
	st := e.ok(e.root, "", "status")
	contains(t, st.out, "! ", "ssh.conf  malformed REDACTED[…] marker on line 2", "✓ file        ssh.conf  hydrated")
}

func TestStatusReportsEveryProblemOfAFile(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.ok(e.root, "bob", "set", "SYS_USER")
	e.git(e.root, "reset", "-q", "--hard")
	stale := strings.Replace(settings, "alice\"", "bob\"", 1)
	e.write(e.root, "local/settings.nix", strings.Replace(stale, "}", "  x = \"REDACTED[NEW]\";\n}", 1))
	st := e.run(e.root, "", "status")
	if st.code != 1 {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	contains(t, st.out, "no value for NEW; stale; run: redact hydrate")
}

func TestInvalidStoreEntryCanBeRepaired(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	p := e.run(e.root, "", "get", "SYS_USER")
	if p.code != 0 {
		t.Fatal(p.err)
	}
	kr := filepath.Join(e.home, ".config", "redact", "identity.txt")
	broken := `{"version":1,"values":{"EMAIL":"alice@corp.co.uk","SYS_USER":"alice"},"retired":{"OLD":["xREDACTED[Y]z"]},"recipients":[RECIPIENTS]}`
	writeStore(t, e, kr, broken)
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "redact unset --forget OLD") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	if r := e.run(e.root, "carol", "set", "SYS_USER"); r.code == 0 || !strings.Contains(r.err, "refusing to write") {
		t.Fatalf("%d %s", r.code, r.err)
	}
	e.ok(e.root, "", "unset", "--forget", "OLD")
	e.ok(e.root, "", "status")
}
