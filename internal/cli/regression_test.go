package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestForgetThatCannotRehydrateKeepsTheValueTokenised(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "local/aaa.nix", "x = \"REDACTED[REDACTED[Q]\";\n")
	e.ok(e.root, "", "add", "local/aaa.nix")
	if r := e.run(e.root, "XY]", "set", "Q"); r.code != 1 {
		t.Fatalf("setting Q should fail to rehydrate: %d\n%s", r.code, r.err)
	}
	r := e.run(e.root, "", "unset", "--forget", "SYS_USER")
	if r.code != 1 || !strings.Contains(r.err, "still remembered by this clone") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
	e.write(e.root, "local/aaa.nix", "x = 1;\n")
	e.ok(e.root, "", "unset", "--forget", "Q")
	if h := e.run(e.root, "", "hydrate"); h.code != 1 || !strings.Contains(h.err, "REDACTED[SYS_USER] has no value") {
		t.Fatalf("%d\n%s", h.code, h.err)
	}
	if got := e.read(e.root, "local/settings.nix"); !strings.Contains(got, "REDACTED[SYS_USER]") {
		t.Fatalf("the forgotten value is back in clear:\n%s", got)
	}
	e.git(e.root, "add", "-A")
	if got := e.git(e.root, "show", ":local/settings.nix"); strings.Contains(got, "alice\"") {
		t.Fatalf("the value was staged in clear:\n%s", got)
	}
	e.ok(e.root, "", "unset", "--forget", "SYS_USER")
}

func TestMergeDropsRecipientsThisCloneDoesNotTrust(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	one, two := twoClones(t, e)
	attacker, rec := secondIdentity(t, e, false)
	e.write(one, ".redact/recipients", e.read(one, ".redact/recipients")+rec+"\n")
	e.ok(one, "", "rekey")
	e.ok(one, "carol", "set", "SYS_USER")
	e.git(one, "commit", "-qam", "add a recipient")
	e.ok(two, "two-only", "set", "TWO")
	e.git(two, "commit", "-qam", "two")
	out, err := e.gitErr(two, "pull", "--no-rebase", "--no-edit", one, "main")
	if err == nil || !strings.Contains(out, "recipients this clone does not trust") {
		t.Fatalf("expected the merge to stop:\n%s", out)
	}
	if r := e.run(two, "", "--identity", attacker, "get", "TWO"); r.code == 0 {
		t.Fatal("the merged store was encrypted to an untrusted recipient")
	}
	if got := e.ok(two, "", "get", "SYS_USER").out; got != "carol" {
		t.Fatalf("their change was lost: %q", got)
	}
}

func TestEditRemovesThePlaintextBeforeSaving(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	runtime := filepath.Join(e.home, "run")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	script := filepath.Join(e.home, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf carol > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	marker := filepath.Join(e.home, "count")
	e.git(e.root, "config", "redact.postHydrate", "ls -A "+runtime+" | wc -l > "+marker)
	e.ok(e.root, "", "edit", "SYS_USER")
	if got := strings.TrimSpace(e.read(e.home, "count")); got != "0" {
		t.Fatalf("the temp file still existed while postHydrate ran: %s entries", got)
	}
}

func TestInitRestoresTheStoreMergeAttribute(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, ".gitattributes", "/local/settings.nix filter=redact\n")
	r := e.ok(e.root, "", "init")
	contains(t, r.err, "marked .redact/secrets.age for the merge driver")
	contains(t, e.read(e.root, ".gitattributes"), "/.redact/secrets.age merge=redact-store")
}

func TestMissingMergeDriverDoesNotBlockAdd(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.git(e.root, "config", "--unset", "merge.redact-store.driver")
	e.write(e.root, "local/more.nix", "u = \"alice\";\n")
	e.ok(e.root, "", "add", "local/more.nix")
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "merge driver is not configured") || !strings.Contains(st.out, "filter      configured") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
}

func TestStatusReportsAnUnpinnedClone(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	if err := os.Remove(filepath.Join(e.root, ".git", "redact", "known.age")); err != nil {
		t.Fatal(err)
	}
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "has not pinned the recipients it trusts") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	e.ok(e.root, "", "init")
	e.ok(e.root, "", "status")
}

func TestRelativeIdentityWorksInLinkedWorktrees(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	keys := filepath.Join(e.root, ".git", "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(e.home, ".config", "redact", "identity.txt"), filepath.Join(keys, "id.txt")); err != nil {
		t.Fatal(err)
	}
	e.git(e.root, "config", "redact.identity", ".git/keys/id.txt")
	wt := filepath.Join(filepath.Dir(e.root), "wt")
	e.git(e.root, "worktree", "add", "-q", wt)
	if got := e.ok(wt, "", "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("got %q", got)
	}
	if got := e.read(wt, "local/settings.nix"); got != settings {
		t.Fatalf("the linked worktree was not hydrated:\n%s", got)
	}
}
