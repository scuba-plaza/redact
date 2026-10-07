package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/scuba-plaza/redact/internal/store"
	"github.com/scuba-plaza/redact/internal/vault"
)

func TestLifecycle(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()

	if got := e.git(e.root, "show", "HEAD:local/settings.nix"); got != tokenised {
		t.Fatalf("committed content:\n%s", got)
	}
	if got := e.read(e.root, "local/settings.nix"); got != settings {
		t.Fatalf("working tree:\n%s", got)
	}
	e.clean(e.root)
	if info, err := os.Stat(filepath.Join(e.home, ".config", "redact", "identity.txt")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("identity: %v %v", info, err)
	}
	st := e.ok(e.root, "", "status")
	contains(t, st.out, "filter      configured", "local/settings.nix  hydrated")
	ls := e.ok(e.root, "", "list")
	contains(t, ls.out, "EMAIL     ok", "SYS_USER  ok", "local/settings.nix")
	for _, mode := range [][]string{{"check"}, {"check", "--staged"}, {"check", "--history"}} {
		r := e.ok(e.root, "", mode...)
		contains(t, r.err, "no private values found")
	}
	if got := e.ok(e.root, "", "get", "EMAIL").out; got != "alice@corp.co.uk" {
		t.Fatalf("get: %q", got)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	before := e.storeBytes(e.root)
	r := e.ok(e.root, "", "init")
	contains(t, r.err, "can read .redact/secrets.age", "up to date")
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("init rewrote the store")
	}
}

func TestFreshCloneHydratesOnInit(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	clone := filepath.Join(filepath.Dir(e.root), "clone")
	e.git(filepath.Dir(e.root), "clone", "-q", e.root, clone)
	if got := e.read(clone, "local/settings.nix"); got != tokenised {
		t.Fatalf("before init:\n%s", got)
	}
	st := e.run(clone, "", "status")
	if st.code != 1 {
		t.Fatalf("status should report the missing filter, got %d\n%s", st.code, st.out)
	}
	contains(t, st.out, "not configured")
	e.ok(clone, "", "init")
	if got := e.read(clone, "local/settings.nix"); got != settings {
		t.Fatalf("after init:\n%s", got)
	}
	e.clean(clone)
}

func TestGlobalFilterHydratesDuringClone(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.git(e.root, "config", "--global", "filter.redact.clean", "redact clean -- %f")
	e.git(e.root, "config", "--global", "filter.redact.smudge", "redact smudge -- %f")
	e.git(e.root, "config", "--global", "filter.redact.required", "true")
	clone := filepath.Join(filepath.Dir(e.root), "clone")
	e.git(filepath.Dir(e.root), "clone", "-q", e.root, clone)
	if got := e.read(clone, "local/settings.nix"); got != settings {
		t.Fatalf("clone was not smudged:\n%s", got)
	}
}

func TestRotationKeepsLocalEdits(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "local/settings.nix", strings.Replace(settings, "}", "  extra = true;\n}", 1))
	e.ok(e.root, "bob", "set", "SYS_USER")
	got := e.read(e.root, "local/settings.nix")
	if !strings.Contains(got, `username = "bob"`) || !strings.Contains(got, "extra = true;") {
		t.Fatalf("working tree:\n%s", got)
	}
	diff := e.git(e.root, "diff", "--", "local/settings.nix")
	if strings.Contains(diff, "bob") || strings.Contains(diff, "alice") || !strings.Contains(diff, "+  extra = true;") {
		t.Fatalf("diff:\n%s", diff)
	}
}

func TestGitOperationsKeepTheTreeHydrated(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "local/settings.nix", strings.Replace(settings, "}", "  extra = true;\n}", 1))
	e.git(e.root, "stash", "-q")
	if got := e.read(e.root, "local/settings.nix"); got != settings {
		t.Fatalf("after stash:\n%s", got)
	}
	e.git(e.root, "stash", "pop", "-q")
	if !strings.Contains(e.read(e.root, "local/settings.nix"), "extra = true;") {
		t.Fatal("stash pop lost the edit")
	}
	e.git(e.root, "checkout", "--", "local/settings.nix")
	if got := e.read(e.root, "local/settings.nix"); got != settings {
		t.Fatalf("after checkout:\n%s", got)
	}
	if err := os.Remove(filepath.Join(e.root, "local/settings.nix")); err != nil {
		t.Fatal(err)
	}
	e.git(e.root, "reset", "-q", "--hard")
	if got := e.read(e.root, "local/settings.nix"); got != settings {
		t.Fatalf("after reset:\n%s", got)
	}
	e.git(e.root, "checkout", "-q", "-b", "other")
	e.git(e.root, "checkout", "-q", "main")
	e.clean(e.root)
}

func TestStoreRollbackNeverLeaksTheNewerValue(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.ok(e.root, "bob", "set", "SYS_USER")
	e.git(e.root, "reset", "-q", "--hard")
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("store after reset: %q", got)
	}
	e.clean(e.root)
	if st := e.run(e.root, "", "status"); st.code != 1 || !strings.Contains(st.out, "stale") {
		t.Fatalf("status: %d\n%s", st.code, st.out)
	}
	e.write(e.root, "notes.txt", "bob was here\n")
	e.git(e.root, "add", "-A")
	if got := e.git(e.root, "show", ":local/settings.nix"); got != tokenised {
		t.Fatalf("index:\n%s", got)
	}
	r := e.run(e.root, "", "check", "--staged")
	if r.code != 1 {
		t.Fatalf("check --staged should flag bob: %d\n%s", r.code, r.err)
	}
	contains(t, r.out, "notes.txt:1:1", "retired value of SYS_USER")
	e.ok(e.root, "", "hydrate")
	if got := e.read(e.root, "local/settings.nix"); got != settings {
		t.Fatalf("hydrate:\n%s", got)
	}
}

func TestPreCommitBlocksLeaks(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "notes.md", "ping alice about carol@corp.co.uk\n")
	e.git(e.root, "add", "notes.md")
	out, err := e.gitErr(e.root, "commit", "-qm", "leak")
	if err == nil {
		t.Fatal("the commit went through")
	}
	contains(t, out, "notes.md:1:6", "value of SYS_USER", "notes.md:1:18", "email address")
	if strings.Contains(out, "carol@corp.co.uk") {
		t.Fatal("the finding was not masked")
	}
	e.write(e.root, "notes.md", "nothing to see\n")
	e.git(e.root, "add", "notes.md")
	e.git(e.root, "commit", "-qm", "fine")
}

func TestCleanFailsClosedWithoutIdentity(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	t.Setenv("REDACT_IDENTITY", filepath.Join(e.home, "missing"))
	e.write(e.root, "local/settings.nix", strings.Replace(settings, "}", "  extra = true;\n}", 1))
	out, err := e.gitErr(e.root, "add", "local/settings.nix")
	if err == nil {
		t.Fatal("git add succeeded without an identity")
	}
	contains(t, out, "refusing to let git store local/settings.nix")
	if got := e.git(e.root, "show", ":local/settings.nix"); got != tokenised {
		t.Fatalf("index changed:\n%s", got)
	}
}

func TestSmudgeWithoutIdentityLeavesTokens(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	if err := os.Remove(filepath.Join(e.root, "local/settings.nix")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDACT_IDENTITY", filepath.Join(e.home, "missing"))
	out := e.git(e.root, "checkout", "--", "local/settings.nix")
	contains(t, out, "leaving local/settings.nix tokenised")
	if got := e.read(e.root, "local/settings.nix"); got != tokenised {
		t.Fatalf("got:\n%s", got)
	}
}

func TestWrongIdentityCannotDamageTheStore(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	other := filepath.Join(e.home, "other.txt")
	file, _, err := vault.Generate(true, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, file, 0o600); err != nil {
		t.Fatal(err)
	}
	before := e.storeBytes(e.root)
	r := e.run(e.root, "carol", "--identity", other, "set", "SYS_USER")
	if r.code == 0 {
		t.Fatal("set succeeded with the wrong identity")
	}
	contains(t, r.err, "is not a recipient of this store")
	r = e.run(e.root, "", "--identity", other, "init")
	if r.code == 0 {
		t.Fatal("init succeeded with the wrong identity")
	}
	contains(t, r.err, "add one of these to .redact/recipients")
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("the store changed")
	}
}

func TestSetValidation(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	cases := []struct {
		stdin string
		args  []string
		want  string
	}{
		{"value", []string{"set", "lower"}, "is not valid"},
		{"ab", []string{"set", "SHORT"}, "at least 3 bytes"},
		{"xREDACTED[Y]z", []string{"set", "TOK"}, `must not contain "REDACTED["`},
		{"\n\n", []string{"set", "EMPTY"}, "empty value"},
		{"", []string{"set"}, "accepts 1 arg"},
	}
	for _, c := range cases {
		r := e.run(e.root, c.stdin, c.args...)
		if r.code == 0 || !strings.Contains(r.err, c.want) {
			t.Errorf("%v: code %d, stderr:\n%s", c.args, r.code, r.err)
		}
	}
}

func TestNoopsDoNotRewriteTheStore(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	before := e.storeBytes(e.root)
	r := e.ok(e.root, "alice", "set", "SYS_USER")
	contains(t, r.err, "SYS_USER is unchanged")
	e.ok(e.root, "", "hydrate")
	e.ok(e.root, "", "status")
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("a no-op rewrote the store")
	}
}

func TestUnsetAndForget(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.ok(e.root, "", "unset", "EMAIL")
	if got := e.read(e.root, "local/settings.nix"); !strings.Contains(got, `email = "REDACTED[EMAIL]"`) {
		t.Fatalf("token did not come back:\n%s", got)
	}
	e.unmodified(e.root)
	e.write(e.root, "notes.txt", "alice@corp.co.uk\n")
	r := e.run(e.root, "", "check")
	contains(t, r.out, "retired value of EMAIL")
	e.ok(e.root, "", "unset", "--forget", "EMAIL")
	r = e.run(e.root, "", "check", "--json")
	var fs []map[string]any
	if err := json.Unmarshal([]byte(r.out), &fs); err != nil {
		t.Fatalf("%v\n%s", err, r.out)
	}
	if len(fs) == 0 {
		t.Fatal("expected the address to still be reported")
	}
	for _, f := range fs {
		if strings.Contains(f["description"].(string), "of EMAIL") {
			t.Fatalf("a forgotten value is still scanned for: %v", f)
		}
	}
	if r := e.run(e.root, "", "unset", "NOPE"); r.code != 1 {
		t.Fatalf("unset of a missing name: %d", r.code)
	}
}

func TestEdit(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	script := filepath.Join(e.home, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'Host box\\n  HostName box.lan\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	e.ok(e.root, "", "edit", "SSH_CONFIG")
	if got := e.ok(e.root, "", "get", "SSH_CONFIG").out; got != "Host box\n  HostName box.lan" {
		t.Fatalf("got %q", got)
	}
	before := e.storeBytes(e.root)
	t.Setenv("EDITOR", "false")
	if r := e.run(e.root, "", "edit", "SSH_CONFIG"); r.code != 1 || !strings.Contains(r.err, "nothing saved") {
		t.Fatalf("failing editor: %d %s", r.code, r.err)
	}
	t.Setenv("EDITOR", "true")
	r := e.ok(e.root, "", "edit", "SSH_CONFIG")
	contains(t, r.err, "unchanged")
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("the store changed")
	}
}

func TestRecipientsAndRekey(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	second := filepath.Join(e.home, "second.txt")
	file, rec, err := vault.Generate(false, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, file, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.run(e.root, "", "--identity", second, "get", "SYS_USER"); r.code == 0 {
		t.Fatal("second identity could read before rekey")
	}
	recipients := filepath.Join(e.root, ".redact", "recipients")
	f, err := os.OpenFile(recipients, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(rec + "\n")
	f.Close()
	if st := e.run(e.root, "", "status"); st.code != 1 || !strings.Contains(st.out, "redact rekey") {
		t.Fatalf("status should ask for a rekey:\n%s", st.out)
	}
	e.ok(e.root, "", "rekey")
	if got := e.ok(e.root, "", "--identity", second, "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("second identity: %q", got)
	}
	e.ok(e.root, "", "status")
	if err := os.WriteFile(recipients, []byte(rec+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.ok(e.root, "carol", "set", "SYS_USER")
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "carol" {
		t.Fatalf("an edited recipients file must not change who can read the store: %q", got)
	}
	before := e.storeBytes(e.root)
	r := e.run(e.root, "", "rekey")
	if r.code == 0 || !strings.Contains(r.err, "refusing to write a store you could not read back") {
		t.Fatalf("removing yourself: %d\n%s", r.code, r.err)
	}
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("the store changed")
	}
}

func TestHydratePromptsForMissingValues(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init")
	e.write(e.root, "local/ssh.conf", "Host REDACTED[HOST]\n  User REDACTED[SSH_USER]\n")
	e.ok(e.root, "", "add", "local/ssh.conf")
	r := e.run(e.root, "", "hydrate")
	if r.code != 1 {
		t.Fatalf("hydrate without a terminal: %d", r.code)
	}
	contains(t, r.err, "REDACTED[HOST] has no value", "redact set HOST")
	tty := &fakeTTY{answers: map[string]string{"HOST": "box.lan", "SSH_USER": ""}}
	r = e.runTTY(e.root, "", tty, "hydrate")
	if r.code != 1 {
		t.Fatalf("SSH_USER was skipped, so hydrate is incomplete: %d\n%s", r.code, r.err)
	}
	if got := e.read(e.root, "local/ssh.conf"); got != "Host box.lan\n  User REDACTED[SSH_USER]\n" {
		t.Fatalf("got:\n%s", got)
	}
	if len(tty.asked) != 2 || !strings.Contains(tty.asked[0], "used in local/ssh.conf") {
		t.Fatalf("prompts: %q", tty.asked)
	}
	e.unmodified(e.root)
}

func TestAddPaths(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init")
	e.ok(e.root, "alice", "set", "SYS_USER")
	e.write(e.root, "deep/dir/a[1].nix", "user alice\n")
	e.ok(filepath.Join(e.root, "deep"), "", "add", "dir/a[1].nix")
	attrs := e.read(e.root, ".gitattributes")
	contains(t, attrs, `/deep/dir/a\[1].nix filter=redact`)
	if got := e.git(e.root, "show", ":deep/dir/a[1].nix"); got != "user REDACTED[SYS_USER]\n" {
		t.Fatalf("index:\n%s", got)
	}
	r := e.run(e.root, "", "add", "deep/dir/a[1].nix")
	if r.code != 0 || strings.Count(e.read(e.root, ".gitattributes"), "filter=redact") != 1 {
		t.Fatalf("adding twice: %d\n%s", r.code, e.read(e.root, ".gitattributes"))
	}
	e.write(e.root, "with space.nix", "x\n")
	if r := e.run(e.root, "", "add", "with space.nix"); r.code == 0 {
		t.Fatal("a path with a space was accepted")
	}
	if r := e.run(e.root, "", "add", "../outside"); r.code == 0 || !strings.Contains(r.err, "outside the repository") {
		t.Fatalf("outside: %d %s", r.code, r.err)
	}
	if r := e.run(e.root, "", "add", ".redact/recipients"); r.code == 0 {
		t.Fatal("redact's own files were accepted")
	}
}

func TestAddWarnsAboutHistory(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init")
	e.write(e.root, "conf.nix", "user alice\n")
	e.git(e.root, "add", "conf.nix")
	e.git(e.root, "commit", "-qm", "oops", "--no-verify")
	e.ok(e.root, "alice", "set", "SYS_USER")
	r := e.ok(e.root, "", "add", "conf.nix")
	contains(t, r.err, "HEAD already holds conf.nix with real values")
	h := e.run(e.root, "", "check", "--history", "--reveal")
	if h.code != 1 {
		t.Fatalf("history: %d", h.code)
	}
	head := strings.TrimSpace(e.git(e.root, "rev-parse", "--short=12", "HEAD"))
	contains(t, h.out, head+":conf.nix:1:6", "alice")
}

func TestCheckExclusions(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "docs/a.md", "mail me: dave@corp.co.uk\n")
	e.write(e.root, "b.md", "server 93.184.216.34\n")
	if r := e.run(e.root, "", "check"); r.code != 1 || !strings.Contains(r.out, "docs/a.md") || !strings.Contains(r.out, "b.md") {
		t.Fatalf("before exclusions: %d\n%s", r.code, r.out)
	}
	e.write(e.root, ".gitattributes", e.read(e.root, ".gitattributes")+"docs/** -redact-scan\n")
	e.write(e.root, ".redact/allow", "# documentation server\n93\\.184\\.216\\.34\n")
	e.ok(e.root, "", "check")
	if r := e.run(e.root, "", "check", "--staged", "--history"); r.code != 2 {
		t.Fatalf("conflicting flags: %d", r.code)
	}
}

func TestCheckWithoutStore(t *testing.T) {
	e := newEnv(t)
	e.write(e.root, "a.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	r := e.run(e.root, "", "check")
	if r.code != 1 || !strings.Contains(r.out, "private key") {
		t.Fatalf("%d\n%s%s", r.code, r.out, r.err)
	}
}

func TestCheckNoValuesWithoutIdentity(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	clone := filepath.Join(filepath.Dir(e.root), "collaborator")
	e.git(filepath.Dir(e.root), "clone", "-q", e.root, clone)
	t.Setenv("REDACT_IDENTITY", filepath.Join(e.home, "missing"))
	if r := e.run(clone, "", "init"); r.code != 2 {
		t.Fatalf("init without an identity: %d", r.code)
	}
	r := e.ok(clone, "", "check", "--staged")
	contains(t, r.err, "scanning for well-known secret shapes only")
	for range 3 {
		if err := os.Chtimes(filepath.Join(clone, "local", "settings.nix"), timeNow(), timeNow()); err != nil {
			t.Fatal(err)
		}
		e.write(clone, "README.md", "# config\nmore docs\n"+timeNow().String()+"\n")
		e.git(clone, "add", "README.md")
	}
	e.git(clone, "commit", "-qm", "docs by a collaborator without access")
	e.write(clone, "key.txt", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	e.git(clone, "add", "key.txt")
	if out, err := e.gitErr(clone, "commit", "-qm", "key"); err == nil || !strings.Contains(out, "private key") {
		t.Fatalf("shape rules did not run without access: %v\n%s", err, out)
	}
	e.write(clone, "local/settings.nix", settings)
	if _, err := e.gitErr(clone, "add", "local/settings.nix"); err == nil {
		t.Fatal("real values were staged without an identity")
	}
	e.git(clone, "rm", "-q", "--cached", "key.txt")
	e.ok(clone, "", "check", "--staged", "--no-values")
}

func TestPostHydrateHook(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	marker := filepath.Join(e.home, "marker")
	e.git(e.root, "config", "redact.postHydrate", "touch "+marker)
	e.ok(e.root, "bob", "set", "SYS_USER")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("postHydrate did not run")
	}
}

func TestPullHydratesThroughPostMerge(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	clone := filepath.Join(filepath.Dir(e.root), "clone")
	e.git(filepath.Dir(e.root), "clone", "-q", e.root, clone)
	e.ok(clone, "", "init")
	e.ok(e.root, "bob", "set", "SYS_USER")
	e.git(e.root, "commit", "-qam", "rotate")
	e.git(clone, "pull", "-q", "--ff-only")
	if got := e.read(clone, "local/settings.nix"); !strings.Contains(got, `username = "bob"`) {
		t.Fatalf("post-merge did not hydrate:\n%s", got)
	}
	e.clean(clone)
}

func TestConcurrentSets(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	var wg sync.WaitGroup
	names := []string{"A_ONE", "A_TWO", "A_THREE", "A_FOUR", "A_FIVE", "A_SIX"}
	errs := make(chan error, len(names))
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("redact", "-C", e.root, "set", n)
			cmd.Stdin = strings.NewReader("value-of-" + n)
			if out, err := cmd.CombinedOutput(); err != nil {
				errs <- err
				t.Logf("%s", out)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	ls := e.ok(e.root, "", "list").out
	for _, n := range names {
		contains(t, ls, n)
	}
}

func TestMixingClassicAndPostQuantumRecipientsIsRefused(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	_, rec, err := vault.Generate(true, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	recipients := filepath.Join(e.root, ".redact", "recipients")
	if err := os.WriteFile(recipients, []byte(e.read(e.root, ".redact/recipients")+rec+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := e.run(e.root, "", "rekey")
	if r.code != 2 || !strings.Contains(r.err, "can't mix post-quantum and classic recipients") || strings.Contains(r.err, "--help") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
}

func TestStoreIsPlainAge(t *testing.T) {
	if _, err := exec.LookPath("age"); err != nil {
		t.Skip("age is not installed")
	}
	e := newEnv(t)
	e.bootstrap()
	out, err := exec.Command("age", "-d", "-i", filepath.Join(e.home, ".config", "redact", "identity.txt"), filepath.Join(e.root, ".redact", "secrets.age")).Output()
	if err != nil {
		t.Skipf("this age cannot read post-quantum files: %v", err)
	}
	s, err := store.Decode(out)
	if err != nil || s.Values["SYS_USER"] != "alice" {
		t.Fatalf("%v %+v", err, s)
	}
}

func TestClassicIdentityAndVersion(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init", "--classic")
	id := e.read(e.home, ".config/redact/identity.txt")
	if !strings.Contains(id, "AGE-SECRET-KEY-1") {
		t.Fatalf("identity:\n%s", id)
	}
	if got := e.ok(e.root, "", "version").out; !strings.HasPrefix(got, "redact ") {
		t.Fatalf("version: %q", got)
	}
	if r := e.run(e.root, "", "frobnicate"); r.code != 2 || !strings.Contains(r.err, "unknown command") {
		t.Fatalf("unknown command: %d %s", r.code, r.err)
	}
}

func TestOutsideRepository(t *testing.T) {
	e := newEnv(t)
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(e.home))
	r := e.run(e.home, "", "status")
	if r.code != 1 || !strings.Contains(r.out, "not inside a git repository") {
		t.Fatalf("%d\n%s%s", r.code, r.out, r.err)
	}
	if r := e.run(e.home, "", "init"); r.code != 2 {
		t.Fatalf("init outside a repo: %d", r.code)
	}
}
