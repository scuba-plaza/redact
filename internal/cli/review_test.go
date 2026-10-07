package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scuba-plaza/redact/internal/vault"
)

func secondIdentity(t *testing.T, e *env, classic bool) (string, string) {
	t.Helper()
	file, rec, err := vault.Generate(classic, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.home, "attacker.txt")
	if err := os.WriteFile(path, file, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, rec
}

func TestEditedRecipientsFileCannotWidenAccess(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	attacker, rec := secondIdentity(t, e, false)
	e.write(e.root, ".redact/recipients", e.read(e.root, ".redact/recipients")+rec+"\n")
	e.ok(e.root, "bob", "set", "SYS_USER")
	if r := e.run(e.root, "", "--identity", attacker, "get", "SYS_USER"); r.code == 0 {
		t.Fatal("a recipient added to the file could read the store without a rekey")
	}
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "lists 1 more and 0 fewer than the store") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	r := e.ok(e.root, "", "rekey")
	contains(t, r.err, "  + "+rec)
	if got := e.ok(e.root, "", "--identity", attacker, "get", "SYS_USER").out; got != "bob" {
		t.Fatalf("after rekey: %q", got)
	}
}

func TestCraftedStoreWithAnUntrustedRecipientIsRefused(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	_, rec := secondIdentity(t, e, false)
	own := filepath.Join(e.home, ".config", "redact", "identity.txt")
	data, _ := os.ReadFile(own)
	kr, _ := vault.ParseKeyring(data)
	recs, err := vault.ParseRecipients(strings.NewReader(kr.Recipients[0] + "\n" + rec))
	if err != nil {
		t.Fatal(err)
	}
	crafted := `{"version":1,"values":{"SYS_USER":"alice"},"retired":{},"recipients":["` + kr.Recipients[0] + `","` + rec + `"]}`
	ct, err := vault.Encrypt([]byte(crafted), recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.root, ".redact", "secrets.age"), ct, 0o644); err != nil {
		t.Fatal(err)
	}
	before := e.storeBytes(e.root)
	r := e.run(e.root, "s3cret-value", "set", "NEW_SECRET")
	if r.code == 0 || !strings.Contains(r.err, "not trusted yet") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
	if !bytes.Equal(before, e.storeBytes(e.root)) {
		t.Fatal("the store was written")
	}
	if st := e.run(e.root, "", "status"); st.code != 1 || !strings.Contains(st.out, "not trusted in this clone") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
}

func TestInitWithoutIdentityStillProtectsTheClone(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	clone := filepath.Join(filepath.Dir(e.root), "clone")
	e.git(filepath.Dir(e.root), "clone", "-q", e.root, clone)
	t.Setenv("REDACT_IDENTITY", filepath.Join(e.home, "missing"))
	r := e.run(clone, "", "init")
	if r.code != 2 || !strings.Contains(r.err, "git refuses to stage redacted files") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
	e.write(clone, "local/settings.nix", settings)
	if out, err := e.gitErr(clone, "add", "local/settings.nix"); err == nil {
		t.Fatalf("a real value was staged without an identity:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(clone, ".git", "hooks", "pre-commit")); err != nil {
		t.Fatal("the pre-commit hook was not installed")
	}
	if !strings.Contains(e.read(clone, ".git/info/exclude"), ".*.redact-tmp-*") {
		t.Fatal("temporary files are not excluded")
	}
}

func TestEditRefusesAConcurrentChange(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	script := filepath.Join(e.home, "editor.sh")
	body := "#!/bin/sh\nprintf other | redact -C " + e.root + " set SYS_USER >/dev/null 2>&1\nprintf mine > \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	r := e.run(e.root, "", "edit", "SYS_USER")
	if r.code != 1 || !strings.Contains(r.err, "changed while you were editing") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "other" {
		t.Fatalf("got %q", got)
	}
}

func TestCheckWithoutAStoreStillUsesValuesSeenBefore(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	if err := os.Remove(filepath.Join(e.root, ".redact", "secrets.age")); err != nil {
		t.Fatal(err)
	}
	e.write(e.root, "notes.txt", "ask alice\n")
	r := e.run(e.root, "", "check")
	if r.code != 1 || !strings.Contains(r.out, "notes.txt:1:5") {
		t.Fatalf("%d\n%s%s", r.code, r.out, r.err)
	}
}

func TestHistoryScansEveryPathAndNamesTheIntroducingCommit(t *testing.T) {
	e := newEnv(t)
	e.write(e.root, ".gitattributes", "adocs/** -redact-scan\n")
	e.write(e.root, "adocs/x", "mail dave@corp.co.uk\n")
	e.write(e.root, "zconf/y", "mail dave@corp.co.uk\n")
	e.git(e.root, "add", "-A")
	e.git(e.root, "commit", "-qm", "add", "--no-verify")
	added := strings.TrimSpace(e.git(e.root, "rev-parse", "--short=12", "HEAD"))
	e.git(e.root, "rm", "-q", "zconf/y")
	e.git(e.root, "commit", "-qm", "remove", "--no-verify")
	r := e.run(e.root, "", "check", "--history", "--no-values")
	if r.code != 1 || !strings.Contains(r.out, added+":zconf/y:1:6") {
		t.Fatalf("%d\n%s", r.code, r.out)
	}
}

func TestStagedScanUsesTheIndexAttributes(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "secrets/a.txt", "dave@corp.co.uk\n")
	e.git(e.root, "add", "secrets/a.txt")
	e.write(e.root, ".gitattributes", e.read(e.root, ".gitattributes")+"secrets/** -redact-scan\n")
	r := e.run(e.root, "", "check", "--staged")
	if r.code != 1 || !strings.Contains(r.out, "secrets/a.txt") {
		t.Fatalf("an unstaged exclusion hid a staged leak: %d\n%s", r.code, r.out)
	}
}

func TestBinaryFilesWithAValueAreBlocked(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "dump.bin", "abc\x00def alice@corp.co.uk")
	e.git(e.root, "add", "dump.bin")
	if out, err := e.gitErr(e.root, "commit", "-qm", "dump"); err == nil || !strings.Contains(out, "value of EMAIL") {
		t.Fatalf("binary leak committed: %v\n%s", err, out)
	}
}

func TestForgetWorksForValuesOnlyThisCloneRemembers(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.ok(e.root, "oops-value", "set", "XNAME")
	e.git(e.root, "checkout", "-q", "--", ".redact/secrets.age")
	e.write(e.root, "notes.txt", "oops-value\n")
	if r := e.run(e.root, "", "check"); r.code != 1 || !strings.Contains(r.out, "retired value of XNAME") {
		t.Fatalf("%d\n%s", r.code, r.out)
	}
	e.ok(e.root, "", "unset", "--forget", "XNAME")
	e.ok(e.root, "", "check")
}

func TestAddWithInfoAttributesAndRepeatedPaths(t *testing.T) {
	e := newEnv(t)
	e.ok(e.root, "", "init")
	e.ok(e.root, "alice", "set", "SYS_USER")
	e.write(e.root, ".git/info/attributes", "/b.nix filter=redact\n")
	e.write(e.root, "b.nix", "user alice\n")
	e.ok(e.root, "", "add", "b.nix", "b.nix", "./b.nix")
	if strings.Contains(e.read(e.root, ".gitattributes"), "b.nix") {
		t.Fatal(".gitattributes got a line for an already filtered path")
	}
	if got := e.git(e.root, "show", ":b.nix"); got != "user REDACTED[SYS_USER]\n" {
		t.Fatalf("index: %q", got)
	}
	e.write(e.root, "c.nix", "user alice\n")
	e.ok(e.root, "", "add", "c.nix", "c.nix")
	if n := strings.Count(e.read(e.root, ".gitattributes"), "/c.nix filter=redact"); n != 1 {
		t.Fatalf("%d attribute lines", n)
	}
}

func TestIntentToAddSurvivesRehydration(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, ".gitattributes", e.read(e.root, ".gitattributes")+"/local/b.nix filter=redact\n")
	e.write(e.root, "local/b.nix", "user alice\n")
	e.git(e.root, "add", "-N", "local/b.nix")
	e.ok(e.root, "bob", "set", "SYS_USER")
	if got := e.read(e.root, "local/b.nix"); got != "user bob\n" {
		t.Fatalf("not rehydrated: %q", got)
	}
	if st := e.git(e.root, "status", "--porcelain", "--", "local/b.nix"); st != " A local/b.nix\n" {
		t.Fatalf("intent-to-add lost: %q", st)
	}
}

func TestIdentityWithClassicAndPostQuantumKeys(t *testing.T) {
	e := newEnv(t)
	classic, _, _ := vault.Generate(true, timeNow())
	pq, _, _ := vault.Generate(false, timeNow())
	path := filepath.Join(e.home, ".config", "redact", "identity.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(pq, classic...), 0o600); err != nil {
		t.Fatal(err)
	}
	e.write(e.root, ".redact/recipients", strings.Split(strings.Split(string(pq), "# public key: ")[1], "\n")[0]+"\n")
	e.write(e.root, "local/settings.nix", settings)
	e.ok(e.root, "", "init")
	r := e.ok(e.root, "alice", "set", "SYS_USER")
	if strings.Contains(r.err, "warning") {
		t.Fatalf("stderr:\n%s", r.err)
	}
	if _, err := os.Stat(filepath.Join(e.root, ".git", "redact", "known.age")); err != nil {
		t.Fatal("the cache of values seen before was not written")
	}
}

func TestUnreadableCacheIsReportedAndReplacedByRekey(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	known := filepath.Join(e.root, ".git", "redact", "known.age")
	if err := os.WriteFile(known, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := e.run(e.root, "", "status")
	if st.code != 1 || !strings.Contains(st.out, "cannot read the cache") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
	if r := e.run(e.root, "bob", "set", "SYS_USER"); r.code == 0 {
		t.Fatal("a write went ahead without a readable list of trusted recipients")
	}
	e.ok(e.root, "", "rekey")
	if _, err := os.Stat(known + ".unreadable"); err != nil {
		t.Fatal("the unreadable cache was not kept aside")
	}
	e.ok(e.root, "", "status")
}

func TestDuplicateValuesAreRefused(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	r := e.run(e.root, "alice", "set", "OTHER_USER")
	if r.code != 2 || !strings.Contains(r.err, "SYS_USER already holds this value") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
}

func TestHooksPathIsReportedAccurately(t *testing.T) {
	e := newEnv(t)
	e.git(e.root, "config", "core.hooksPath", ".githooks")
	r := e.ok(e.root, "", "init")
	contains(t, r.err, "core.hooksPath is set", "redact check --staged || exit 1")
	if st := e.run(e.root, "", "status"); st.code != 1 || !strings.Contains(st.out, "not managed (core.hooksPath)") {
		t.Fatalf("%d\n%s", st.code, st.out)
	}
}

func TestRelativeIdentityInGitConfigUsesTheRepositoryRoot(t *testing.T) {
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
	if got := e.ok(filepath.Join(e.root, "local"), "", "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("got %q", got)
	}
}

func TestSetReportsAStoredValueThatCouldNotBeRehydrated(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	e.write(e.root, "local/odd.nix", "x = \"REDACTED[REDACTED[Q]\";\n")
	e.ok(e.root, "", "add", "local/odd.nix")
	r := e.run(e.root, "XY]", "set", "Q")
	if r.code != 1 || !strings.Contains(r.err, "the store was saved, but the redacted files were not rehydrated") {
		t.Fatalf("%d\n%s", r.code, r.err)
	}
	if got := e.ok(e.root, "", "get", "Q").out; got != "XY]" {
		t.Fatalf("got %q", got)
	}
}
