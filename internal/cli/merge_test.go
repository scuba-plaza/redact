package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func twoClones(t *testing.T, e *env) (string, string) {
	t.Helper()
	parent := filepath.Dir(e.root)
	one, two := filepath.Join(parent, "one"), filepath.Join(parent, "two")
	for _, c := range []string{one, two} {
		e.git(parent, "clone", "-q", e.root, c)
		e.ok(c, "", "init")
	}
	return one, two
}

func TestStoreMergesCleanly(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	contains(t, e.read(e.root, ".gitattributes"), "/.redact/secrets.age merge=redact-store")
	one, two := twoClones(t, e)
	e.ok(one, "host-one", "set", "HOST_ONE")
	e.git(one, "commit", "-qam", "one")
	e.ok(two, "host-two", "set", "HOST_TWO")
	e.ok(two, "bob", "set", "SYS_USER")
	e.git(two, "commit", "-qam", "two")
	e.git(two, "pull", "-q", "--no-rebase", "--no-edit", one, "main")
	for name, want := range map[string]string{"HOST_ONE": "host-one", "HOST_TWO": "host-two", "SYS_USER": "bob", "EMAIL": "alice@corp.co.uk"} {
		if got := e.ok(two, "", "get", name).out; got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	e.clean(two)
}

func TestStoreMergeConflictKeepsOursAndCanBeResolved(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	one, two := twoClones(t, e)
	e.ok(one, "carol", "set", "SYS_USER")
	e.git(one, "commit", "-qam", "one")
	e.ok(two, "dave", "set", "SYS_USER")
	e.git(two, "commit", "-qam", "two")
	out, err := e.gitErr(two, "pull", "--no-rebase", "--no-edit", one, "main")
	if err == nil {
		t.Fatalf("expected a conflict:\n%s", out)
	}
	contains(t, out, "both sides changed SYS_USER")
	if got := e.ok(two, "", "get", "SYS_USER").out; got != "dave" {
		t.Fatalf("got %q", got)
	}
	e.ok(two, "carol", "set", "SYS_USER")
	e.git(two, "add", ".redact/secrets.age")
	e.git(two, "commit", "-qm", "merge", "--no-edit")
	r := e.run(two, "", "check", "--staged")
	if r.code != 0 {
		t.Fatalf("%s%s", r.out, r.err)
	}
	if !strings.Contains(e.read(two, "local/settings.nix"), `"carol"`) {
		t.Fatal("not rehydrated after resolving")
	}
}
