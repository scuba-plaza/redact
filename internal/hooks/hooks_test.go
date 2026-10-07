package hooks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/scuba-plaza/redact/internal/git"
)

func repo(t *testing.T) *git.Repo {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	root := filepath.Join(dir, "repo")
	if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	r, err := git.Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func states(sts []Status) map[string]State {
	m := map[string]State{}
	for _, s := range sts {
		m[s.Hook.Name] = s.State
	}
	return m
}

func TestInstallLeavesForeignHooksAlone(t *testing.T) {
	ctx := context.Background()
	r := repo(t)
	foreign := filepath.Join(r.GitDir, "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\nmake lint\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sts, err := Install(ctx, r, false)
	if err != nil {
		t.Fatal(err)
	}
	m := states(sts)
	if m["pre-commit"] != Foreign || m["post-checkout"] != Installed || m["post-merge"] != Installed {
		t.Fatalf("got %v", m)
	}
	data, _ := os.ReadFile(foreign)
	if string(data) != "#!/bin/sh\nmake lint\n" {
		t.Fatal("foreign hook was overwritten")
	}
	info, _ := os.Stat(filepath.Join(r.GitDir, "hooks", "post-merge"))
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("hook is not executable")
	}
	sts, err = Install(ctx, r, true)
	if err != nil {
		t.Fatal(err)
	}
	if states(sts)["pre-commit"] != Updated {
		t.Fatal("force did not install")
	}
	again, _ := Inspect(ctx, r)
	for _, s := range again {
		if s.State != Installed {
			t.Fatalf("%s is %v", s.Hook.Name, s.State)
		}
	}
}

func TestOlderRedactHooksAreUpdated(t *testing.T) {
	ctx := context.Background()
	r := repo(t)
	old := filepath.Join(r.GitDir, "hooks", "pre-commit")
	if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("#!/bin/sh\nredact_hook=0\nexec redact check --staged --old-flag\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sts, err := Inspect(ctx, r)
	if err != nil || states(sts)["pre-commit"] != Outdated {
		t.Fatalf("%v %v", states(sts), err)
	}
	sts, err = Install(ctx, r, false)
	if err != nil || states(sts)["pre-commit"] != Updated {
		t.Fatalf("%v %v", states(sts), err)
	}
	data, _ := os.ReadFile(old)
	if string(data) != All[0].Script {
		t.Fatalf("not updated:\n%s", data)
	}
}

func TestHooksPathOutsideRepoIsNotTouched(t *testing.T) {
	ctx := context.Background()
	r := repo(t)
	shared := t.TempDir()
	if out, err := exec.Command("git", "-C", r.Root, "config", "core.hooksPath", shared).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	sts, err := Install(ctx, r, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sts {
		if s.State != Unmanaged {
			t.Fatalf("%s is %v", s.Hook.Name, s.State)
		}
	}
	entries, _ := os.ReadDir(shared)
	if len(entries) != 0 {
		t.Fatal("wrote into a shared hooks directory")
	}
}

func TestUnreadableHookUnderHooksPathIsNotAnError(t *testing.T) {
	ctx := context.Background()
	r := repo(t)
	shared := t.TempDir()
	if err := os.Mkdir(filepath.Join(shared, "pre-commit"), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", r.Root, "config", "core.hooksPath", shared).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	sts, err := Inspect(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if states(sts)["pre-commit"] != Unmanaged {
		t.Fatalf("got %v", states(sts))
	}
}
