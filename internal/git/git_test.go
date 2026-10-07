package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newRepo(t *testing.T) *Repo {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@example.invalid")
	root := filepath.Join(dir, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	sh(t, root, "git", "init", "-q", "-b", "main")
	r, err := Open(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sh(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFromSubdirectory(t *testing.T) {
	r := newRepo(t)
	sub := filepath.Join(r.Root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Root != r.Root || !strings.HasSuffix(r2.GitDir, ".git") {
		t.Fatalf("got %+v", r2)
	}
}

func TestOpenOutsideRepo(t *testing.T) {
	t.Setenv("GIT_CEILING_DIRECTORIES", os.TempDir())
	_, err := Open(context.Background(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not inside a git repository") {
		t.Fatalf("got %v", err)
	}
}

func TestFilesAndIndex(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	write(t, r.Root, "tracked.txt", "a")
	write(t, r.Root, "dir/ünï code.txt", "b")
	write(t, r.Root, ".gitignore", "ignored\n")
	write(t, r.Root, "ignored", "c")
	sh(t, r.Root, "git", "add", "tracked.txt", "dir", ".gitignore")
	write(t, r.Root, "untracked.txt", "d")

	tracked, err := r.Tracked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tracked, []string{".gitignore", "dir/ünï code.txt", "tracked.txt"}) {
		t.Fatalf("tracked %q", tracked)
	}
	all, err := r.WorktreeFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(all, "untracked.txt") || slices.Contains(all, "ignored") {
		t.Fatalf("worktree files %q", all)
	}
	entries, err := r.Index(ctx, "dir/ünï code.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Mode != "100644" || entries[0].Tag != "H" || entries[0].Path != "dir/ünï code.txt" {
		t.Fatalf("entries %+v", entries)
	}
	br, err := r.Blobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer br.Close()
	data, err := br.Read(entries[0].Blob)
	if err != nil || string(data) != "b" {
		t.Fatalf("blob %q %v", data, err)
	}
	if _, err := br.Read("0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected an error for a missing object")
	}
	data, err = br.Read(entries[0].Blob)
	if err != nil || string(data) != "b" {
		t.Fatalf("reader unusable after a missing object: %q %v", data, err)
	}
}

func TestAttributes(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	write(t, r.Root, ".gitattributes", "/secret.nix filter=redact\ndocs/** -redact-scan\n")
	got, err := r.Attributes(ctx, []string{"secret.nix", "docs/a.md", "other"}, false, "filter", "redact-scan")
	if err != nil {
		t.Fatal(err)
	}
	if got["secret.nix"]["filter"] != "redact" || got["docs/a.md"]["redact-scan"] != "unset" || got["other"]["filter"] != "unspecified" {
		t.Fatalf("got %v", got)
	}
}

func TestConfig(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	if _, ok, err := r.ConfigGet(ctx, "redact.missing", false); ok || err != nil {
		t.Fatalf("missing key: %v %v", ok, err)
	}
	if err := r.ConfigSetLocal(ctx, "redact.identity", "~/id.txt"); err != nil {
		t.Fatal(err)
	}
	v, ok, err := r.ConfigGet(ctx, "redact.identity", true)
	if err != nil || !ok || strings.HasPrefix(v, "~") {
		t.Fatalf("path expansion: %q %v %v", v, ok, err)
	}
}

func TestHistory(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	blobs, err := r.History(ctx)
	if err != nil || len(blobs) != 0 {
		t.Fatalf("empty repo: %v %v", blobs, err)
	}
	write(t, r.Root, "a", "one")
	sh(t, r.Root, "git", "add", "a")
	sh(t, r.Root, "git", "commit", "-qm", "1")
	first := strings.TrimSpace(sh(t, r.Root, "git", "rev-parse", "HEAD"))
	write(t, r.Root, "b c", "one")
	write(t, r.Root, "a", "two")
	sh(t, r.Root, "git", "add", "-A")
	sh(t, r.Root, "git", "commit", "-qm", "2")
	sh(t, r.Root, "git", "rm", "-q", "b c")
	sh(t, r.Root, "git", "commit", "-qm", "3")
	blobs, err = r.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(blobs) != 2 {
		t.Fatalf("expected two unique blobs, got %+v", blobs)
	}
	var one HistoryBlob
	for _, b := range blobs {
		if len(b.Places) == 2 {
			one = b
		}
	}
	paths := []string{one.Places[0].Path, one.Places[1].Path}
	slices.Sort(paths)
	if !slices.Equal(paths, []string{"a", "b c"}) {
		t.Fatalf("places %+v", one.Places)
	}
	for _, pl := range one.Places {
		if pl.Path == "a" && pl.Commit != first {
			t.Fatalf("a should be attributed to the commit that added it, got %+v", pl)
		}
	}
}

func TestHistoryIgnoresMergeConfigAndFindsTaggedBlobs(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	write(t, r.Root, "a", "one")
	sh(t, r.Root, "git", "add", "a")
	sh(t, r.Root, "git", "commit", "-qm", "1")
	sh(t, r.Root, "git", "checkout", "-qb", "side")
	write(t, r.Root, "b", "side")
	sh(t, r.Root, "git", "add", "b")
	sh(t, r.Root, "git", "commit", "-qm", "2")
	sh(t, r.Root, "git", "checkout", "-q", "main")
	write(t, r.Root, "c", "main")
	sh(t, r.Root, "git", "add", "c")
	sh(t, r.Root, "git", "commit", "-qm", "3")
	sh(t, r.Root, "git", "merge", "-q", "--no-edit", "side")
	sh(t, r.Root, "git", "config", "log.diffMerges", "combined")
	sh(t, r.Root, "git", "config", "log.showSignature", "true")
	blob := strings.TrimSpace(sh(t, r.Root, "sh", "-c", "printf 'only tagged' | git hash-object -w --stdin"))
	sh(t, r.Root, "git", "tag", "loose", blob)
	blobs, err := r.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, b := range blobs {
		found[b.Blob] = true
	}
	if len(blobs) != 4 || !found[blob] {
		t.Fatalf("got %+v", blobs)
	}
}

func TestBlobID(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	write(t, r.Root, "f", "hello\n")
	want := strings.TrimSpace(sh(t, r.Root, "git", "hash-object", "f"))
	got, err := r.BlobID(ctx, []byte("hello\n"))
	if err != nil || got != want {
		t.Fatalf("got %q %v, want %q", got, err, want)
	}
}

func TestUnstage(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	write(t, r.Root, "new", "x")
	sh(t, r.Root, "git", "add", "new")
	if err := r.Unstage(ctx, "new"); err != nil {
		t.Fatal(err)
	}
	if out := sh(t, r.Root, "git", "ls-files"); out != "" {
		t.Fatalf("still staged: %q", out)
	}
	write(t, r.Root, "kept", "committed")
	sh(t, r.Root, "git", "add", "kept")
	sh(t, r.Root, "git", "commit", "-qm", "1")
	write(t, r.Root, "kept", "changed")
	sh(t, r.Root, "git", "add", "kept")
	if err := r.Unstage(ctx, "kept"); err != nil {
		t.Fatal(err)
	}
	if got := sh(t, r.Root, "git", "show", ":kept"); got != "committed" {
		t.Fatalf("index holds %q", got)
	}
}

func TestRefreshableSkipsSpecialEntries(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	for _, f := range []string{"plain", "skip", "ita"} {
		write(t, r.Root, f, "x")
	}
	sh(t, r.Root, "git", "add", "plain", "skip")
	sh(t, r.Root, "git", "update-index", "--skip-worktree", "skip")
	sh(t, r.Root, "git", "add", "-N", "ita")
	entries, err := r.Index(ctx, "plain", "skip", "ita")
	if err != nil {
		t.Fatal(err)
	}
	keep := Refreshable(entries)
	if len(keep) != 1 || keep[0].Path != "plain" {
		t.Fatalf("got %+v", keep)
	}
	if err := r.TouchIndexEntries(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if err := r.RefreshIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if st := sh(t, r.Root, "git", "status", "--porcelain"); !strings.Contains(st, " A ita") || !strings.Contains(st, "A  plain\n") {
		t.Fatalf("status:\n%s", st)
	}
}

func TestGitPathAndRevBlob(t *testing.T) {
	ctx := context.Background()
	r := newRepo(t)
	p, err := r.GitPath(ctx, "hooks/pre-commit")
	if err != nil || p != filepath.Join(r.GitDir, "hooks", "pre-commit") {
		t.Fatalf("hook path %q %v", p, err)
	}
	if _, ok, err := r.RevBlob(ctx, "HEAD", "a"); ok || err != nil {
		t.Fatalf("no HEAD yet: %v %v", ok, err)
	}
	write(t, r.Root, "a", "x")
	sh(t, r.Root, "git", "add", "a")
	sh(t, r.Root, "git", "commit", "-qm", "1")
	data, ok, err := r.RevBlob(ctx, "HEAD", "a")
	if err != nil || !ok || string(data) != "x" {
		t.Fatalf("got %q %v %v", data, ok, err)
	}
}
