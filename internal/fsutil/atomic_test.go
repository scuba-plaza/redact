package fsutil

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("got %q", got)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("perm %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestReplaceFileKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(p, []byte("y")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("perm %v", info.Mode().Perm())
	}
}

func TestReplaceFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceFile(link, []byte("y")); err == nil {
		t.Fatal("expected an error for a symlink")
	}
}

func TestCreateExclusiveRefusesExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "key")
	if err := CreateExclusive(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateExclusive(p, []byte("b"), 0o600); err == nil {
		t.Fatal("expected an error for an existing file")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "a" {
		t.Fatalf("existing file was modified: %q", got)
	}
	info, _ := os.Stat(filepath.Dir(p))
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %v", info.Mode().Perm())
	}
}

func TestLockSerialises(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	var mu sync.Mutex
	inside := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := Lock(p)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			if inside != 1 {
				t.Error("two holders inside the lock")
			}
			mu.Unlock()
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
}
