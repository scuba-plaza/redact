//go:build unix

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestEditCleansUpAfterAnInterrupt(t *testing.T) {
	e := newEnv(t)
	e.bootstrap()
	runtime := filepath.Join(e.home, "run")
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	script := filepath.Join(e.home, "editor.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nkill -INT 0\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	cmd := exec.Command("redact", "-C", e.root, "edit", "SYS_USER")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if code := exitCode(err); code != 1 || !strings.Contains(string(out), "nothing saved") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if entries, _ := os.ReadDir(runtime); len(entries) != 0 {
		t.Fatalf("the plaintext temp file was left behind: %v", entries)
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func TestEditAbortsWhenTerminated(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("needs /proc to find the redact process")
	}
	e := newEnv(t)
	e.bootstrap()
	script := filepath.Join(e.home, "editor.sh")
	body := "#!/bin/sh\n" +
		"p=$PPID\n" +
		"case \"$(cat /proc/$p/comm)\" in sh|dash|bash) p=$(cut -d' ' -f4 /proc/$p/stat) ;; esac\n" +
		"trap 'printf changed > \"$1\"; exit 0' TERM\n" +
		"kill -TERM $p\n" +
		"sleep 5 & wait\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	cmd := exec.Command("redact", "-C", e.root, "edit", "SYS_USER")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.CombinedOutput()
	if code := exitCode(err); code != 1 || !strings.Contains(string(out), "nothing saved") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if got := e.ok(e.root, "", "get", "SYS_USER").out; got != "alice" {
		t.Fatalf("saved after SIGTERM: %q", got)
	}
}
