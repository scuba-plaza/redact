package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type Repo struct {
	Root      string
	GitDir    string
	CommonDir string
}

type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.Args, " "), msg)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func ExitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &Error{Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

func Open(ctx context.Context, dir string) (*Repo, error) {
	out, err := run(ctx, dir, nil, "rev-parse", "--path-format=absolute", "--show-toplevel", "--absolute-git-dir", "--git-common-dir")
	if err != nil {
		var ge *Error
		if errors.As(err, &ge) && strings.Contains(ge.Stderr, "not a git repository") {
			return nil, fmt.Errorf("%s is not inside a git repository", dir)
		}
		if errors.As(err, &ge) && strings.Contains(ge.Stderr, "must be run in a work tree") {
			return nil, fmt.Errorf("%s is not inside a git work tree", dir)
		}
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 3 || lines[0] == "" {
		return nil, fmt.Errorf("%s is not inside a git work tree", dir)
	}
	return &Repo{Root: lines[0], GitDir: lines[1], CommonDir: filepath.Clean(lines[2])}, nil
}

func (r *Repo) MainRoot() string {
	if filepath.Base(r.CommonDir) == ".git" {
		return filepath.Dir(r.CommonDir)
	}
	return r.Root
}

func (r *Repo) Run(ctx context.Context, args ...string) ([]byte, error) {
	return run(ctx, r.Root, nil, args...)
}

func (r *Repo) RunInput(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	return run(ctx, r.Root, stdin, args...)
}

func splitZ(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := strings.Split(string(b), "\x00")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func (r *Repo) Tracked(ctx context.Context) ([]string, error) {
	out, err := r.Run(ctx, "ls-files", "-z", "--cached", "--deduplicate")
	if err != nil {
		return nil, err
	}
	return splitZ(out), nil
}

func (r *Repo) WorktreeFiles(ctx context.Context) ([]string, error) {
	out, err := r.Run(ctx, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--deduplicate")
	if err != nil {
		return nil, err
	}
	return splitZ(out), nil
}

type Entry struct {
	Tag   string
	Mode  string
	Blob  string
	Stage int
	Path  string
}

func (r *Repo) Index(ctx context.Context, paths ...string) ([]Entry, error) {
	args := []string{"ls-files", "-z", "--stage", "-t", "-v"}
	if len(paths) > 0 {
		args = append(args, "--")
		args = append(args, literal(paths)...)
	}
	out, err := r.Run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, rec := range splitZ(out) {
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			return nil, fmt.Errorf("unexpected ls-files output %q", rec)
		}
		f := strings.Fields(meta)
		if len(f) != 4 {
			return nil, fmt.Errorf("unexpected ls-files output %q", rec)
		}
		stage, err := strconv.Atoi(f[3])
		if err != nil {
			return nil, err
		}
		entries = append(entries, Entry{Tag: f[0], Mode: f[1], Blob: f[2], Stage: stage, Path: path})
	}
	return entries, nil
}

func literal(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = ":(literal)" + p
	}
	return out
}

func (r *Repo) Attributes(ctx context.Context, paths []string, cached bool, attrs ...string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string, len(paths))
	if len(paths) == 0 {
		return result, nil
	}
	var in bytes.Buffer
	for _, p := range paths {
		in.WriteString(p)
		in.WriteByte(0)
	}
	args := []string{"check-attr", "-z", "--stdin"}
	if cached {
		args = append(args, "--cached")
	}
	args = append(args, attrs...)
	out, err := r.RunInput(ctx, in.Bytes(), args...)
	if err != nil {
		return nil, err
	}
	parts := splitZ(out)
	if len(parts)%3 != 0 {
		return nil, fmt.Errorf("unexpected check-attr output")
	}
	for i := 0; i < len(parts); i += 3 {
		path, attr, value := parts[i], parts[i+1], parts[i+2]
		if result[path] == nil {
			result[path] = map[string]string{}
		}
		result[path][attr] = value
	}
	return result, nil
}

func (r *Repo) ConfigGet(ctx context.Context, key string, path bool) (string, bool, error) {
	args := []string{"config", "--get"}
	if path {
		args = []string{"config", "--type=path", "--get"}
	}
	out, err := r.Run(ctx, append(args, key)...)
	if err != nil {
		if ExitCode(err) == 1 {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimRight(string(out), "\n"), true, nil
}

func (r *Repo) ConfigSetLocal(ctx context.Context, key, value string) error {
	_, err := r.Run(ctx, "config", "--local", key, value)
	return err
}

func (r *Repo) GitPath(ctx context.Context, name string) (string, error) {
	out, err := r.Run(ctx, "rev-parse", "--git-path", name)
	if err != nil {
		return "", err
	}
	p := strings.TrimRight(string(out), "\n")
	if !filepath.IsAbs(p) {
		p = filepath.Join(r.Root, p)
	}
	return filepath.Clean(p), nil
}

func (r *Repo) Add(ctx context.Context, paths ...string) error {
	_, err := r.Run(ctx, append([]string{"add", "--"}, literal(paths)...)...)
	return err
}

func (r *Repo) RefreshIndex(ctx context.Context) error {
	_, err := r.Run(ctx, "update-index", "-q", "--refresh")
	if err != nil && ExitCode(err) == 1 {
		return nil
	}
	return err
}

func (r *Repo) RevBlob(ctx context.Context, rev, path string) ([]byte, bool, error) {
	out, err := r.Run(ctx, "cat-file", "blob", rev+":"+path)
	if err != nil {
		if ExitCode(err) == 128 {
			return nil, false, nil
		}
		return nil, false, err
	}
	return out, true, nil
}

type Place struct {
	Commit string
	Path   string
}

type HistoryBlob struct {
	Blob   string
	Places []Place
}

func (r *Repo) stream(ctx context.Context, read func(*bufio.Reader) error, args ...string) error {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.Root
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	readErr := read(bufio.NewReaderSize(out, 256*1024))
	if readErr != nil {
		_, _ = io.Copy(io.Discard, out)
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	if waitErr != nil {
		return &Error{Args: args, Stderr: stderr.String(), Err: waitErr}
	}
	return nil
}

type history struct {
	index map[string]int
	seen  map[[3]string]bool
	blobs []HistoryBlob
}

func (h *history) add(blob string, place Place) {
	k, ok := h.index[blob]
	if !ok {
		k = len(h.blobs)
		h.index[blob] = k
		h.blobs = append(h.blobs, HistoryBlob{Blob: blob})
	}
	key := [3]string{blob, place.Commit, place.Path}
	if h.seen[key] {
		return
	}
	h.seen[key] = true
	h.blobs[k].Places = append(h.blobs[k].Places, place)
}

func (r *Repo) History(ctx context.Context) ([]HistoryBlob, error) {
	if _, err := r.Run(ctx, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		refs, rerr := r.Run(ctx, "for-each-ref", "--count=1", "--format=%(refname)")
		if rerr != nil {
			return nil, rerr
		}
		if len(bytes.TrimSpace(refs)) == 0 {
			return nil, nil
		}
	}
	h := &history{index: map[string]int{}, seen: map[[3]string]bool{}}
	err := r.stream(ctx, func(rd *bufio.Reader) error { return parseLog(rd, h) },
		"log", "--all", "--root", "--diff-merges=separate", "--no-renames", "--no-color",
		"--no-show-signature", "--no-ext-diff", "--no-textconv", "--raw", "--no-abbrev", "-z", "--format=%x01%H")
	if err != nil {
		return nil, err
	}
	var extra [][2]string
	err = r.stream(ctx, func(rd *bufio.Reader) error {
		for {
			line, err := rd.ReadString('\n')
			line = strings.TrimSuffix(line, "\n")
			if line != "" {
				sha, path, _ := strings.Cut(line, " ")
				if _, known := h.index[sha]; !known {
					extra = append(extra, [2]string{sha, path})
				}
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}, "rev-list", "--objects", "--all", "--filter=object:type=blob", "--filter-provided-objects")
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return h.blobs, nil
	}
	var input bytes.Buffer
	for _, e := range extra {
		input.WriteString(e[0] + "\n")
	}
	out, err := r.RunInput(ctx, input.Bytes(), "cat-file", "--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		return nil, err
	}
	types := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if sha, typ, ok := strings.Cut(line, " "); ok {
			types[sha] = typ
		}
	}
	for _, e := range extra {
		sha, path := e[0], e[1]
		if types[sha] != "blob" {
			continue
		}
		if path == "" {
			path = "(tagged blob " + sha[:min(12, len(sha))] + ")"
		}
		h.add(sha, Place{Path: path})
	}
	return h.blobs, nil
}

func parseLog(rd *bufio.Reader, h *history) error {
	var commit string
	for {
		tok, err := rd.ReadString(0)
		if errors.Is(err, io.EOF) && tok == "" {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		tok = strings.TrimLeft(strings.TrimSuffix(tok, "\x00"), "\n")
		switch {
		case strings.HasPrefix(tok, "\x01"):
			commit = tok[1:]
		case strings.HasPrefix(tok, ":"):
			meta := strings.Fields(tok[1:])
			if len(meta) != 5 {
				return fmt.Errorf("unexpected git log record %q", tok)
			}
			path, perr := rd.ReadString(0)
			if perr != nil && !errors.Is(perr, io.EOF) {
				return perr
			}
			path = strings.TrimSuffix(path, "\x00")
			newMode, newBlob, status := meta[1], meta[3], meta[4]
			if status != "D" && newMode != "160000" && newMode != "000000" {
				h.add(newBlob, Place{Commit: commit, Path: path})
			}
		case tok == "":
		default:
			return fmt.Errorf("unexpected git log record %q", tok)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func (r *Repo) BlobID(ctx context.Context, data []byte) (string, error) {
	out, err := r.RunInput(ctx, data, "hash-object", "--no-filters", "--stdin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (r *Repo) Unstage(ctx context.Context, path string) error {
	if _, err := r.Run(ctx, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
		_, err = r.Run(ctx, "reset", "-q", "HEAD", "--", ":(literal)"+path)
		return err
	}
	_, err := r.Run(ctx, "rm", "--cached", "-q", "--", ":(literal)"+path)
	return err
}

var emptyBlobs = map[string]bool{
	"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391":                         true,
	"473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813": true,
}

func Refreshable(entries []Entry) []Entry {
	var keep []Entry
	for _, e := range entries {
		if e.Stage == 0 && e.Tag == "H" && !emptyBlobs[e.Blob] {
			keep = append(keep, e)
		}
	}
	return keep
}

func (r *Repo) TouchIndexEntries(ctx context.Context, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	var in bytes.Buffer
	for _, e := range entries {
		fmt.Fprintf(&in, "%s %s\t%s\x00", e.Mode, e.Blob, e.Path)
	}
	_, err := r.RunInput(ctx, in.Bytes(), "update-index", "-z", "--index-info")
	return err
}

type BlobReader struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr bytes.Buffer
}

func (r *Repo) Blobs(ctx context.Context) (*BlobReader, error) {
	cmd := exec.CommandContext(ctx, "git", "cat-file", "--batch")
	cmd.Dir = r.Root
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	br := &BlobReader{cmd: cmd}
	cmd.Stderr = &br.stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	br.stdin = stdin
	br.stdout = bufio.NewReaderSize(stdout, 64*1024)
	return br, nil
}

func (b *BlobReader) Read(sha string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := io.WriteString(b.stdin, sha+"\n"); err != nil {
		return nil, b.wrap(err)
	}
	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return nil, b.wrap(err)
	}
	f := strings.Fields(header)
	if len(f) == 2 && f[1] == "missing" {
		return nil, fmt.Errorf("object %s is missing", sha)
	}
	if len(f) != 3 {
		return nil, fmt.Errorf("unexpected cat-file header %q", header)
	}
	size, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, err
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(b.stdout, data); err != nil {
		return nil, b.wrap(err)
	}
	if f[1] != "blob" {
		return nil, fmt.Errorf("object %s is a %s, not a blob", sha, f[1])
	}
	return data[:size], nil
}

func (b *BlobReader) wrap(err error) error {
	if msg := strings.TrimSpace(b.stderr.String()); msg != "" {
		return fmt.Errorf("git cat-file: %s", msg)
	}
	return fmt.Errorf("git cat-file: %w", err)
}

func (b *BlobReader) Close() error {
	_ = b.stdin.Close()
	return b.cmd.Wait()
}
