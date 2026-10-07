package hooks

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/scuba-plaza/redact/internal/fsutil"
	"github.com/scuba-plaza/redact/internal/git"
)

const marker = "redact_hook="

type Hook struct {
	Name   string
	Line   string
	Script string
}

const (
	checkLine   = "redact check --staged || exit 1"
	hydrateLine = "redact hydrate --no-prompt --quiet || true"
)

var All = []Hook{
	{
		Name: "pre-commit",
		Line: checkLine,
		Script: `#!/bin/sh
` + marker + `1
if ! command -v redact >/dev/null 2>&1; then
	echo "pre-commit: redact is not on PATH; refusing to commit without a secret scan" >&2
	exit 1
fi
exec redact check --staged
`,
	},
	{
		Name: "post-checkout",
		Line: hydrateLine,
		Script: `#!/bin/sh
` + marker + `1
command -v redact >/dev/null 2>&1 || exit 0
` + hydrateLine + `
`,
	},
	{
		Name: "post-merge",
		Line: hydrateLine,
		Script: `#!/bin/sh
` + marker + `1
command -v redact >/dev/null 2>&1 || exit 0
` + hydrateLine + `
`,
	},
}

type State int

const (
	Missing State = iota
	Installed
	Outdated
	Updated
	Foreign
	Unmanaged
)

func (s State) String() string {
	switch s {
	case Missing:
		return "missing"
	case Installed, Updated:
		return "installed"
	case Outdated:
		return "outdated"
	case Foreign:
		return "foreign"
	default:
		return "not managed (core.hooksPath)"
	}
}

type Status struct {
	Hook  Hook
	Path  string
	State State
}

func ours(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, marker) {
			return true
		}
	}
	return false
}

func Inspect(ctx context.Context, r *git.Repo) ([]Status, error) {
	out := make([]Status, 0, len(All))
	for _, h := range All {
		p, err := r.GitPath(ctx, "hooks/"+h.Name)
		if err != nil {
			return nil, err
		}
		st := Status{Hook: h, Path: p}
		data, err := os.ReadFile(p)
		switch {
		case !inside(r.CommonDir, p):
			st.State = Unmanaged
			if err == nil && bytes.Equal(data, []byte(h.Script)) {
				st.State = Installed
			}
		case err != nil && !errors.Is(err, fs.ErrNotExist):
			return nil, err
		case err == nil && bytes.Equal(data, []byte(h.Script)):
			st.State = Installed
		case err != nil:
			st.State = Missing
		case ours(data):
			st.State = Outdated
		default:
			st.State = Foreign
		}
		out = append(out, st)
	}
	return out, nil
}

func inside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func Install(ctx context.Context, r *git.Repo, force bool) ([]Status, error) {
	states, err := Inspect(ctx, r)
	if err != nil {
		return nil, err
	}
	for i, st := range states {
		switch {
		case st.State == Installed || st.State == Unmanaged:
			continue
		case st.State == Foreign && !force:
			continue
		}
		if err := os.MkdirAll(filepath.Dir(st.Path), 0o755); err != nil {
			return nil, err
		}
		if err := fsutil.WriteFileAtomic(st.Path, []byte(st.Hook.Script), 0o755); err != nil {
			return nil, err
		}
		if st.State == Missing {
			states[i].State = Installed
		} else {
			states[i].State = Updated
		}
	}
	return states, nil
}
