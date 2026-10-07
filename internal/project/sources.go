package project

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"github.com/scuba-plaza/redact/internal/scan"
	"github.com/scuba-plaza/redact/internal/token"
)

func skipped(path string) bool {
	return path == StoreFile || path == AllowFile
}

type scanAttrs struct {
	filtered map[string]bool
	skip     map[string]bool
}

func (p *Project) scanAttrs(ctx context.Context, paths []string, cached bool) (*scanAttrs, error) {
	attrs, err := p.Repo.Attributes(ctx, paths, cached, "filter", ScanAttr)
	if err != nil {
		return nil, err
	}
	sa := &scanAttrs{filtered: map[string]bool{}, skip: map[string]bool{}}
	for _, path := range paths {
		a := attrs[path]
		sa.filtered[path] = a["filter"] == FilterName
		sa.skip[path] = a[ScanAttr] == "unset" || a[ScanAttr] == "false" || skipped(path)
	}
	return sa, nil
}

func (p *Project) WorktreeSource(lx *token.Lexicon) scan.Source {
	return func(ctx context.Context, emit func(scan.Item) error) error {
		paths, err := p.Repo.WorktreeFiles(ctx)
		if err != nil {
			return err
		}
		sa, err := p.scanAttrs(ctx, paths, false)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if sa.skip[path] {
				continue
			}
			data, err := readWorktree(p.Path(path))
			if err != nil {
				return err
			}
			if data == nil {
				continue
			}
			if sa.filtered[path] && lx != nil {
				res, err := token.Tokenise(data, lx)
				if err != nil {
					return &PathError{Path: path, Err: err}
				}
				data = res.Clean
			}
			if err := emit(scan.Item{Path: path, Data: data, Strict: sa.filtered[path]}); err != nil {
				return err
			}
		}
		return nil
	}
}

type PathError struct {
	Path string
	Err  error
}

func (e *PathError) Error() string {
	return e.Path + ": " + e.Err.Error()
}

func (e *PathError) Unwrap() error {
	return e.Err
}

func readWorktree(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case info.Mode().IsRegular():
		return os.ReadFile(path)
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		return []byte(target), nil
	}
	return nil, nil
}

func (p *Project) IndexSource() scan.Source {
	return func(ctx context.Context, emit func(scan.Item) error) error {
		entries, err := p.Repo.Index(ctx)
		if err != nil {
			return err
		}
		paths := make([]string, 0, len(entries))
		for _, e := range entries {
			paths = append(paths, e.Path)
		}
		sa, err := p.scanAttrs(ctx, paths, true)
		if err != nil {
			return err
		}
		blobs, err := p.Repo.Blobs(ctx)
		if err != nil {
			return err
		}
		defer blobs.Close()
		seen := map[string]bool{}
		for _, e := range entries {
			if e.Mode == "160000" || sa.skip[e.Path] || seen[e.Blob+"\x00"+e.Path] {
				continue
			}
			seen[e.Blob+"\x00"+e.Path] = true
			data, err := blobs.Read(e.Blob)
			if err != nil {
				return err
			}
			if err := emit(scan.Item{Path: e.Path, Blob: e.Blob, Data: data, Strict: sa.filtered[e.Path]}); err != nil {
				return err
			}
		}
		return nil
	}
}

func (p *Project) HistorySource() scan.Source {
	return func(ctx context.Context, emit func(scan.Item) error) error {
		history, err := p.Repo.History(ctx)
		if err != nil {
			return err
		}
		if len(history) == 0 {
			return nil
		}
		var paths []string
		have := map[string]bool{}
		for _, h := range history {
			for _, pl := range h.Places {
				if !have[pl.Path] {
					have[pl.Path] = true
					paths = append(paths, pl.Path)
				}
			}
		}
		sa, err := p.scanAttrs(ctx, paths, false)
		if err != nil {
			return err
		}
		blobs, err := p.Repo.Blobs(ctx)
		if err != nil {
			return err
		}
		defer blobs.Close()
		for _, h := range history {
			var report *scan.Item
			strict := false
			for i := len(h.Places) - 1; i >= 0; i-- {
				pl := h.Places[i]
				if sa.skip[pl.Path] {
					continue
				}
				strict = strict || sa.filtered[pl.Path]
				if report == nil {
					report = &scan.Item{Path: pl.Path, Commit: pl.Commit, Blob: h.Blob}
				}
			}
			if report == nil {
				continue
			}
			data, err := blobs.Read(h.Blob)
			if err != nil {
				return err
			}
			report.Data, report.Strict = data, strict
			if err := emit(*report); err != nil {
				return err
			}
		}
		return nil
	}
}
