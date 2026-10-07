package cli

import (
	"fmt"
	"io"
	"strings"
)

type ui struct {
	w     io.Writer
	color bool
	quiet bool
}

func newUI(w io.Writer, color bool) *ui {
	return &ui{w: w, color: color}
}

func (u *ui) paint(code, s string) string {
	if !u.color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func (u *ui) ok(format string, args ...any) {
	if u.quiet {
		return
	}
	fmt.Fprintf(u.w, "%s %s\n", u.paint("32", "✓"), fmt.Sprintf(format, args...))
}

func (u *ui) info(format string, args ...any) {
	if u.quiet {
		return
	}
	fmt.Fprintln(u.w, fmt.Sprintf(format, args...))
}

func (u *ui) warn(format string, args ...any) {
	fmt.Fprintf(u.w, "%s %s\n", u.paint("33", "warning:"), fmt.Sprintf(format, args...))
}

func (u *ui) error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(u.w, "%s %s\n", u.paint("31", "error:"), strings.ReplaceAll(msg, "\n", "\n  "))
}

func (u *ui) dim(s string) string {
	return u.paint("2", s)
}

func (u *ui) bold(s string) string {
	return u.paint("1", s)
}
