package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/scuba-plaza/redact/internal/store"
)

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestBuiltinRules(t *testing.T) {
	s := New(Options{})
	cases := []struct {
		in   string
		want []string
	}{
		{"-----BEGIN OPENSSH PRIVATE KEY-----", []string{"private-key"}},
		{"-----BEGIN PGP PRIVATE KEY BLOCK-----", []string{"private-key"}},
		{"-----BEGIN PUBLIC KEY-----", nil},
		{"AGE-SECRET-KEY-1QYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQSZQGPQYQS", []string{"age-identity"}},
		{"AGE-SECRET-KEY-PQ-1QYQSZQGPQYQSZQGPQYQSZQGPQYQ", []string{"age-identity"}},
		{`hashedPassword = "$6$rounds=5000$saltsalt$abcdefghijklmnop";`, []string{"crypt-hash"}},
		{`"$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7"`, []string{"crypt-hash"}},
		{`"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"`, []string{"crypt-hash"}},
		{`echo "$1 $2"`, nil},
		{`SCRAM-SHA-256$4096:c2FsdA==$abc:def`, []string{"scram-verifier"}},
		{"token ghp_abcdefghijklmnopqrstuvwxyz0123456789", []string{"github-token"}},
		{"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", []string{"github-token"}},
		{"AKIAIOSFODNN7EXAMPLE", []string{"aws-access-key"}},
		{"xoxb-123456789012-abcdefghij", []string{"slack-token"}},
		{"AIzaSyA-1234567890abcdefghijklmnopqrstu", []string{"google-api-key"}},
		{"sk-ant-api03-abcdefghijklmnopqrstuvwxyz", []string{"anthropic-api-key"}},
		{"12345678+someone@users.noreply.github.com", []string{"github-noreply-id"}},
		{"00000000+someone@users.noreply.github.com", nil},
		{"someone@users.noreply.github.com", []string{"email"}},
		{"cd /home/alice/src", []string{"home-directory"}},
		{"/Users/Alice/Library", []string{"home-directory"}},
		{"/home/user/src /Users/Shared/x /home/runner/work", nil},
		{"/var/lib/home/alice/x", nil},
		{"mail alice@corp.co.uk now", []string{"email"}},
		{"alice@example.com bob@mail.example.org c@x.invalid d@host.test git@github.com", nil},
		{"icon@2x.png pkg@1.2.3 @scope/pkg", nil},
		{"HostName 93.184.216.34", []string{"public-ip"}},
		{"10.0.0.1 192.168.1.1 172.16.0.5 127.0.0.1 100.64.1.1 203.0.113.9 255.255.255.0 8.8.8.8 1.1.1.1", nil},
		{"version 1.2.3.4.5 and v93.184.216.34", nil},
		{"999.184.216.34 01.02.03.04", nil},
		{"uuid 3F2504E0-4F89-11D3-9A0C-0305E82C3301", []string{"uuid"}},
		{"00000000-0000-0000-0000-000000000000", nil},
	}
	for _, c := range cases {
		got := rules(s.Scan("f", []byte(c.in), false))
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValues(t *testing.T) {
	s := New(Options{Secrets: []store.Secret{
		{Name: "USER", Value: "alice"},
		{Name: "OLD", Value: "oldpassword123", Retired: true},
		{Name: "SSH", Value: "Host home\n  HostName homebox.lan\n  User x"},
	}})
	cases := []struct {
		in     string
		strict bool
		want   []string
	}{
		{"user = alice;", false, []string{"value"}},
		{"malice", false, nil},
		{"malice", true, []string{"value"}},
		{"xoldpassword123x", false, []string{"retired-value"}},
		{"  HostName homebox.lan", false, []string{"value"}},
		{"User x", false, nil},
		{"REDACTED[USER] alice", false, []string{"value"}},
	}
	for _, c := range cases {
		got := rules(s.Scan("f", []byte(c.in), c.strict))
		if !slices.Equal(got, c.want) {
			t.Errorf("%q strict=%v: got %v, want %v", c.in, c.strict, got, c.want)
		}
	}
}

func TestValueInsideTokenNameIsIgnored(t *testing.T) {
	s := New(Options{Secrets: []store.Secret{{Name: "X", Value: "USER"}}})
	if fs := s.Scan("f", []byte("REDACTED[GIT_USER_1]"), true); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestOverlappingFindingsKeepTheMostSpecific(t *testing.T) {
	s := New(Options{Secrets: []store.Secret{{Name: "EMAIL", Value: "alice@corp.co.uk"}}})
	fs := s.Scan("f", []byte("to: alice@corp.co.uk"), false)
	if len(fs) != 1 || fs[0].Rule != "value" {
		t.Fatalf("got %+v", fs)
	}
}

func TestPositionsAndMasking(t *testing.T) {
	s := New(Options{})
	fs := s.Scan("f", []byte("first\nünï alice@corp.co.uk"), false)
	if len(fs) != 1 {
		t.Fatalf("got %+v", fs)
	}
	f := fs[0]
	if f.Line != 2 || f.Column != 5 {
		t.Fatalf("position %d:%d", f.Line, f.Column)
	}
	if strings.Contains(f.Match, "alice") || f.Match != "ali… (16 chars)" {
		t.Fatalf("match not masked: %q", f.Match)
	}
	revealed := New(Options{Reveal: true}).Scan("f", []byte("alice@corp.co.uk"), false)
	if revealed[0].Match != "alice@corp.co.uk" {
		t.Fatalf("reveal: %q", revealed[0].Match)
	}
}

func TestAllowList(t *testing.T) {
	allow, err := ParseAllow(strings.NewReader("# corp\n.*@corp\\.co\\.uk\n\n93\\.184\\.216\\.34\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{Allow: allow})
	if fs := s.Scan("f", []byte("alice@corp.co.uk 93.184.216.34 bob@other.co.uk"), false); len(fs) != 1 || fs[0].Rule != "email" {
		t.Fatalf("got %+v", fs)
	}
	if _, err := ParseAllow(strings.NewReader("ok\n(\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("got %v", err)
	}
}

func TestBinaryFilesAreSearchedForValuesOnly(t *testing.T) {
	s := New(Options{Secrets: []store.Secret{{Name: "PW", Value: "hunter2-secret"}}})
	if fs := s.Scan("f", []byte("\x00alice@corp.co.uk"), false); fs != nil {
		t.Fatalf("shape rules ran on binary data: %+v", fs)
	}
	short := New(Options{Secrets: []store.Secret{{Name: "ENV", Value: "dev"}}})
	if fs := short.Scan("image.png", []byte("\x89PNG\x00\x01devx\x02"), false); fs != nil {
		t.Fatalf("a short value matched inside binary data: %+v", fs)
	}
	raw := s.Scan("dump.bin", []byte("abc\x00def xhunter2-secretx"), false)
	if len(raw) != 1 || raw[0].Description != "value of PW" {
		t.Fatalf("raw: %+v", raw)
	}
	var wide []byte
	for _, c := range "pw=hunter2-secret" {
		wide = append(wide, byte(c), 0)
	}
	got := s.Scan("win.reg", append([]byte{0xff, 0xfe}, wide...), false)
	if len(got) != 1 || got[0].Description != "value of PW (UTF-16)" || got[0].Match != Mask("hunter2-secret") {
		t.Fatalf("utf-16: %+v", got)
	}
}

func TestManyFindingsStayLinear(t *testing.T) {
	var b strings.Builder
	for range 50000 {
		b.WriteString("a@corp.co.uk 93.184.216.34\n")
	}
	if fs := New(Options{}).Scan("f", []byte(b.String()), false); len(fs) != 100000 {
		t.Fatalf("got %d findings", len(fs))
	}
}

func TestRun(t *testing.T) {
	s := New(Options{})
	src := func(ctx context.Context, emit func(Item) error) error {
		for _, p := range []string{"b", "a", "c"} {
			if err := emit(Item{Path: p, Blob: "sha-" + p, Data: []byte("x alice@corp.co.uk")}); err != nil {
				return err
			}
		}
		return nil
	}
	fs, err := s.Run(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 || fs[0].Path != "a" || fs[0].Blob != "sha-a" || fs[2].Path != "c" {
		t.Fatalf("got %+v", fs)
	}
	boom := errors.New("boom")
	_, err = s.Run(context.Background(), func(ctx context.Context, emit func(Item) error) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func FuzzScan(f *testing.F) {
	f.Add("alice@corp.co.uk 93.184.216.34 /home/bob/ REDACTED[USER]", "alice")
	f.Add("\n\n$6$x$yy", "Host x\n  HostName longhostname")
	f.Fuzz(func(t *testing.T, text, value string) {
		s := New(Options{Secrets: []store.Secret{{Name: "V", Value: value}}})
		for _, strict := range []bool{false, true} {
			for _, fd := range s.Scan("f", []byte(text), strict) {
				if fd.Line < 1 || fd.Column < 1 || fd.end <= fd.start || fd.end > len(text) {
					t.Fatalf("bad finding %+v", fd)
				}
			}
		}
	})
}
