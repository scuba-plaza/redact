package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func keyring(t *testing.T, classic bool) (*Keyring, string) {
	t.Helper()
	file, rec, err := Generate(classic, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := ParseKeyring(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.Recipients) != 1 || kr.Recipients[0] != rec {
		t.Fatalf("recipients %v, want %s", kr.Recipients, rec)
	}
	return kr, rec
}

func recipients(t *testing.T, lines ...string) []Recipient {
	t.Helper()
	recs, err := ParseRecipients(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestRoundTrip(t *testing.T) {
	for _, classic := range []bool{true, false} {
		kr, rec := keyring(t, classic)
		ct, err := Encrypt([]byte("hello"), recipients(t, rec))
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt(ct, kr)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != "hello" {
			t.Fatalf("got %q", pt)
		}
	}
}

func TestGeneratedFileFormat(t *testing.T) {
	file, rec, err := Generate(false, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(file)), "\n")
	if len(lines) != 3 || lines[0] != "# created: 2026-01-02T03:04:05Z" || lines[1] != "# public key: "+rec {
		t.Fatalf("unexpected file:\n%s", file)
	}
	if !strings.HasPrefix(lines[2], "AGE-SECRET-KEY-PQ-1") {
		t.Fatalf("expected a post-quantum identity, got %s", lines[2][:20])
	}
}

func TestWrongIdentity(t *testing.T) {
	_, rec := keyring(t, true)
	other, _ := keyring(t, true)
	other.Path = "/tmp/other"
	ct, err := Encrypt([]byte("x"), recipients(t, rec))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(ct, other)
	if err == nil || !strings.Contains(err.Error(), "/tmp/other is not a recipient") {
		t.Fatalf("got %v", err)
	}
}

func TestMultipleRecipients(t *testing.T) {
	a, ra := keyring(t, true)
	b, rb := keyring(t, true)
	ct, err := Encrypt([]byte("shared"), recipients(t, "# team", ra, "", rb, ra))
	if err != nil {
		t.Fatal(err)
	}
	for _, kr := range []*Keyring{a, b} {
		if pt, err := Decrypt(ct, kr); err != nil || string(pt) != "shared" {
			t.Fatalf("decrypt: %q %v", pt, err)
		}
	}
}

func TestParseRecipientsDedupesAndRejectsGarbage(t *testing.T) {
	_, ra := keyring(t, true)
	if got := recipients(t, ra, ra); len(got) != 1 {
		t.Fatalf("expected a deduplicated list, got %d", len(got))
	}
	if _, err := ParseRecipients(strings.NewReader("# only comments\n")); err == nil {
		t.Fatal("expected an error for an empty file")
	}
	_, err := ParseRecipients(strings.NewReader(ra + "\nnot-a-key\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("got %v", err)
	}
}

func TestSSHIdentity(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	kr, err := ParseKeyring(pem.EncodeToMemory(block))
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.Recipients) != 1 || !strings.HasPrefix(kr.Recipients[0], "ssh-ed25519 ") {
		t.Fatalf("recipients %v", kr.Recipients)
	}
	recs := recipients(t, kr.Recipients[0]+" alice@laptop")
	if recs[0].Text != kr.Recipients[0] {
		t.Fatalf("comment was not stripped: %q", recs[0].Text)
	}
	ct, err := Encrypt([]byte("via ssh"), recs)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Decrypt(ct, kr); err != nil || string(pt) != "via ssh" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
}

func TestEncryptedSSHIdentityRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseKeyring(pem.EncodeToMemory(block))
	if err == nil || !strings.Contains(err.Error(), "passphrase-protected") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadKeyringMissing(t *testing.T) {
	_, err := LoadKeyring(filepath.Join(t.TempDir(), "nope"))
	if err == nil || !strings.Contains(err.Error(), "no identity at") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadKeyringFile(t *testing.T) {
	file, _, _ := Generate(true, time.Now())
	p := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(p, file, 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := LoadKeyring(p)
	if err != nil || kr.Path != p {
		t.Fatalf("%v %v", kr, err)
	}
}

func TestEncryptIsNondeterministicButDecryptsSame(t *testing.T) {
	kr, rec := keyring(t, true)
	recs := recipients(t, rec)
	a, _ := Encrypt([]byte("v"), recs)
	b, _ := Encrypt([]byte("v"), recs)
	if bytes.Equal(a, b) {
		t.Fatal("expected fresh file keys")
	}
	pa, _ := Decrypt(a, kr)
	pb, _ := Decrypt(b, kr)
	if !bytes.Equal(pa, pb) {
		t.Fatal("plaintexts differ")
	}
}
