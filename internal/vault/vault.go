package vault

import (
	"bufio"
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

var (
	ErrNoIdentity   = errors.New("no identity")
	ErrNotRecipient = errors.New("not a recipient of this store")
)

type Keyring struct {
	Path       string
	Identities []age.Identity
	Recipients []string
}

func LoadKeyring(path string) (*Keyring, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrNoIdentity, path)
	}
	if err != nil {
		return nil, err
	}
	kr, err := ParseKeyring(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	kr.Path = path
	return kr, nil
}

func ParseKeyring(data []byte) (*Keyring, error) {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return parseSSHIdentity(data)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	kr := &Keyring{Identities: ids}
	for _, id := range ids {
		switch v := id.(type) {
		case *age.X25519Identity:
			kr.Recipients = append(kr.Recipients, v.Recipient().String())
		case *age.HybridIdentity:
			kr.Recipients = append(kr.Recipients, v.Recipient().String())
		}
	}
	return kr, nil
}

func parseSSHIdentity(pemBytes []byte) (*Keyring, error) {
	id, err := agessh.ParseIdentity(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, errors.New("passphrase-protected SSH keys are not supported; use an age identity or an unencrypted key")
	}
	if err != nil {
		return nil, err
	}
	kr := &Keyring{Identities: []age.Identity{id}}
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		if signer, ok := raw.(crypto.Signer); ok {
			if pub, err := ssh.NewPublicKey(signer.Public()); err == nil {
				kr.Recipients = append(kr.Recipients, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))))
			}
		}
	}
	return kr, nil
}

func Generate(classic bool, now time.Time) (file []byte, recipient string, err error) {
	var secret string
	if classic {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, "", err
		}
		secret, recipient = id.String(), id.Recipient().String()
	} else {
		id, err := age.GenerateHybridIdentity()
		if err != nil {
			return nil, "", err
		}
		secret, recipient = id.String(), id.Recipient().String()
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# created: %s\n", now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "# public key: %s\n", recipient)
	fmt.Fprintf(&b, "%s\n", secret)
	return b.Bytes(), recipient, nil
}

type Recipient struct {
	Text string
	age.Recipient
}

func ParseRecipients(r io.Reader) ([]Recipient, error) {
	var out []Recipient
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	seen := map[string]bool{}
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		rec, canonical, err := parseRecipient(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, Recipient{Text: canonical, Recipient: rec})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no recipients")
	}
	return out, nil
}

func parseRecipient(text string) (age.Recipient, string, error) {
	if strings.HasPrefix(text, "ssh-") {
		rec, err := agessh.ParseRecipient(text)
		if err != nil {
			return nil, "", err
		}
		fields := strings.Fields(text)
		return rec, fields[0] + " " + fields[1], nil
	}
	recs, err := age.ParseRecipients(strings.NewReader(text))
	if err != nil {
		return nil, "", err
	}
	if len(recs) != 1 {
		return nil, "", fmt.Errorf("expected one recipient, got %d", len(recs))
	}
	return recs[0], text, nil
}

func Encrypt(plaintext []byte, recipients []Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients")
	}
	recs := make([]age.Recipient, len(recipients))
	for i, r := range recipients {
		recs[i] = r.Recipient
	}
	var b bytes.Buffer
	w, err := age.Encrypt(&b, recs...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func Decrypt(ciphertext []byte, kr *Keyring) ([]byte, error) {
	if kr == nil || len(kr.Identities) == 0 {
		return nil, ErrNoIdentity
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), kr.Identities...)
	if err != nil {
		var nomatch *age.NoIdentityMatchError
		if errors.As(err, &nomatch) {
			return nil, fmt.Errorf("%s is %w", describe(kr), ErrNotRecipient)
		}
		return nil, err
	}
	return io.ReadAll(r)
}

func Abbreviate(recipient string) string {
	if len(recipient) <= 48 {
		return recipient
	}
	return recipient[:24] + "…" + recipient[len(recipient)-12:]
}

func describe(kr *Keyring) string {
	if kr.Path != "" {
		return "the identity at " + kr.Path
	}
	return "the identity"
}
