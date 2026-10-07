package scan

import (
	"net/netip"
	"regexp"
	"strings"
)

type rule struct {
	id       string
	desc     string
	re       *regexp.Regexp
	accept   func(text []byte, start, end int) bool
	allowed  func(match string) bool
	priority int
}

func ascii(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func before(text []byte, i int) byte {
	if i <= 0 {
		return 0
	}
	return text[i-1]
}

func after(text []byte, i int) byte {
	if i >= len(text) {
		return 0
	}
	return text[i]
}

var builtinRules = []rule{
	{
		id:       "private-key",
		desc:     "private key",
		re:       regexp.MustCompile(`-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----`),
		priority: 1,
	},
	{
		id:       "age-identity",
		desc:     "age identity",
		re:       regexp.MustCompile(`AGE-SECRET-KEY-(?:PQ-)?1[02-9AC-HJ-NP-Z]{20,}`),
		priority: 1,
	},
	{
		id:       "crypt-hash",
		desc:     "password hash",
		re:       regexp.MustCompile(`\$(?:1|2[abxy]|5|6|7|y|gy)\$[./A-Za-z0-9=,]+\$[./A-Za-z0-9]{2,}`),
		priority: 1,
	},
	{
		id:       "scram-verifier",
		desc:     "SCRAM verifier",
		re:       regexp.MustCompile(`SCRAM-SHA-(?:1|256)\$[0-9]+:[A-Za-z0-9+/=]+`),
		priority: 1,
	},
	{
		id:       "github-token",
		desc:     "GitHub token",
		re:       regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})`),
		priority: 1,
	},
	{
		id:       "aws-access-key",
		desc:     "AWS access key",
		re:       regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		priority: 1,
	},
	{
		id:       "slack-token",
		desc:     "Slack token",
		re:       regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z-]{10,}`),
		priority: 1,
	},
	{
		id:       "google-api-key",
		desc:     "Google API key",
		re:       regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		priority: 1,
	},
	{
		id:       "anthropic-api-key",
		desc:     "Anthropic API key",
		re:       regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`),
		priority: 1,
	},
	{
		id:       "github-noreply-id",
		desc:     "GitHub account id",
		re:       regexp.MustCompile(`\b[1-9][0-9]{5,}\+[A-Za-z0-9-]+@users\.noreply\.github\.com\b`),
		priority: 2,
	},
	{
		id:       "home-directory",
		desc:     "home directory",
		re:       regexp.MustCompile(`/home/([a-z_][a-z0-9_.-]*)/|/Users/([A-Za-z][A-Za-z0-9_.-]*)/`),
		accept:   acceptHome,
		priority: 3,
	},
	{
		id:       "email",
		desc:     "email address",
		re:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b`),
		allowed:  allowedEmail,
		priority: 3,
	},
	{
		id:       "public-ip",
		desc:     "public IP address",
		re:       regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		accept:   acceptIP,
		allowed:  allowedIP,
		priority: 3,
	},
	{
		id:       "uuid",
		desc:     "UUID",
		re:       regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		allowed:  allowedUUID,
		priority: 3,
	},
}

var homeNamesAllowed = map[string]bool{"user": true, "Shared": true, "runner": true}

func acceptHome(text []byte, start, end int) bool {
	b := before(text, start)
	if ascii(b) || b == '_' || b == '.' || b == '-' {
		return false
	}
	seg := string(text[start:end])
	seg = strings.TrimPrefix(seg, "/home/")
	seg = strings.TrimPrefix(seg, "/Users/")
	return !homeNamesAllowed[strings.TrimSuffix(seg, "/")]
}

func acceptIP(text []byte, start, end int) bool {
	if b := before(text, start); b == '.' || b == '-' || b == '_' {
		return false
	}
	if after(text, end) == '.' && end+1 < len(text) && text[end+1] >= '0' && text[end+1] <= '9' {
		return false
	}
	_, err := netip.ParseAddr(string(text[start:end]))
	return err == nil
}

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var publicResolvers = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true, "208.67.222.222": true, "208.67.220.220": true,
}

func allowedIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return true
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || publicResolvers[s] {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var (
	allowedAddresses = map[string]bool{
		"git@github.com": true, "git@gitlab.com": true, "git@bitbucket.org": true,
		"git@codeberg.org": true, "noreply@github.com": true,
	}
	placeholderNoreply = regexp.MustCompile(`^0+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$`)
	fileExtensions     = map[string]bool{
		"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true, "webp": true, "avif": true,
		"ico": true, "css": true, "js": true, "mjs": true, "cjs": true, "ts": true, "tsx": true,
		"jsx": true, "json": true, "nix": true, "lock": true, "toml": true, "yaml": true, "yml": true,
		"lua": true, "txt": true, "html": true,
	}
)

func allowedEmail(s string) bool {
	lower := strings.ToLower(s)
	if allowedAddresses[lower] || placeholderNoreply.MatchString(s) {
		return true
	}
	_, domain, _ := strings.Cut(lower, "@")
	switch domain {
	case "example.com", "example.net", "example.org", "localhost":
		return true
	}
	for _, suffix := range []string{".example", ".invalid", ".test", ".localhost", ".local", ".example.com", ".example.net", ".example.org"} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	return fileExtensions[tld]
}

func allowedUUID(s string) bool {
	l := strings.ToLower(s)
	return l == "00000000-0000-0000-0000-000000000000" || l == "ffffffff-ffff-ffff-ffff-ffffffffffff"
}
