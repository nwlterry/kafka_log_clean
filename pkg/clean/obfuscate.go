package clean

import (
	"net"
	"regexp"
	"strings"
)

var (
	ipv4Re = regexp.MustCompile(`(?m)(?:^|[^\d.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?:[^\d.]|$)`)
	ipv4OnlyRe = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`)
	ipv6Re     = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	macRe      = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	pemRe      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
	clockRe = regexp.MustCompile(`^(?:[01]?\d|2[0-3]):[0-5]?\d:[0-5]?\d(?:\.\d{1,9})?$`)
	moduleVerRe = regexp.MustCompile(`(?i)^\d+\.\d+`)
)

var nonMailTLDs = map[string]struct{}{
	"final": {}, "snapshot": {}, "release": {}, "beta": {}, "alpha": {},
	"rc": {}, "build": {}, "ga": {}, "sp": {}, "m1": {}, "m2": {},
}

var localIPv4 = map[string]struct{}{
	"127.0.0.1": {}, "0.0.0.0": {}, "255.255.255.255": {},
}
var localIPv6 = map[string]struct{}{
	"::1": {}, "::": {},
}

func looksLikeEmail(v string) bool {
	at := strings.LastIndex(v, "@")
	if at <= 0 || at == len(v)-1 {
		return false
	}
	domain := v[at+1:]
	dot := strings.LastIndex(domain, ".")
	if dot <= 0 {
		return false
	}
	tld := strings.ToLower(domain[dot+1:])
	if _, skip := nonMailTLDs[tld]; skip {
		return false
	}
	if moduleVerRe.MatchString(domain) {
		return false
	}
	host := domain[:dot]
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

func looksLikeIPv6(v string) bool {
	if clockRe.MatchString(v) {
		return false
	}
	ip := net.ParseIP(v)
	return ip != nil && ip.To4() == nil
}

type secretPat struct {
	re   *regexp.Regexp
	repl string
}

var defaultSecrets = []secretPat{
	{regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(basic|bearer)\s+[A-Za-z0-9+/=._\-]+`), `${1}${2} x-redacted-auth-x`},
	{regexp.MustCompile(`(?i)(api[_-]?key\s*[:=]\s*)([A-Za-z0-9+/=_\-]{8,})`), `${1}x-redacted-apikey-x`},
	{regexp.MustCompile(`(?i)(ApiKey\s+)([A-Za-z0-9+/=_\-]{8,})`), `${1}x-redacted-apikey-x`},
	{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|bind_password|service_token|keystore\.seed|truststore\.password|keystore\.password)\s*[=:]\s*)([^\s,"'}]+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api_key|authorization|bind_password)"\s*:\s*")([^"]+)"`), `${1}x-redacted-secret-x"`},
	{regexp.MustCompile(`(?i)((?:sasl\.jaas\.config|jaas\.config)\s*[:=]\s*)(\S+)`), `${1}x-redacted-jaas-x`},
	{regexp.MustCompile(`(?i)(://[^:/@\s]+:)([^@/\s]+)(@)`), `${1}x-redacted-secret-x${3}`},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `x-redacted-awskey-x`},
}
