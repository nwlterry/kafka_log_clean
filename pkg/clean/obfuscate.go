package clean

import (
	"net"
	"regexp"
	"strings"
)

var (
	ipv4Re = regexp.MustCompile(`(?m)(?:^|[^\d.])((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))(?:[^\d.]|$)`)
	// Simpler IPv4 matcher used after isolating candidates.
	ipv4OnlyRe = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`)
	ipv6Re     = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	macRe      = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)
	emailRe    = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	pemRe      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)
	// HH:MM:SS or HH:MM:SS.mmm — Elastic/Kafka timestamps, not IPv6.
	clockRe = regexp.MustCompile(`^(?:[01]?\d|2[0-3]):[0-5]?\d:[0-5]?\d(?:\.\d{1,9})?$`)
	// Maven/JPMS version after @, e.g. 4.1.135.Final
	moduleVerRe = regexp.MustCompile(`(?i)^\d+\.\d+`)
	ldapFilterRe = regexp.MustCompile(`(?i)(\((?:cn|uid|sAMAccountName|userPrincipalName|mail|memberOf|member|distinguishedName)\s*=\s*)([^)\\]+)(\))`)
	// Kafka / MDS principal and username forms:
	//   User:alice  User:first_name.last_name  principal:User:bob
	//   username=alice  username="alice"  "principal":"User:alice"
	userPrincipalRe = regexp.MustCompile(`(?i)\b(user)\s*:\s*([A-Za-z][A-Za-z0-9._\-]{0,200})`)
	userNameAssignRe = regexp.MustCompile(`(?i)\b(user(?:name|PrincipalName)?)\s*=\s*["']?([A-Za-z][A-Za-z0-9._\-]{0,200})["']?`)
	// JSON-ish principal value that is not already covered by User: form.
	jsonPrincipalRe = regexp.MustCompile(`(?i)(["']principal["']\s*:\s*["'])([A-Za-z][A-Za-z0-9._\-]{0,200})(["'])`)
	// Free-form "login ... for user <name>" / "user <name> logged" phrases.
	loginUserRe = regexp.MustCompile(`(?i)\b((?:login\s+(?:successful|failed|failure)?\s*(?:for\s+)?|authenticated\s+|failed\s+for\s+)user)\s+([A-Za-z][A-Za-z0-9._\-]{0,200})`)
	// MDS request / access log: [date] LEVEL host - username [utc] METHOD
	// e.g. [2024-10-16 15:48:01] INFO broker-1 - alice [2024-10-16T07:48:01.123Z] GET
	mdsRequestUserRe = regexp.MustCompile(`(?i)\s-\s([A-Za-z][A-Za-z0-9._\-]{0,200})\s+\[[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+Z?\]\s+(?:GET|PUT|POST|DELETE|PATCH|HEAD|OPTIONS)\b`)
	// Product token before a slash: Chrome, Edg, Version, AppleWebKit, ...
	productTokenRe = regexp.MustCompile(`(?i)[A-Za-z][A-Za-z0-9._\-]*$`)
)

// browserNames are User-Agent product tokens whose following dotted version
// must never be treated as an IPv4 address.
var browserNames = map[string]struct{}{
	"chrome": {}, "chromium": {}, "headlesschrome": {}, "crios": {},
	"firefox": {}, "fxios": {}, "focus": {}, "klar": {}, "waterfox": {},
	"librewolf": {}, "palemoon": {}, "seamonkey": {}, "torbrowser": {},
	"safari": {}, "version": {}, "applewebkit": {}, "webkit": {}, "mobile": {},
	"edge": {}, "edg": {}, "edgios": {}, "edga": {},
	"opr": {}, "opera": {}, "opios": {},
	"vivaldi": {}, "brave": {}, "samsungbrowser": {}, "yabrowser": {},
	"qqbrowser": {}, "ucbrowser": {}, "miuibrowser": {}, "huaweibrowser": {},
	"duckduckgo": {}, "silk": {}, "maxthon": {}, "electron": {},
	"gecko": {}, "trident": {}, "msie": {}, "rv": {},
	"slack": {}, "teams": {}, "outlook": {},
}

// isBrowserOrProductVersion reports whether text[start:end] is a dotted
// product version (Chrome/155.0.0.0, Edg/120.0.0.0, Version/17.6.1.0) rather
// than an IPv4 address. Any Name/x.x.x.x is a product version; known browser
// names also cover space or colon separators.
func isBrowserOrProductVersion(text string, start, end int) bool {
	if start <= 0 {
		return false
	}
	// Name/x.x.x.x — the UA / product-version form.
	if text[start-1] == '/' {
		token := productTokenRe.FindString(text[:start-1])
		if token != "" {
			return true
		}
	}
	// Name<sep>x.x.x.x for known browsers (space, colon, equals, paren).
	sep := text[start-1]
	if sep == ' ' || sep == ':' || sep == '=' || sep == '(' {
		token := productTokenRe.FindString(text[:start-1])
		if _, ok := browserNames[strings.ToLower(token)]; ok {
			return true
		}
	}
	return false
}

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

// looksLikeEmail rejects Java/Maven module@version, version-shaped domains,
// and our own redaction tokens (x-redacted-secret-x@host left by URL userinfo).
func looksLikeEmail(v string) bool {
	at := strings.LastIndex(v, "@")
	if at <= 0 || at == len(v)-1 {
		return false
	}
	local := v[:at]
	lowLocal := strings.ToLower(local)
	// Tokens we already emitted must not be reclassified as email local-parts.
	if strings.HasPrefix(lowLocal, "x-redacted-") || (strings.HasPrefix(lowLocal, "x-") && strings.HasSuffix(lowLocal, "-x")) {
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

// looksLikeIPv6 rejects clock values such as 07:29:19 and short all-decimal groups.
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
	{regexp.MustCompile(`(?i)((?:password|passwd|username)\s*=\s*)(?:"[^"]+"|'[^']+'|[^\s;"']+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)((?:ssl\.(?:keystore|truststore|key)\.password|ssl\.keystore\.key|sasl\.jaas\.config|confluent\.license|basic\.auth\.user\.info|schema\.registry\.basic\.auth\.user\.info|producer\.sasl\.jaas\.config|consumer\.sasl\.jaas\.config|admin\.sasl\.jaas\.config|ldap\.java\.naming\.security\.credentials|confluent\.metadata\.sasl\.jaas\.config)\s*[=:]\s*)([^\s,]+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|sasl\.password)\s*[=:]\s*)([^\s,"'}]+)`), `${1}x-redacted-secret-x`},
	{regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api_key|authorization|jaas)"\s*:\s*")([^"]+)"`), `${1}x-redacted-secret-x"`},
	{regexp.MustCompile(`(?i)(://[^:/@\s]+:)([^@/\s]+)(@)`), `${1}x-redacted-secret-x${3}`},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `x-redacted-awskey-x`},
}
