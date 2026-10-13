package clean

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	// RDN attribute names we recognise in RFC 2253 / OpenSSL subjects.
	dnAttrRe = regexp.MustCompile(`(?i)^(cn|ou|dc|uid|o|l|st|c|givenname|sn|mail|samaccountname|userprincipalname|emailaddress|serialnumber)\s*=`)

	// Labels that start a certificate DN (subject/issuer) vs an LDAP DN.
	certLabelRe = regexp.MustCompile(`(?i)(?:subject(?:[_-]?dn)?|issuer(?:[_-]?dn)?|peer[_-]?cert(?:ificate)?(?:\s+subject)?|ssl\.(?:certificate[_-]?)?subject|x509\s+(?:subject|issuer)|certificate\s+subject|cert\s+subject)\s*[=:]\s*$`)
	ldapLabelRe = regexp.MustCompile(`(?i)(?:bind[_-]?dn|user[_-]?dn|base[_-]?dn|search[_-]?base(?:[_-]?dn)?|group_search\.base_dn|user_search\.base_dn|java\.naming\.security\.principal|ldap\.bind_dn|binddn)\s*[=:]\s*$`)

	// OpenSSL one-line subject: /C=US/O=Elastic/CN=node.local
	slashCertRe = regexp.MustCompile(`(?i)(?:/(?:c|st|l|o|ou|cn|dc|emailaddress|serialnumber)=[^/\s,;]+){2,}`)
)

// dnSpan is one distinguished name found in text, with optional trailing braces.
type dnSpan struct {
	start, end int
	text       string // full original including trailing }} if present
	kind       string // "certsubj" or "ldapdn"
}

func looksLikeCertDN(dn string) bool {
	low := strings.ToLower(dn)
	if strings.Contains(low, "emailaddress=") || strings.Contains(low, "serialnumber=") {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(dn), "/") {
		return true
	}
	hasC := regexp.MustCompile(`(?i)(?:^|,)\s*c\s*=`).MatchString(dn)
	hasO := regexp.MustCompile(`(?i)(?:^|,)\s*o\s*=`).MatchString(dn)
	hasDC := strings.Contains(low, "dc=")
	hasDir := strings.Contains(low, "uid=") || strings.Contains(low, "samaccountname=") || strings.Contains(low, "userprincipalname=")
	if hasDir {
		return false
	}
	return hasC && hasO && !hasDC
}

// scanDN tries to parse a full DN starting at text[i]. Returns the end index
// (exclusive) of the DN body (not including trailing braces) and whether it
// consumed at least one RDN. Multi-word values are allowed; the scan stops
// at the next comma+attr, a delimiter, or a label boundary.
func scanDN(text string, i int) (end int, ok bool) {
	n := len(text)
	pos := i
	rdns := 0
	for pos < n {
		// optional whitespace
		for pos < n && (text[pos] == ' ' || text[pos] == '\t') {
			pos++
		}
		if pos >= n {
			break
		}
		m := dnAttrRe.FindStringSubmatch(text[pos:])
		if m == nil {
			break
		}
		// advance past "attr="
		eq := strings.IndexByte(text[pos:], '=')
		if eq < 0 {
			break
		}
		pos += eq + 1
		// value: quoted or unquoted (may contain spaces)
		if pos < n && (text[pos] == '"' || text[pos] == '\'') {
			q := text[pos]
			pos++
			for pos < n && text[pos] != q {
				pos++
			}
			if pos < n && text[pos] == q {
				pos++
			}
		} else {
			// unquoted value: one or more words. A following word is part of
			// the value only when it is eventually followed by ",<attr>="
			// (e.g. "Service Accounts,DC=..."). Otherwise stop, so trailing
			// text like " search (sAMAccountName=...)" is not absorbed.
			valStart := pos
			for pos < n {
				tokStart := pos
				for pos < n {
					c := text[pos]
					if c == ',' || c == ';' || c == ')' || c == '(' || c == ']' || c == '}' || c == '"' || c == '\'' || c == '\n' || c == '\r' || c == ' ' || c == '\t' {
						break
					}
					pos++
				}
				if pos == tokStart {
					break
				}
				if !valueContinues(text, pos) {
					break
				}
				// skip the spaces and continue into the next word
				for pos < n && (text[pos] == ' ' || text[pos] == '\t') {
					pos++
				}
			}
			if pos == valStart {
				return i, false
			}
		}
		rdns++
		// after a value, optional comma/semicolon continues the DN
		j := pos
		for j < n && (text[j] == ' ' || text[j] == '\t') {
			j++
		}
		if j < n && (text[j] == ',' || text[j] == ';') {
			k := j + 1
			for k < n && (text[k] == ' ' || text[k] == '\t') {
				k++
			}
			if dnAttrRe.MatchString(text[k:]) {
				// consume the separator so the next loop starts at the next attr
				pos = k
				continue
			}
		}
		break
	}
	if rdns == 0 {
		return i, false
	}
	return pos, true
}

// valueContinues reports whether the whitespace at pos is inside an RDN value
// (more words, then a comma and the next attribute) rather than the end of the DN.
func valueContinues(text string, pos int) bool {
	n := len(text)
	j := pos
	for j < n && (text[j] == ' ' || text[j] == '\t') {
		j++
	}
	if j >= n {
		return false
	}
	// next token
	k := j
	for k < n {
		c := text[k]
		if c == ' ' || c == '\t' || c == ',' || c == ';' || c == ')' || c == '(' || c == ']' || c == '}' || c == '"' || c == '\'' || c == '\n' || c == '\r' {
			break
		}
		k++
	}
	if k == j {
		return false
	}
	if strings.Contains(text[j:k], "=") {
		return false
	}
	// after this token, if comma + attr, the token belongs to the value
	m := k
	for m < n && (text[m] == ' ' || text[m] == '\t') {
		m++
	}
	if m < n && (text[m] == ',' || text[m] == ';') {
		p := m + 1
		for p < n && (text[p] == ' ' || text[p] == '\t') {
			p++
		}
		return dnAttrRe.MatchString(text[p:])
	}
	// more words — keep going only if they eventually lead to comma+attr
	return valueContinues(text, k)
}

// isLabelBoundary reports whether text[pos:] starts a cert/ldap label that
// should terminate the current DN value.
func isLabelBoundary(text string, pos int) bool {
	// only check at word boundaries
	if pos > 0 && (unicode.IsLetter(rune(text[pos-1])) || unicode.IsDigit(rune(text[pos-1]))) {
		return false
	}
	tail := text[pos:]
	if len(tail) < 6 {
		return false
	}
	low := strings.ToLower(tail)
	labels := []string{"subject=", "subject:", "issuer=", "issuer:", "bind_dn", "base_dn", "user_dn", "openssl"}
	for _, lab := range labels {
		if strings.HasPrefix(low, lab) {
			return true
		}
	}
	return false
}

// findDNSpans locates complete distinguished names in text.
// Each span includes a trailing "}}" or "}" when it is glued to the DN.
func findDNSpans(text string) []dnSpan {
	var out []dnSpan
	n := len(text)
	for i := 0; i < n; {
		// skip until we might start an RDN
		if !isDNStart(text, i) {
			i++
			continue
		}
		end, ok := scanDN(text, i)
		if !ok || end <= i {
			i++
			continue
		}
		body := text[i:end]
		// require at least one RDN; prefer multi-RDN or a labeled single RDN
		rdnCount := countRDNs(body)
		prefix := ""
		if i > 0 {
			from := i - 80
			if from < 0 {
				from = 0
			}
			prefix = text[from:i]
		}
		labeledCert := certLabelRe.MatchString(prefix)
		labeledLDAP := ldapLabelRe.MatchString(prefix)
		if rdnCount < 1 {
			i = end
			continue
		}
		// single RDN is only kept when labeled as LDAP/cert, or when it is clearly directory-like
		if rdnCount == 1 && !labeledCert && !labeledLDAP {
			i = end
			continue
		}
		// include trailing braces that were part of the original token
		fullEnd := end
		if fullEnd+1 < n && text[fullEnd] == '}' && text[fullEnd+1] == '}' {
			fullEnd += 2
		} else if fullEnd < n && text[fullEnd] == '}' {
			fullEnd++
		}
		kind := "ldapdn"
		if labeledCert || looksLikeCertDN(body) {
			kind = "certsubj"
		}
		out = append(out, dnSpan{start: i, end: fullEnd, text: text[i:fullEnd], kind: kind})
		i = fullEnd
	}
	return out
}

func isDNStart(text string, i int) bool {
	if i > 0 {
		prev := text[i-1]
		// don't start mid-token, and don't start inside an LDAP filter (...)
		if unicode.IsLetter(rune(prev)) || unicode.IsDigit(rune(prev)) || prev == '_' || prev == '.' || prev == '-' || prev == '(' {
			return false
		}
	}
	return dnAttrRe.MatchString(text[i:])
}

func countRDNs(dn string) int {
	n := 0
	i := 0
	for i < len(dn) {
		for i < len(dn) && (dn[i] == ' ' || dn[i] == '\t' || dn[i] == ',') {
			i++
		}
		if i >= len(dn) {
			break
		}
		if dnAttrRe.MatchString(dn[i:]) {
			n++
			// skip to next comma
			eq := strings.IndexByte(dn[i:], '=')
			if eq < 0 {
				break
			}
			i += eq + 1
			if i < len(dn) && (dn[i] == '"' || dn[i] == '\'') {
				q := dn[i]
				i++
				for i < len(dn) && dn[i] != q {
					i++
				}
				if i < len(dn) {
					i++
				}
			}
			continue
		}
		i++
	}
	return n
}

func (c *Cleaner) redactDNs(text string) string {
	mode := "Consistent"

	// OpenSSL slash subjects first — always certificates.
	text = slashCertRe.ReplaceAllStringFunc(text, func(v string) string {
		return c.Store.consistent("certsubj", strings.ToLower(v), "certsubj", mode, "CN=x-redacted-cert-x")
	})

	// LDAP search filters.
	text = ldapFilterRe.ReplaceAllStringFunc(text, func(v string) string {
		m := ldapFilterRe.FindStringSubmatch(v)
		if len(m) != 4 {
			return v
		}
		tok := c.Store.consistent("ldapsearch", strings.ToLower(m[2]), "ldapsearch", mode, "x-redacted-ldap-x")
		return m[1] + tok + m[3]
	})

	// Full DN scan (handles multi-word values and trailing }}).
	spans := findDNSpans(text)
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		if sp.start < last {
			continue
		}
		b.WriteString(text[last:sp.start])
		// Store the full original (including trailing }} when present) so the
		// report shows exactly what was in the log, and the same full string
		// always maps to the same token.
		orig := sp.text
		tok := c.Store.consistent(sp.kind, strings.ToLower(orig), sp.kind, mode, fallbackFor(sp.kind))
		b.WriteString(tok)
		last = sp.end
	}
	b.WriteString(text[last:])
	return b.String()
}

func fallbackFor(kind string) string {
	if kind == "certsubj" {
		return "CN=x-redacted-cert-x"
	}
	return "cn=x-redacted-dn-x"
}

// redactLDAP is kept as an alias so older ObfuscateText hooks keep compiling.
func (c *Cleaner) redactLDAP(text string) string {
	return c.redactDNs(text)
}
