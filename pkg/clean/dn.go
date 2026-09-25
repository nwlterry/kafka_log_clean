package clean

import (
	"regexp"
	"strings"
)

var (
	dnVal  = `(?:"[^"]+"|'[^']+'|[^,=;()\s]+)`
	dnAttr = `(?:cn|ou|dc|uid|o|l|st|c|givenname|sn|mail|samaccountname|userprincipalname|emailaddress|serialnumber)`
	dnBody = dnAttr + `\s*=\s*` + dnVal + `(?:\s*,\s*` + dnAttr + `\s*=\s*` + dnVal + `){1,}`

	rfc2253DNRe = regexp.MustCompile(`(?i)` + dnBody)
	slashCertRe = regexp.MustCompile(`(?i)(?:/(?:c|st|l|o|ou|cn|dc|emailaddress|serialnumber)=[^/\s,;]+){2,}`)
	certCtxDNRe = regexp.MustCompile(`(?i)((?:subject(?:[_-]?dn)?|issuer(?:[_-]?dn)?|peer[_-]?cert(?:ificate)?(?:\s+subject)?|ssl\.(?:certificate[_-]?)?subject|x509\s+(?:subject|issuer)|certificate\s+subject|cert\s+subject)\s*[=:]\s*)(` + dnBody + `)`)
	ldapCtxDNRe = regexp.MustCompile(`(?i)((?:bind[_-]?dn|user[_-]?dn|base[_-]?dn|search[_-]?base(?:[_-]?dn)?|group_search\.base_dn|user_search\.base_dn|java\.naming\.security\.principal|ldap\.bind_dn|binddn)\s*[=:]\s*)(` + dnBody + `)`)
)

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

func (c *Cleaner) redactDNs(text string) string {
	mode := "Consistent"
	text = certCtxDNRe.ReplaceAllStringFunc(text, func(v string) string {
		m := certCtxDNRe.FindStringSubmatch(v)
		if len(m) != 3 {
			return v
		}
		return m[1] + c.Store.consistent("certsubj", strings.ToLower(m[2]), "certsubj", mode, "CN=x-redacted-cert-x")
	})
	text = ldapCtxDNRe.ReplaceAllStringFunc(text, func(v string) string {
		m := ldapCtxDNRe.FindStringSubmatch(v)
		if len(m) != 3 {
			return v
		}
		return m[1] + c.Store.consistent("ldapdn", strings.ToLower(m[2]), "ldapdn", mode, "cn=x-redacted-dn-x")
	})
	text = slashCertRe.ReplaceAllStringFunc(text, func(v string) string {
		return c.Store.consistent("certsubj", strings.ToLower(v), "certsubj", mode, "CN=x-redacted-cert-x")
	})
	text = ldapFilterRe.ReplaceAllStringFunc(text, func(v string) string {
		m := ldapFilterRe.FindStringSubmatch(v)
		if len(m) != 4 {
			return v
		}
		return m[1] + c.Store.consistent("ldapsearch", strings.ToLower(m[2]), "ldapsearch", mode, "x-redacted-ldap-x") + m[3]
	})
	locs := rfc2253DNRe.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		b.WriteString(text[last:loc[0]])
		dn := text[loc[0]:loc[1]]
		if looksLikeCertDN(dn) {
			b.WriteString(c.Store.consistent("certsubj", strings.ToLower(dn), "certsubj", mode, "CN=x-redacted-cert-x"))
		} else {
			b.WriteString(c.Store.consistent("ldapdn", strings.ToLower(dn), "ldapdn", mode, "cn=x-redacted-dn-x"))
		}
		last = loc[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

func (c *Cleaner) redactLDAP(text string) string {
	return c.redactDNs(text)
}
