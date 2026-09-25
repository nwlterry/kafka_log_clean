package clean

import "strings"

func (c *Cleaner) redactLDAP(text string) string {
	text = ldapDNRe.ReplaceAllStringFunc(text, func(v string) string {
		return c.Store.consistent("ldapdn", strings.ToLower(v), "ldapdn", "Consistent", "cn=x-redacted-dn-x")
	})
	text = ldapFilterRe.ReplaceAllStringFunc(text, func(v string) string {
		m := ldapFilterRe.FindStringSubmatch(v)
		if len(m) != 4 {
			return v
		}
		tok := c.Store.consistent("ldapsearch", strings.ToLower(m[2]), "ldapsearch", "Consistent", "x-redacted-ldap-x")
		return m[1] + tok + m[3]
	})
	return text
}
