package clean

import (
	"strings"
	"testing"
)

func TestCertSubjectSeparateFromLDAPDN(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `subject=CN=es-node-01,O=Elastic,C=US issuer=CN=Corp-CA,O=Elastic,C=US bind_dn: CN=es-bind,OU=Service,DC=corp,DC=example,DC=com openssl /C=US/O=Elastic/CN=es-node-01`
	out := c.ObfuscateText(in)
	for _, leak := range []string{"CN=es-node-01,O=Elastic,C=US", "CN=Corp-CA,O=Elastic,C=US", "CN=es-bind,OU=Service,DC=corp,DC=example,DC=com", "/C=US/O=Elastic/CN=es-node-01"} {
		if strings.Contains(out, leak) {
			t.Fatalf("dn leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "x-certsubj-") {
		t.Fatalf("missing cert token:\n%s", out)
	}
	if !strings.Contains(out, "x-ldapdn-") {
		t.Fatalf("missing ldap token:\n%s", out)
	}
	if strings.Contains(out, "subject=x-ldapdn-") {
		t.Fatalf("cert subject classified as ldap:\n%s", out)
	}
	if strings.Contains(out, "bind_dn: x-certsubj-") {
		t.Fatalf("ldap bind classified as cert:\n%s", out)
	}
}
