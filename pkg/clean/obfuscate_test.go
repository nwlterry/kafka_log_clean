package clean

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsistentIPAndLoopback(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	out := c.ObfuscateText("a 10.20.30.41 b 10.20.30.41 c 127.0.0.1 d 10.20.30.99 version 8.18.4")
	if !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("loopback rewritten: %s", out)
	}
	if !strings.Contains(out, "8.18.4") {
		t.Fatalf("version rewritten: %s", out)
	}
	if strings.Contains(out, "10.20.30.41") || strings.Contains(out, "10.20.30.99") {
		t.Fatalf("ip left in place: %s", out)
	}
	parts := strings.Fields(out)
	if !strings.HasPrefix(parts[1], "x-ipv4-") {
		t.Fatalf("token: %s", parts[1])
	}
	if parts[1] != parts[3] {
		t.Fatalf("inconsistent tokens %s vs %s", parts[1], parts[3])
	}
}

func TestSecretsAndPEM(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	samplePath := filepath.Join("..", "..", "examples", "sample-server.log")
	b, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	out := c.ObfuscateText(string(b))
	for _, bad := range []string{"changeit", "P@ssw0rd!", "LdapBind#99", "C0nn3ct!", "sr-secret", "BEGIN PRIVATE KEY", "ops@kafka.example.com"} {
		if strings.Contains(out, bad) {
			t.Fatalf("leaked %q in:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "x-redacted-secret-x") {
		t.Fatalf("missing secret token:\n%s", out)
	}
	if !strings.Contains(out, "x-redacted-pem-x") {
		t.Fatalf("missing pem token")
	}
}

func TestOmitKeystore(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	if !c.ShouldOmit("etc/kafka/kafka_server_jaas.conf") {
		t.Fatal("keystore not omitted")
	}
	if !c.ShouldOmit("ssl/kafka.server.keystore.jks") {
		t.Fatal("jks not omitted")
	}
	if c.ShouldOmit("logs/server.log") {
		t.Fatal("log omitted")
	}
}

func TestZipRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "diag.zip")
	zf, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(zf)
	f, _ := w.Create("logs/server.log")
	_, _ = f.Write([]byte("node 10.1.2.3 password=abc123\n"))
	f2, _ := w.Create("ssl/kafka.server.keystore.jks")
	_, _ = f2.Write([]byte{0, 1, 2})
	_ = w.Close()
	_ = zf.Close()

	c := NewCleaner(DefaultConfig(), nil)
	srcRoot := filepath.Join(dir, "src")
	dstRoot := filepath.Join(dir, "dst")
	if _, err := ExtractZip(src, srcRoot); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTree(c, srcRoot, dstRoot, 1); err != nil {
		t.Fatal(err)
	}
	outZip := filepath.Join(dir, "out.zip")
	if err := WriteZip(dstRoot, outZip); err != nil {
		t.Fatal(err)
	}
	r, err := zip.OpenReader(outZip)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var sawLog, sawJKS bool
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".jks") {
			sawJKS = true
		}
		if strings.HasSuffix(f.Name, "server.log") {
			sawLog = true
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			body := string(b)
			if strings.Contains(body, "10.1.2.3") || strings.Contains(body, "abc123") {
				t.Fatalf("leaked in zip: %s", body)
			}
		}
	}
	if !sawLog {
		t.Fatal("log missing from zip")
	}
	if sawJKS {
		t.Fatal("jks should be omitted")
	}
}

func TestLDAPFullDNWithSpacesAndTrailingBraces(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `bind_dn: CN=es-bind,OU=Service Accounts,DC=corp,DC=example,DC=com}} user_search.base_dn=OU=Users,DC=corp,DC=example,DC=com search (sAMAccountName=terryng)`
	out := c.ObfuscateText(in)
	for _, leak := range []string{
		"CN=es-bind,OU=Service Accounts,DC=corp,DC=example,DC=com",
		"OU=Service Accounts",
		"DC=corp,DC=example,DC=com",
		"OU=Users,DC=corp,DC=example,DC=com",
		"terryng",
		"}}",
	} {
		if strings.Contains(out, leak) {
			t.Fatalf("ldap leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "x-ldapdn-") {
		t.Fatalf("missing ldap dn token:\n%s", out)
	}
	// report must store the full original including trailing }}
	reps := c.Store.Report()
	var sawFull bool
	for _, r := range reps {
		if r.Canonical == "" {
			continue
		}
		for _, oc := range r.Occurrences {
			if strings.Contains(oc.Original, "ou=service accounts") && strings.Contains(oc.Original, "dc=com}}") {
				sawFull = true
			}
			// must not be a truncated OU-only or CN-only original for this DN
			if oc.Original == "ou=service" || oc.Original == "cn=es-bind" {
				t.Fatalf("truncated original stored: %q", oc.Original)
			}
		}
	}
	if !sawFull {
		t.Fatalf("report missing full DN with trailing }}:\n%#v", reps)
	}
}

func TestUserPrincipalFirstLast(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `Principal = User:first_name.last_name is Allowed Operation = Read from host = 10.1.2.3 User:alice super.users=User:bob.smith`
	out := c.ObfuscateText(in)
	for _, leak := range []string{"first_name.last_name", "alice", "bob.smith"} {
		if strings.Contains(out, leak) {
			t.Fatalf("user leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "x-user-") {
		t.Fatalf("missing user token:\n%s", out)
	}
	if !strings.Contains(out, "User:") && !strings.Contains(out, "user:") {
		t.Fatalf("User: prefix dropped:\n%s", out)
	}
}

func TestMDSMetadataServerUsernames(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `Principal = User:first_name.last_name is Allowed
principal:User:alice
username=bob.smith username="carol.jones" username='dave.admin'
userPrincipalName=eve.smith
"principal":"frank.user" "principal":"User:grace.admin"
{"authenticationInfo":{"principal":"User:heidi.ops"}}
login successful for user first_name.last_name
MdsBasicLoginService login - Login failed for kafka
principal = User:kafka_cluster is a super user
username=x-redacted-user-x should stay
`
	out := c.ObfuscateText(in)
	leaks := []string{
		"first_name.last_name", "alice", "bob.smith", "carol.jones",
		"dave.admin", "eve.smith", "frank.user", "grace.admin", "heidi.ops",
		"kafka_cluster",
	}
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Fatalf("user leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "x-user-") {
		t.Fatalf("missing user token:\n%s", out)
	}
	for _, keep := range []string{"User:", "principal:", "username=", "userPrincipalName=", `"principal":`} {
		if !strings.Contains(out, keep) && !strings.Contains(strings.ToLower(out), strings.ToLower(keep)) {
			t.Fatalf("key/prefix %q dropped:\n%s", keep, out)
		}
	}
}

func TestArchiveRoundTripTarGz(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "Principal = User:first_name.last_name host 10.9.8.7\n"
	if err := os.WriteFile(filepath.Join(src, "logs", "authorizer.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "support.tar.gz")
	if err := WriteArchive(src, archive); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	n, err := ExtractArchive(archive, dst)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("extract count %d", n)
	}
	got, err := os.ReadFile(filepath.Join(dst, "logs", "authorizer.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestCertSubjectSeparateFromLDAPDN(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `subject=CN=es-node-01,O=Elastic,C=US issuer=CN=Corp-CA,O=Elastic,C=US bind_dn: CN=es-bind,OU=Service Accounts,DC=corp,DC=example,DC=com openssl /C=US/O=Elastic/CN=es-node-01`
	out := c.ObfuscateText(in)
	for _, leak := range []string{"CN=es-node-01,O=Elastic,C=US", "CN=Corp-CA,O=Elastic,C=US", "CN=es-bind,OU=Service Accounts,DC=corp,DC=example,DC=com", "/C=US/O=Elastic/CN=es-node-01"} {
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

func TestBrowserVersionNotIPv4(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0 OPR/108.0.0.0 Firefox/131.0.0.0 Version/17.6.1.0 CriOS/120.0.6099.119 host 10.20.30.41`
	out := c.ObfuscateText(in)
	for _, keep := range []string{
		"Chrome/155.0.0.0",
		"Edg/155.0.0.0",
		"OPR/108.0.0.0",
		"Firefox/131.0.0.0",
		"Version/17.6.1.0",
		"CriOS/120.0.6099.119",
		"AppleWebKit/537.36",
	} {
		if !strings.Contains(out, keep) {
			t.Fatalf("browser version rewritten %q in:\n%s", keep, out)
		}
	}
	if strings.Contains(out, "10.20.30.41") {
		t.Fatalf("real ipv4 not redacted:\n%s", out)
	}
	if !strings.Contains(out, "x-ipv4-") {
		t.Fatalf("missing ipv4 token:\n%s", out)
	}
}

func TestModuleCoordNotEmailAndClockNotIPv6(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `[2026-09-24T07:29:19,123][INFO] loaded io.netty.transport@4.1.135.Final org.apache.kafka.clients@3.8.0 "07:29:19" user sre@corp.example.com ipv6 2001:db8::1`
	out := c.ObfuscateText(in)
	for _, keep := range []string{
		"io.netty.transport@4.1.135.Final",
		"org.apache.kafka.clients@3.8.0",
		"07:29:19",
		"2026-09-24T07:29:19,123",
	} {
		if !strings.Contains(out, keep) {
			t.Fatalf("false positive, lost %q in:\n%s", keep, out)
		}
	}
	if strings.Contains(out, "sre@corp.example.com") {
		t.Fatalf("real email not redacted:\n%s", out)
	}
	if strings.Contains(out, "2001:db8::1") {
		t.Fatalf("real ipv6 not redacted:\n%s", out)
	}
	if !strings.Contains(out, "x-email-") {
		t.Fatalf("missing email token:\n%s", out)
	}
	if !strings.Contains(out, "x-ipv6-") && !strings.Contains(out, "x:x:x") {
		t.Fatalf("missing ipv6 token:\n%s", out)
	}
}

func TestLDAPDNAndSearchFilter(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `bind_dn: CN=kafka-bind,OU=Service Accounts,DC=corp,DC=example,DC=com search (uid=connect) base=OU=Kafka,DC=corp,DC=example,DC=com`
	out := c.ObfuscateText(in)
	for _, leak := range []string{"CN=kafka-bind,OU=Service Accounts,DC=corp,DC=example,DC=com", "uid=connect", "OU=Kafka,DC=corp,DC=example,DC=com"} {
		if strings.Contains(out, leak) {
			t.Fatalf("ldap leaked %q in:\n%s", leak, out)
		}
	}
}

func TestMDSRequestLogUsername(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	in := `[2024-10-16 15:48:01] INFO broker-1.example.com - first_name.last_name [2024-10-16T07:48:01.123Z] GET /security/1.0/authenticate
[2024-10-16 15:48:02,456] DEBUG 10.1.2.3 - alice [2024-10-16T07:48:02.456Z] POST /security/1.0/authorize
[2024-10-16 15:48:03] WARN kafka-prod-01 - bob.smith [2024-10-16 07:48:03.000Z] PUT /security/1.0/roles
[2024-10-16 15:48:04] ERROR 192.168.1.10 - carol [2024-10-16T07:48:04Z] DELETE /v1/metadata`
	out := c.ObfuscateText(in)
	for _, leak := range []string{"first_name.last_name", "alice", "bob.smith", "carol"} {
		if strings.Contains(out, leak) {
			t.Fatalf("username leaked %q in:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "x-user-") {
		t.Fatalf("missing user token:\n%s", out)
	}
	// Structure should still be readable: host - token [timestamp] METHOD
	if !strings.Contains(out, " - x-user-") || !strings.Contains(out, " GET ") || !strings.Contains(out, " POST ") {
		t.Fatalf("request structure broken:\n%s", out)
	}
	// Already-redacted should stay
	in2 := `[2024-10-16 15:48:01] INFO broker-1 - x-redacted-user-x [2024-10-16T07:48:01Z] GET`
	out2 := c.ObfuscateText(in2)
	if !strings.Contains(out2, "x-redacted-user-x") {
		t.Fatalf("already-redacted token was altered:\n%s", out2)
	}
}
