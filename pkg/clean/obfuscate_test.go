package clean

import (
	"strings"
	"testing"
)

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
}
