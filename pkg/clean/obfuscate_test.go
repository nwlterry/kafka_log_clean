package clean

import (
	"strings"
	"testing"
)

func TestConsistentIPAndLoopback(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	out := c.ObfuscateText("listener 10.40.50.11 and 10.40.50.11 plus 127.0.0.1")
	if !strings.Contains(out, "127.0.0.1") || strings.Contains(out, "10.40.50.11") {
		t.Fatalf("bad ip rewrite: %s", out)
	}
	if strings.Count(out, "x-ipv4-0000000001-x") != 2 {
		t.Fatalf("inconsistent: %s", out)
	}
}

func TestSecrets(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	out := c.ObfuscateText(`sasl.jaas.config=x password="P@ssw0rd!"; ssl.keystore.password=changeit`)
	if strings.Contains(out, "P@ssw0rd!") || strings.Contains(out, "changeit") {
		t.Fatalf("leaked: %s", out)
	}
}

func TestOmit(t *testing.T) {
	c := NewCleaner(DefaultConfig(), nil)
	if !c.ShouldOmit("etc/kafka/kafka_server_jaas.conf") || !c.ShouldOmit("ssl/kafka.server.keystore.jks") || c.ShouldOmit("logs/server.log") {
		t.Fatal("omit rules")
	}
}
