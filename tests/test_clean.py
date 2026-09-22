#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kafka_log_clean import Cleaner, default_config, main  # noqa: E402


class CleanerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cleaner = Cleaner(default_config())

    def test_consistent_ip(self) -> None:
        text = "listener 10.40.50.11:9093 and 10.40.50.11 again plus 127.0.0.1"
        out = self.cleaner.obfuscate_text(text)
        self.assertIn("127.0.0.1", out)
        self.assertNotIn("10.40.50.11", out)
        self.assertEqual(out.count("x-ipv4-0000000001-x"), 2)

    def test_jaas_and_ssl_secrets(self) -> None:
        sample = (ROOT / "examples" / "sample-server.log").read_text(encoding="utf-8")
        out = self.cleaner.obfuscate_text(sample)
        self.assertNotIn("P@ssw0rd!", out)
        self.assertNotIn("changeit", out)
        self.assertNotIn("sr-secret", out)
        self.assertNotIn("C0nn3ct!", out)
        self.assertNotIn("LdapBind#99", out)
        self.assertNotIn("BEGIN PRIVATE KEY", out)
        self.assertIn("x-redacted-secret-x", out)
        self.assertNotIn("ops@kafka.example.com", out)

    def test_omit_jaas_and_jks(self) -> None:
        self.assertTrue(self.cleaner.should_omit("etc/kafka/kafka_server_jaas.conf"))
        self.assertTrue(self.cleaner.should_omit("ssl/kafka.server.keystore.jks"))
        self.assertFalse(self.cleaner.should_omit("logs/server.log"))

    def test_file_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src = tmp_path / "server.log"
            src.write_text("broker 192.168.9.9 password=hidden\n", encoding="utf-8")
            out = tmp_path / "server.cleaned.log"
            report = tmp_path / "report.yaml"
            rc = main(["-i", str(src), "-o", str(out), "-r", str(report), "-w", "1"])
            self.assertEqual(rc, 0)
            body = out.read_text(encoding="utf-8")
            self.assertNotIn("192.168.9.9", body)
            self.assertNotIn("hidden", body)


if __name__ == "__main__":
    unittest.main()
