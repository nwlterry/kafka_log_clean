# kafka_log_clean

Obfuscate sensitive data in **Confluent Kafka** broker, controller, Connect, Schema Registry, and ksqlDB logs (and support zips).

Same omit / obfuscate / `report.yaml` model as [openshift/must-gather-clean](https://github.com/openshift/must-gather-clean) and [elastic_log_clean](https://github.com/nwlterry/elastic_log_clean).

Typical inputs: `server.log`, rotated `server.log.yyyy-MM-dd-HH`, `controller.log`, `state-change.log`, `kafka-authorizer.log`, Connect `connect.log`, Schema Registry logs, zipped support bundles.

## Default redactions

- IPv4/IPv6 (not loopback) → `x-ipv4-0000000001-x`
- MAC / email
- `sasl.jaas.config` LoginModule username/password
- `ssl.keystore.password`, `ssl.truststore.password`, `ssl.key.password`
- `basic.auth.user.info`, Schema Registry basic auth
- `confluent.license`, LDAP bind credentials, MDS JAAS
- `Authorization: Basic ...`
- `user:pass@broker` URL passwords
- PEM key blocks
- Omit `*.jks`, `*.p12`, `*.key`, `kafka_server_jaas.conf`

Broker IDs, topic names, and partition numbers are kept. Add `Keywords` rules if those are also sensitive. Never share `report.yaml`.

Live broker redaction is a different problem — use the [Confluent Log Redactor](https://docs.confluent.io/platform/current/security/protect-data/log-redaction.html) plugin for that.

## Requirements

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 kafka_log_clean.py -i /var/log/kafka -o /tmp/kafka-logs-cleaned
python3 kafka_log_clean.py -i server.log -o server.cleaned.log
python3 kafka_log_clean.py -i kafka-support-bundle.zip -o scrubbed-kafka-support-bundle.zip
echo 'sasl.jaas.config=... password="secret"; listener 10.40.50.11:9093' | python3 kafka_log_clean.py --stdin
python3 kafka_log_clean.py -c config/kafka_default.yaml -i /var/log/kafka -o /tmp/kafka-cleaned -r /tmp/kafka-clean-report.yaml -w 8
bash scripts/kafka_log_clean.sh --version
python3 tests/test_clean.py
```

Flags: `-c` config, `-i` input, `-o` output, `-w` workers, `-r` report, `--stdin`, `--print-default-config`.

## Config schema

```yaml
config:
  omit:
    - type: File
      pattern: "**/*.jks"
    - type: File
      pattern: "**/kafka_server_jaas.conf"
  obfuscate:
    - type: IP
      replacementType: Consistent
      target: All
    - type: MAC
      replacementType: Consistent
    - type: Email
      replacementType: Consistent
    - type: Domain
      replacementType: Consistent
      domainNames: [kafka.internal]
    - type: Keywords
      target: FileContents
      replacement:
        kafka-broker-1: broker-a
        payments-pii: topic-redacted
    - type: Regex
      regex: '(?i)(principal\s*=\s*)User:[^\s,]+'
      replacement: '\1User:redacted'
    - type: Secrets
      enabled: true
    - type: PEM
      enabled: true
```

See [GROUP.md](GROUP.md). Catalog: https://github.com/nwlterry/nwlterry
