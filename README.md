# kafka_log_clean

Go log cleaner for Confluent Kafka broker, controller, Connect, and Schema Registry logs. Same omit + obfuscate + `report.yaml` model as [openshift/must-gather-clean](https://github.com/openshift/must-gather-clean).

Sibling: [elastic_log_clean](https://github.com/nwlterry/elastic_log_clean).

## Download

Pre-built binaries are on the [Releases](https://github.com/nwlterry/kafka_log_clean/releases) page (`v1.0.0`).

| Archive | Use on |
|---------|--------|
| `kafka_log_clean_1.0.0_linux_amd64.tar.gz` | RHEL / most servers |
| `kafka_log_clean_1.0.0_linux_arm64.tar.gz` | Linux aarch64 |
| `kafka_log_clean_1.0.0_darwin_amd64.tar.gz` | Intel macOS |
| `kafka_log_clean_1.0.0_darwin_arm64.tar.gz` | Apple Silicon |
| `kafka_log_clean_1.0.0_windows_amd64.zip` | Windows 11 |

```bash
curl -fsSL -O https://github.com/nwlterry/kafka_log_clean/releases/download/v1.0.0/kafka_log_clean_1.0.0_linux_amd64.tar.gz
tar -xzf kafka_log_clean_1.0.0_linux_amd64.tar.gz
chmod +x kafka_log_clean
./kafka_log_clean --version
./kafka_log_clean -v -i /var/log/kafka -o /tmp/kafka-logs-cleaned
```

## Windows 11

```powershell
powershell -ExecutionPolicy Bypass -File .\kafka_log_clean.ps1 -InputPath .\kafka-support-bundle.zip
.\kafka_log_clean.ps1 -InputPath C:\logs\kafka -VerboseLog
.\kafka_log_clean.ps1 -InputPath .\server.log -Config .\kafka_ip_name_map.yaml
```

## What is redacted

Consistent tokens (`x-ipv4-…`, `x-email-…`, `x-ldapdn-…`, `x-certsubj-…`, `x-redacted-secret-x`).

- IPv4 / IPv6 / MAC
- Email addresses
- LDAP / JAAS DNs and search filters
- Certificate subjects and issuers
- Passwords, SASL/JAAS secrets, keystore passwords, API keys, URL userinfo
- Optional IP-to-name map via `config/kafka_ip_name_map.yaml`

## Guards

- Module coordinates such as `io.netty.transport@4.1.135.Final` are not emails
- Clock values such as `07:29:19` are not IPv6
- `x-redacted-secret-x@host` is not reclassified as an email
- LDAP DNs keep multi-word values and the full `DC=` chain, including a trailing `}}`

Flags: `-c` `-i` `-o` `-w` `-r` `-v`. Do **not** share `report.yaml`.


## Archives

Input can be a folder or an archive. Supported: `.zip`, `.tar`, `.tar.gz`, `.tgz`, and single-file `.gz`.

The tool expands the archive, scans every file (including nested zip/tar.gz), then writes the same archive type back.

## Report

Default report path is `report-<input>.yaml` next to the working directory, using the archive or folder name:

- `diagnostics.zip` → `report-diagnostics.yaml`
- `support-bundle.tar.gz` → `report-support-bundle.yaml`
- `cluster-logs/` → `report-cluster-logs.yaml`

Override with `-r`. Do **not** share the report.

## Principals

Kafka authorizer / ACL lines such as `User:first_name.last_name` and `Principal = User:alice` become `User:x-user-…` with a consistent token.
