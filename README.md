# kafka_log_clean

Go rewrite of the Confluent Kafka broker / Connect / Schema Registry log cleaner, using the same omit + obfuscate + `report.yaml` model as [openshift/must-gather-clean](https://github.com/openshift/must-gather-clean).

Sibling: [elastic_log_clean](https://github.com/nwlterry/elastic_log_clean).

## Download

Pre-built binaries are on the [Releases](https://github.com/nwlterry/kafka_log_clean/releases) page (`v1.2.1`).

| Archive | Use on |
|---------|--------|
| `kafka_log_clean_1.2.1_linux_amd64.tar.gz` | RHEL / most servers |
| `kafka_log_clean_1.2.1_linux_arm64.tar.gz` | Linux aarch64 |
| `kafka_log_clean_1.2.1_darwin_amd64.tar.gz` | Intel macOS |
| `kafka_log_clean_1.2.1_darwin_arm64.tar.gz` | Apple Silicon |
| `kafka_log_clean_1.2.1_windows_amd64.zip` | Windows |

```bash
curl -fsSL -O https://github.com/nwlterry/kafka_log_clean/releases/download/v1.2.1/kafka_log_clean_1.2.1_linux_amd64.tar.gz
tar -xzf kafka_log_clean_1.2.1_linux_amd64.tar.gz
chmod +x kafka_log_clean
./kafka_log_clean --version
./kafka_log_clean -i /var/log/kafka -o /tmp/kafka-logs-cleaned
```

Each archive includes the binary plus `kafka_default.yaml` and `kafka_ip_name_map.yaml`.

## Windows 11

Unpack `kafka_log_clean_1.2.1_windows_amd64.zip`, then from PowerShell:

```powershell
cd ~\Downloads\kafka_log_clean_1.2.1_windows_amd64
powershell -ExecutionPolicy Bypass -File .\kafka_log_clean.ps1 -InputPath .\kafka-support-bundle.zip
.\kafka_log_clean.ps1 -InputPath C:\logs\kafka -VerboseLog
.\kafka_log_clean.ps1 -InputPath .\server.log -Config .\kafka_ip_name_map.yaml
```

`-VerboseLog` prints every cleaned/omitted file. The exe can also be run directly:

```powershell
.\kafka_log_clean.exe -v -i .\kafka-support-bundle.zip -o .\scrubbed-kafka-support-bundle.zip
```

## Build

Requires Go 1.22+.

```bash
make
make test
make install
bash scripts/kafka_log_clean.sh --version
```

## Usage

```bash
./bin/kafka_log_clean -i /var/log/kafka -o /tmp/kafka-logs-cleaned
./bin/kafka_log_clean -i server.log -o server.cleaned.log
./bin/kafka_log_clean -i kafka-support-bundle.zip -o scrubbed-kafka-support-bundle.zip
./bin/kafka_log_clean -c config/kafka_ip_name_map.yaml -i kafka-support-bundle.zip -o scrubbed-kafka-support-bundle.zip
echo 'sasl.jaas.config=... password="secret"; listener 10.40.50.11:9093' | ./bin/kafka_log_clean --stdin
./bin/kafka_log_clean --print-default-config
```

Flags match must-gather-clean: `-c` `-i` `-o` `-w` `-r`.

Do **not** share `report.yaml`.

## Matcher guards (v1.2.1)

Email and IPv6 candidates are filtered after the regex so diagnostic noise is not tokenized:

- Java / Maven coords such as `io.netty.transport@4.1.135.Final` stay as-is (TLD `Final` / version-shaped domain).
- Clock values such as `07:29:19` and `2026-09-24T07:29:19,123` are not treated as IPv6.
- Real addresses (`sre@corp.example.com`, `2001:db8::1`) are still tokenized.

## Config: IP only vs IP + custom names

Passing `-c` **replaces** the built-in config. It does not merge. A file that only contains `type: IP` will rewrite IPs and skip MAC / email / secrets / PEM / omit.

Default (`type: IP`, `replacementType: Consistent`) assigns tokens:

`10.99.1.8` → `x-ipv4-0000000001-x` (same source IP always gets the same token). Loopback `127.0.0.1` / `0.0.0.0` / `::1` is left alone.

The `IP` rule has no name map. Pin specific IPs or hostnames with `Keywords`. Keywords run **before** IP, so a mapped address is not tokenized again.

Copy [config/kafka_ip_name_map.yaml](config/kafka_ip_name_map.yaml) and edit the `replacement` maps:

```yaml
obfuscate:
  - type: IP
    replacementType: Consistent
    target: All
  - type: Keywords
    target: FileContents
    replacement:
      10.40.50.11: broker-a
      10.40.50.12: broker-b
      kafka-prod-01: broker-a
      kafka-prod-02: broker-b
  - type: Keywords
    target: FilePath
    replacement:
      kafka-prod-01: broker-a
      kafka-prod-02: broker-b
```

On a line `kafka-prod-01 10.40.50.11 10.99.1.8:9093`:

| original        | result                |
|-----------------|-----------------------|
| `kafka-prod-01` | `broker-a`            |
| `10.40.50.11`   | `broker-a`            |
| `10.99.1.8`     | `x-ipv4-0000000001-x` |

`FilePath` rewrites directory/file names; `FileContents` rewrites log text.

Do not commit a filled-in map or `report.yaml`.

## Layout

```
cmd/kafka_log_clean/main.go
pkg/clean/
config/kafka_default.yaml
config/kafka_ip_name_map.yaml
examples/sample-server.log
scripts/kafka_log_clean.sh
Makefile
```

See [GROUP.md](GROUP.md).

## Principal / username redaction

In addition to IPs, emails, MACs, LDAP DNs and certificate subjects, the cleaner
redacts Kafka-style and MDS-style user identities while preserving the surrounding
structure:

| form | example | result |
|------|---------|--------|
| `User:` principal | `Principal = User:alice` | `Principal = User:x-user-…-x` |
| dotted name | `User:first_name.last_name` | `User:x-user-…-x` |
| `principal:User:` | `principal:User:bob` | `principal:User:x-user-…-x` |
| `username=` | `username=carol` / `username="carol"` | `username=x-user-…-x` |
| `userPrincipalName=` | `userPrincipalName=dave` | `userPrincipalName=x-user-…-x` |
| JSON principal | `"principal":"eve"` | `"principal":"x-user-…-x"` |
| login phrase | `login successful for user frank` | `login successful for user x-user-…-x` |
| MDS request log | `[date] INFO host - alice [utc] GET` | `host - x-user-…-x [utc] GET` |

This covers the forms seen in Confluent broker metadata-server logs, the
authorizer logger (`Principal = User:…`), the request logger (`principal:User:…`),
JAAS / REST auth (`username=…`), and audit JSON (`"principal":"User:…"`).

The same consistent token is used for the same name across the run. Already-redacted
tokens (`x-…`) are left alone.
