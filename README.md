# kafka_log_clean

Go rewrite of the Confluent Kafka broker / Connect / Schema Registry log cleaner, using the same omit + obfuscate + `report.yaml` model as [openshift/must-gather-clean](https://github.com/openshift/must-gather-clean).

Sibling: [elastic_log_clean](https://github.com/nwlterry/elastic_log_clean).

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
