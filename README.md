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
echo 'sasl.jaas.config=... password="secret"; listener 10.40.50.11:9093' | ./bin/kafka_log_clean --stdin
./bin/kafka_log_clean --print-default-config
```

Flags match must-gather-clean: `-c` `-i` `-o` `-w` `-r`.

Do **not** share `report.yaml`.

## Layout

```
cmd/kafka_log_clean/main.go
pkg/clean/
config/kafka_default.yaml
examples/sample-server.log
scripts/kafka_log_clean.sh
Makefile
```

See [GROUP.md](GROUP.md).
