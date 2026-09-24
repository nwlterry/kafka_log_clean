# kafka_log_clean

Go rewrite of the Confluent Kafka broker / Connect / Schema Registry log cleaner, using the same omit + obfuscate + `report.yaml` model as [openshift/must-gather-clean](https://github.com/openshift/must-gather-clean).

Sibling: [elastic_log_clean](https://github.com/nwlterry/elastic_log_clean).

## Download

Pre-built binaries are on the [Releases](https://github.com/nwlterry/kafka_log_clean/releases) page (`v1.2.0`).

| Archive | Use on |
|---------|--------|
| `kafka_log_clean_1.2.0_linux_amd64.tar.gz` | RHEL / most servers |
| `kafka_log_clean_1.2.0_linux_arm64.tar.gz` | Linux aarch64 |
| `kafka_log_clean_1.2.0_darwin_amd64.tar.gz` | Intel macOS |
| `kafka_log_clean_1.2.0_darwin_arm64.tar.gz` | Apple Silicon |
| `kafka_log_clean_1.2.0_windows_amd64.zip` | Windows 11 |

```bash
curl -fsSL -O https://github.com/nwlterry/kafka_log_clean/releases/download/v1.2.0/kafka_log_clean_1.2.0_linux_amd64.tar.gz
tar -xzf kafka_log_clean_1.2.0_linux_amd64.tar.gz
chmod +x kafka_log_clean
./kafka_log_clean -v -i /var/log/kafka -o /tmp/kafka-logs-cleaned
```

## Windows 11

Copy the support bundle or `server.log` off the broker, unpack the windows zip, then:

```powershell
powershell -ExecutionPolicy Bypass -File .\kafka_log_clean.ps1 -InputPath .\kafka-support-bundle.zip
.\kafka_log_clean.ps1 -InputPath C:\logs\kafka -VerboseLog
.\kafka_log_clean.ps1 -InputPath .\server.log -Config .\kafka_ip_name_map.yaml
```

`-v` / `-VerboseLog` prints every cleaned or omitted file. Stage lines always print.

Flags: `-c` `-i` `-o` `-w` `-r` `-v`. Do **not** share `report.yaml`.
