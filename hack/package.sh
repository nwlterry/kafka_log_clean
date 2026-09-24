#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="kafka_log_clean"
VERSION="${1:-v1.2.0}"
VERSION="${VERSION#v}"
cd "$ROOT"
rm -rf dist
mkdir -p dist
targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)
for spec in "${targets[@]}"; do
  set -- $spec
  os="$1"
  arch="$2"
  ext=""
  [[ "$os" == windows ]] && ext=".exe"
  outdir="$(mktemp -d)"
  name="${BIN}_${VERSION}_${os}_${arch}"
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" -o "$outdir/${BIN}${ext}" "./cmd/${BIN}"
  cp config/kafka_default.yaml config/kafka_ip_name_map.yaml README.md LICENSE scripts/kafka_log_clean.ps1 "$outdir/"
  if [[ "$os" == windows ]]; then
    (cd "$outdir" && zip -q "${ROOT}/dist/${name}.zip" "${BIN}${ext}" kafka_default.yaml kafka_ip_name_map.yaml README.md LICENSE kafka_log_clean.ps1)
  else
    tar -C "$outdir" -czf "${ROOT}/dist/${name}.tar.gz" "${BIN}${ext}" kafka_default.yaml kafka_ip_name_map.yaml README.md LICENSE kafka_log_clean.ps1
  fi
  rm -rf "$outdir"
done
(cd dist && sha256sum * > SHA256SUMS.txt)
ls -l dist
