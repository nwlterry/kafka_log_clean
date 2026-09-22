#!/usr/bin/env python3
"""kafka_log_clean — obfuscate sensitive data in Confluent Kafka logs.

Same omit/obfuscate/report model as OpenShift must-gather-clean and
elastic_log_clean. Tuned for broker/controller/connect/schema-registry
server logs, log4j dumps, JAAS snippets, and support bundles.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

VERSION = "1.0.0"
TEXT_EXTENSIONS = {
    ".log", ".txt", ".json", ".ndjson", ".yml", ".yaml", ".xml", ".csv",
    ".properties", ".conf", ".cfg", ".ini", ".out", ".err", ".md", ".html",
}
SKIP_COPY_AS_BINARY = {".p12", ".jks", ".keystore", ".truststore", ".so", ".dll", ".exe", ".bin"}
LOCAL_IPV4 = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
LOCAL_IPV6 = {"::1", "::", "https://example.net/id/garnet"}
IPV4_RE = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?::[0-9A-Fa-f]{1,4}){1,7})(?![0-9A-Fa-f:])")
MAC_RE = re.compile(r"(?<![:0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![:0-9A-Fa-f])")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.DOTALL)
SECRET_PATTERNS = [
    ("authorization", re.compile(r"(?i)(authorization\s*[:=]\s*)(basic|bearer)\s+[A-Za-z0-9+/=._\-]+"), r"\1\2 x-redacted-auth-x"),
    ("jaas_password", re.compile(r'(?i)((?:password|passwd|username)\s*=\s*)(?:"[^"]+"|\'[^\']+\'|[^\s;"\']+)'), r"\1x-redacted-secret-x"),
    ("jaas_required", re.compile(r"(?i)(org\.apache\.kafka\.common\.security\.[A-Za-z0-9.]+LoginModule\s+required\s+)(.*?)(;)"), r"\1username=\"x-redacted-user-x\" password=\"x-redacted-secret-x\"\3"),
    ("ssl_passwords", re.compile(r"(?i)((?:ssl\.(?:keystore|truststore|key)\.password|ssl\.keystore\.key|listener\.name\.[^=\s]+\.ssl\.(?:keystore|truststore|key)\.password|sasl\.jaas\.config|confluent\.license|basic\.auth\.user\.info|schema\.registry\.basic\.auth\.user\.info|producer\.sasl\.jaas\.config|consumer\.sasl\.jaas\.config|admin\.sasl\.jaas\.config|ldap\.java\.naming\.security\.credentials|confluent\.metadata\.sasl\.jaas\.config)\s*[=:]\s*)([^\s,]+)"), r"\1x-redacted-secret-x"),
    ("password_assignment", re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|sasl\.password)\s*[=:]\s*)([^\s,\"'}]+)"), r"\1x-redacted-secret-x"),
    ("quoted_password", re.compile(r'(?i)("(?:password|passwd|secret|token|api_key|authorization|jaas)"\s*:\s*")([^"]+)"'), r'\1x-redacted-secret-x"'),
    ("connection_string", re.compile(r"(?i)(://[^:/@\s]+:)([^@/\s]+)(@)"), r"\1x-redacted-secret-x\3"),
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "x-redacted-awskey-x"),
]

def die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)

def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        die("PyYAML is required. Install with: pip install pyyaml")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if "config" in data and isinstance(data["config"], dict):
        return data["config"]
    return data

def dump_yaml(data: Any, path: Path) -> None:
    if yaml is None:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, sort_keys=False, allow_unicode=True)

def is_probably_text(path: Path, sample: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix in SKIP_COPY_AS_BINARY:
        return False
    if suffix in TEXT_EXTENSIONS or path.name.lower() in {"server.properties", "producer.properties", "consumer.properties", "connect-distributed.properties", "kafka_server_jaas.conf", "log4j.properties", "log4j2.yaml", "log4j2.properties"}:
        return True
    if b"\x00" in sample[:2048]:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False

def match_glob(rel: str, pattern: str) -> bool:
    from fnmatch import fnmatch
    rel_norm = rel.replace("\\", "/").lstrip("./")
    pat = pattern.replace("\\", "/")
    candidates = {rel_norm, Path(rel_norm).name}
    pats = {pat, pat.lstrip("./")}
    if pat.startswith("**/"):
        pats.add(pat[3:])
        pats.add("*/" + pat[3:])
    for value in candidates:
        for p in pats:
            if fnmatch(value, p) or fnmatch(value, p.replace("**/", "*").replace("**", "*")):
                return True
    return False

@dataclass
class Replacement:
    canonical: str
    replaced_with: str
    occurrences: dict[str, int] = field(default_factory=dict)
    def add(self, original: str, n: int = 1) -> None:
        self.occurrences[original] = self.occurrences.get(original, 0) + n

class MappingStore:
    def __init__(self) -> None:
        self._maps: dict[str, dict[str, str]] = {}
        self._counters: dict[str, int] = {}
        self.replacements: dict[tuple[str, str], Replacement] = {}
    def consistent(self, kind: str, original: str, prefix: str) -> str:
        table = self._maps.setdefault(kind, {})
        key = original.lower() if kind in {"ipv4", "ipv6", "mac"} else original
        if key in table:
            token = table[key]
        else:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"x-{prefix}-{self._counters[kind]:010d}-x"
            table[key] = token
        rec_key = (kind, key)
        rec = self.replacements.get(rec_key)
        if rec is None:
            rec = Replacement(canonical=key, replaced_with=token)
            self.replacements[rec_key] = rec
        rec.add(original)
        return token
    def static_or_consistent(self, kind: str, original: str, prefix: str, replacement_type: str, static: str) -> str:
        if replacement_type.lower() == "static":
            rec_key = (kind, original.lower() if kind in {"ipv4", "ipv6", "mac"} else original)
            rec = self.replacements.get(rec_key)
            if rec is None:
                rec = Replacement(canonical=rec_key[1], replaced_with=static)
                self.replacements[rec_key] = rec
            rec.add(original)
            return static
        return self.consistent(kind, original, prefix)
    def report(self) -> list[dict[str, Any]]:
        return [{"canonical": rec.canonical, "replacedWith": rec.replaced_with, "occurrences": [{"original": k, "count": v} for k, v in sorted(rec.occurrences.items())]} for rec in sorted(self.replacements.values(), key=lambda r: r.replaced_with)]

class Cleaner:
    def __init__(self, config: dict[str, Any], store: MappingStore | None = None) -> None:
        self.config = config
        self.store = store or MappingStore()
        self.omit_rules = config.get("omit") or []
        self.obfuscate_rules = config.get("obfuscate") or []
        self.omitted: list[str] = []
        self.processed_files = 0
        self.custom_regex: list[tuple[re.Pattern[str], str]] = []
        self.keywords: dict[str, str] = {}
        self.domains: list[str] = []
        self.ip_mode = self.mac_mode = self.domain_mode = self.email_mode = "Consistent"
        self.enable_ip = self.enable_mac = self.enable_domain = self.enable_email = False
        self.enable_secrets = True
        self.enable_pem = True
        self.path_keywords: dict[str, str] = {}
        self._compile_rules()
    def _compile_rules(self) -> None:
        for rule in self.obfuscate_rules:
            rtype = str(rule.get("type", "")).lower()
            target = str(rule.get("target", "FileContents"))
            repl_type = str(rule.get("replacementType", "Consistent"))
            if rtype == "ip":
                self.enable_ip, self.ip_mode = True, repl_type
            elif rtype == "mac":
                self.enable_mac, self.mac_mode = True, repl_type
            elif rtype == "domain":
                self.enable_domain, self.domain_mode = True, repl_type
                self.domains.extend(rule.get("domainNames") or [])
            elif rtype == "email":
                self.enable_email, self.email_mode = True, repl_type
            elif rtype == "keywords":
                mapping = rule.get("replacement") or {}
                (self.path_keywords if target.lower() == "filepath" else self.keywords).update(mapping)
            elif rtype == "regex":
                pattern = rule.get("regex") or rule.get("pattern")
                if pattern:
                    self.custom_regex.append((re.compile(pattern), rule.get("replacement", "x-redacted-regex-x")))
            elif rtype in {"secrets", "secret"}:
                self.enable_secrets = bool(rule.get("enabled", True))
            elif rtype == "pem":
                self.enable_pem = bool(rule.get("enabled", True))
    def should_omit(self, rel: str) -> bool:
        for rule in self.omit_rules:
            rtype = str(rule.get("type", "")).lower()
            if rtype in {"file", "path"}:
                pattern = rule.get("pattern") or rule.get("path") or ""
                if pattern and match_glob(rel, pattern):
                    return True
            elif rtype == "extension":
                ext = rule.get("extension") or ""
                if ext and Path(rel).suffix.lower() == ext.lower():
                    return True
        return False
    def obfuscate_path(self, rel: str) -> str:
        out = rel
        for src, dst in sorted(self.path_keywords.items(), key=lambda kv: len(kv[0]), reverse=True):
            out = out.replace(src, dst)
        if self.enable_ip:
            out = IPV4_RE.sub(lambda m: self._repl_ip(m.group(0)), out)
        return out
    def _repl_ip(self, value: str) -> str:
        if value in LOCAL_IPV4:
            return value
        return self.store.static_or_consistent("ipv4", value, "ipv4", self.ip_mode, "x.x.x.x")
    def _repl_ipv6(self, value: str) -> str:
        if value.lower() in LOCAL_IPV6:
            return value
        return self.store.static_or_consistent("ipv6", value, "ipv6", self.ip_mode, "x:x:x:x:x:x:x:x")
    def _repl_mac(self, value: str) -> str:
        return self.store.static_or_consistent("mac", value, "mac", self.mac_mode, "xx:xx:xx:xx:xx:xx")
    def _repl_email(self, value: str) -> str:
        return self.store.static_or_consistent("email", value, "email", self.email_mode, "redacted@example.invalid")
    def obfuscate_text(self, text: str) -> str:
        if self.enable_pem:
            text = PEM_RE.sub("-----BEGIN REDACTED-----\nx-redacted-pem-x\n-----END REDACTED-----", text)
        for src, dst in sorted(self.keywords.items(), key=lambda kv: len(kv[0]), reverse=True):
            if src:
                text = text.replace(src, dst)
        for pattern, replacement in self.custom_regex:
            text = pattern.sub(replacement, text)
        if self.enable_secrets:
            for _name, pattern, replacement in SECRET_PATTERNS:
                text = pattern.sub(replacement, text)
        if self.enable_email:
            text = EMAIL_RE.sub(lambda m: self._repl_email(m.group(0)), text)
        if self.enable_mac:
            text = MAC_RE.sub(lambda m: self._repl_mac(m.group(0)), text)
        if self.enable_domain and self.domains:
            for domain in sorted(self.domains, key=len, reverse=True):
                token = self.store.static_or_consistent("domain", domain.lower(), "domain", self.domain_mode, "redacted.example.invalid")
                text = re.sub(re.escape(domain), lambda m, tok=token: tok, text, flags=re.IGNORECASE)
        if self.enable_ip:
            text = IPV4_RE.sub(lambda m: self._repl_ip(m.group(0)), text)
            text = IPV6_RE.sub(lambda m: self._repl_ipv6(m.group(0)), text)
        return text
    def process_bytes(self, data: bytes, name: str) -> tuple[bytes, bool]:
        if name.endswith(".gz") and not name.endswith(".tar.gz"):
            try:
                inner = gzip.decompress(data)
            except OSError:
                return data, False
            return gzip.compress(self.obfuscate_text(_decode(inner)).encode("utf-8")), True
        if not is_probably_text(Path(name), data[:4096]):
            return data, False
        return self.obfuscate_text(_decode(data)).encode("utf-8"), True

def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")

def iter_files(root: Path) -> Iterable[Path]:
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            yield Path(dirpath) / name

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

def process_tree(cleaner: Cleaner, src: Path, dst: Path, workers: int) -> None:
    files = list(iter_files(src))
    dst.mkdir(parents=True, exist_ok=True)
    def _one(path: Path) -> tuple[str, str]:
        rel = str(path.relative_to(src)).replace("\\", "/")
        if cleaner.should_omit(rel):
            return rel, "omit"
        target = dst / cleaner.obfuscate_path(rel)
        ensure_parent(target)
        cleaned, _ = cleaner.process_bytes(path.read_bytes(), path.name)
        target.write_bytes(cleaned)
        return rel, "ok"
    if workers <= 1:
        for path in files:
            rel, status = _one(path)
            if status == "omit":
                cleaner.omitted.append(rel)
            else:
                cleaner.processed_files += 1
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(_one, p) for p in files]
        for fut in as_completed(futs):
            rel, status = fut.result()
            if status == "omit":
                cleaner.omitted.append(rel)
            else:
                cleaner.processed_files += 1

def extract_zip(archive: Path, dest: Path) -> None:
    with zipfile.ZipFile(archive, "r") as zf:
        zf.extractall(dest)

def write_zip(src_dir: Path, archive: Path) -> None:
    ensure_parent(archive)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in iter_files(src_dir):
            zf.write(path, arcname=str(path.relative_to(src_dir)))

def default_config() -> dict[str, Any]:
    return {
        "omit": [
            {"type": "File", "pattern": "**/*.p12"},
            {"type": "File", "pattern": "**/*.jks"},
            {"type": "File", "pattern": "**/*.keystore"},
            {"type": "File", "pattern": "**/*.truststore"},
            {"type": "File", "pattern": "**/*.key"},
            {"type": "File", "pattern": "**/kafka_server_jaas.conf"},
        ],
        "obfuscate": [
            {"type": "IP", "replacementType": "Consistent", "target": "All"},
            {"type": "MAC", "replacementType": "Consistent", "target": "All"},
            {"type": "Email", "replacementType": "Consistent", "target": "FileContents"},
            {"type": "Secrets", "enabled": True},
            {"type": "PEM", "enabled": True},
        ],
    }

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kafka_log_clean", description="Obfuscate sensitive data in Confluent Kafka broker/connect/registry logs.")
    p.add_argument("-c", "--config")
    p.add_argument("-i", "--input")
    p.add_argument("-o", "--output")
    p.add_argument("-r", "--report", default="report.yaml")
    p.add_argument("-w", "--workers", type=int, default=os.cpu_count() or 4)
    p.add_argument("--stdin", action="store_true")
    p.add_argument("--version", action="store_true")
    p.add_argument("--print-default-config", action="store_true")
    return p

def run_stdin(cleaner: Cleaner) -> int:
    sys.stdout.write(cleaner.obfuscate_text(sys.stdin.read()))
    return 0

def resolve_output(inp: Path, output: str | None) -> Path:
    if output:
        return Path(output).expanduser().resolve()
    if inp.suffix.lower() == ".zip":
        return inp.with_name(f"scrubbed-{inp.name}")
    if inp.is_file():
        return inp.with_name(f"{inp.stem}.cleaned{inp.suffix}")
    return Path(str(inp) + "-cleaned").resolve()

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(VERSION)
        return 0
    if args.print_default_config:
        if yaml is None:
            print(json.dumps({"config": default_config()}, indent=2))
        else:
            yaml.safe_dump({"config": default_config()}, sys.stdout, sort_keys=False)
        return 0
    config = load_yaml(Path(args.config)) if args.config else default_config()
    cleaner = Cleaner(config)
    if args.stdin or (not args.input and not sys.stdin.isatty()):
        return run_stdin(cleaner)
    if not args.input:
        die("provide -i/--input or pipe text on stdin")
    inp = Path(args.input).expanduser().resolve()
    if not inp.exists():
        die(f"input not found: {inp}")
    out = resolve_output(inp, args.output)
    report_path = Path(args.report).expanduser().resolve()
    with tempfile.TemporaryDirectory(prefix="kafka_log_clean_") as tmp:
        tmp_path = Path(tmp)
        src_root, dst_root = tmp_path / "src", tmp_path / "dst"
        src_root.mkdir(); dst_root.mkdir()
        if inp.suffix.lower() == ".zip":
            extract_zip(inp, src_root)
            process_tree(cleaner, src_root, dst_root, max(1, args.workers))
            if out.suffix.lower() == ".zip":
                write_zip(dst_root, out)
            else:
                if out.exists():
                    shutil.rmtree(out)
                shutil.copytree(dst_root, out)
        elif inp.is_dir():
            process_tree(cleaner, inp, out if out.suffix.lower() != ".zip" else dst_root, max(1, args.workers))
            if out.suffix.lower() == ".zip":
                write_zip(dst_root, out)
        else:
            rel = inp.name
            if cleaner.should_omit(rel):
                cleaner.omitted.append(rel)
            else:
                cleaned, _ = cleaner.process_bytes(inp.read_bytes(), inp.name)
                if out.suffix.lower() == ".zip":
                    ensure_parent(out)
                    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr(cleaner.obfuscate_path(rel), cleaned)
                else:
                    ensure_parent(out)
                    out.write_bytes(cleaned)
                cleaner.processed_files += 1
    dump_yaml({"tool": "kafka_log_clean", "version": VERSION, "input": str(inp), "output": str(out), "processedFiles": cleaner.processed_files, "omittedFiles": sorted(cleaner.omitted), "replacements": cleaner.store.report(), "config": config, "warning": "Do not share this report. It maps original values to replacements."}, report_path)
    print(f"cleaned: {out}")
    print(f"report:  {report_path}  (keep private)")
    print(f"files:   {cleaner.processed_files} processed, {len(cleaner.omitted)} omitted")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
