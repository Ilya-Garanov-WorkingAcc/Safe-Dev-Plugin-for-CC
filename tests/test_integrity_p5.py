#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Целостность плагина и выгрузка — фаза 5 (аудит 03.10.2026)."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-p5-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)

from lib import audit, config, export                          # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print("  [{:6}] {:54} {}".format("PASS" if ok else "FAIL", name[:54], str(detail)[:45]))
    if not ok:
        FAILS.append(name)


print("=== A: печать кода плагина ===")
status = config.seal_status()
check("seal_status возвращает известное значение",
      status in ("ok", "tampered", "code_tampered", "unsealed"), status)
check("code_sha256 детерминирован",
      config.code_sha256() == config.code_sha256())

print("=== B: нечитаемая политика → строгий пол, а не audit ===")
# Подменяем plugin_root на временную копию с испорченной policy.json.
fake = os.path.join(TMP, "fakeplugin")
shutil.copytree(ROOT, fake, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"))
with open(os.path.join(fake, "policy.json"), "w", encoding="utf-8") as fh:
    fh.write("{ это не json")
env = dict(os.environ, CLAUDE_PLUGIN_ROOT=fake)
probe = (
    "import sys; sys.path.insert(0, %r); from lib import hookio, config;"
    "hookio.plugin_root = lambda: %r; config.reset_cache();"
    "print(config.level())" % (fake, fake))
out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env)
check("при нечитаемой policy.json level = strict",
      out.stdout.strip() == "strict", out.stdout.strip() or out.stderr[-60:])

print("=== C: выгрузка http защищена ===")
check("http:// отклоняется",
      not export._http_send([{"a": 1}], {"type": "http", "url": "http://x/y"}).ok)
check("хост вне allowed_hosts отклоняется",
      not export._http_send([{"a": 1}], {
          "type": "http", "url": "https://evil.example/c",
          "allowed_hosts": ["collector.corp"]}).ok)
check("https на разрешённый хост не отклоняется по политике (сеть недоступна — ошибка сети)",
      "allowed_hosts" not in (export._http_send([{"a": 1}], {
          "type": "http", "url": "https://collector.corp/c",
          "allowed_hosts": ["collector.corp"]}).reason or ""))
issues = config.validate({"schema_version": 1, "level": "audit",
                          "audit": {"export": {"type": "http", "url": "http://x"}}})
check("validate ловит http:// в url", any("https" in i for i in issues), issues)

print("=== D: цепочка аудита ===")
audit.write({"hook": "t", "rule": "R1", "evidence": "one"}, {"session_id": "s"})
audit.write({"hook": "t", "rule": "R2", "evidence": "two"}, {"session_id": "s"})
recs = [r for r in audit.iter_records() if r.get("rule", "").startswith("R")]
check("у записей есть seq", all("seq" in r for r in recs), [r.get("seq") for r in recs])
check("seq монотонно растёт",
      [r["seq"] for r in recs] == sorted(r["seq"] for r in recs))
check("prev второй записи = hash первой",
      len(recs) >= 2 and recs[1]["prev"] == recs[0]["h"],
      "{} vs {}".format(recs[1].get("prev", "")[:8], recs[0].get("h", "")[:8]))
chain = audit.read_json(audit._chain_path(), {})
check("состояние цепочки хранит последний seq и hash",
      chain.get("seq") == recs[-1]["seq"] and chain.get("last_hash") == recs[-1]["h"])

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
