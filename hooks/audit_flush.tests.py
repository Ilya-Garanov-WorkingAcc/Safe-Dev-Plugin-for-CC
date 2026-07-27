#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея audit_flush.py и lib/export.py (PLAN.md 4.3–4.4).

Критерий фазы 4: переключение export.type на file с временным каталогом даёт
корректную выкладку <path>/<user>/<host>/YYYY-MM-DD.jsonl без потери записей.
"""

import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-af-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)

import importlib.util                                            # noqa: E402

from lib import audit, config, export, policy                    # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "audit_flush", os.path.join(ROOT, "hooks", "audit_flush.py"))
af = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(af)

FAILS = []
SHARE = os.path.join(TMP, "share")


def check(name, ok, detail=""):
    print("  [{:6}] {:50} {}".format("PASS" if ok else "FAIL", name[:50], detail[:70]))
    if not ok:
        FAILS.append(name)


def run():
    payload = {"hook_event_name": "SessionEnd", "session_id": "af", "cwd": ROOT}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        af.main()
    except SystemExit:
        pass
    finally:
        out = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    return json.loads(out) if out else {}


print("=== A: режим none — ничего не уходит ===")
audit.write({"hook": "test", "rule": "r1", "action": "logged"}, {})
result = export.export_pending({"type": "none"})
check("выгрузка отключена", result.ok and result.sent == 0, str(result.as_dict()))
run()
check("хук не создаёт каталог экспорта", not os.path.exists(SHARE))

print("=== B: режим file ===")
result = export.export_pending({"type": "file", "path": SHARE})
expected = os.path.join(SHARE, audit.user(), audit.host(),
                        os.path.basename(audit.day_file()))
check("файл выложен по <path>/<user>/<host>/", os.path.isfile(expected), expected)
check("отчёт сообщает об отправке", result.ok and result.sent == 1,
      str(result.as_dict()))

with open(expected, "r", encoding="utf-8") as fh:
    copied = [json.loads(line) for line in fh if line.strip()]
with open(audit.day_file(), "r", encoding="utf-8") as fh:
    original = [json.loads(line) for line in fh if line.strip()]
check("записи не потеряны", len(copied) == len(original),
      "{} vs {}".format(len(copied), len(original)))

print("=== C: повторная выгрузка ===")
result = export.export_pending({"type": "file", "path": SHARE})
check("уже выгруженное не отправляется повторно", result.sent == 0,
      str(result.as_dict()))
audit.write({"hook": "test", "rule": "r2", "action": "logged"}, {})
result = export.export_pending({"type": "file", "path": SHARE})
check("дозапись возобновляет выгрузку", result.sent == 1, str(result.as_dict()))

print("=== D: недоступный путь — не ошибка ===")
audit.write({"hook": "test", "rule": "r2b", "action": "logged"}, {})
result = export.export_pending({"type": "file", "path": "/proc/nonexistent/x"})
check("выгрузка помечена неуспешной", not result.ok, str(result.as_dict()))
check("причина зафиксирована", bool(result.reason), str(result.reason)[:60])
audit.write({"hook": "test", "rule": "r3", "action": "logged"}, {})
result = export.export_pending({"type": "file", "path": SHARE})
check("после сбоя выгрузка повторяется", result.sent == 1, str(result.as_dict()))

print("=== E: режим http без URL ===")
result = export.export([{"a": 1}], {"type": "http"})
check("отсутствие url — ошибка, а не исключение",
      not result.ok and "url" in (result.reason or ""), str(result.as_dict()))

print("=== F: ротация ===")
old_day = (datetime.date.today() - datetime.timedelta(days=40)).strftime("%Y-%m-%d")
old_path = os.path.join(audit.audit_dir(), old_day + ".jsonl")
with open(old_path, "w", encoding="utf-8") as fh:
    fh.write('{"v":1,"kind":"event"}\n')
removed = audit.rotate(30)
check("старый файл удалён", not os.path.exists(old_path) and removed >= 1,
      str(removed))
check("сегодняшний файл на месте", os.path.exists(audit.day_file()))

print("=== G: уборка состояния сессий ===")
policy.state_set("stale-session", "k", "v")
stale = policy.state_path("stale-session")
os.utime(stale, (0, 0))
check("протухший файл состояния удалён",
      policy.cleanup_states() >= 1 and not os.path.exists(stale))

print("=== H: хук пишет собственную запись ===")
run()
records = [r for r in audit.iter_records() if r.get("hook") == "audit_flush"]
check("запись есть", bool(records), str(len(records)))
check("в evidence есть счётчики",
      "rotated=" in ((records[-1].get("evidence") or "") if records else ""),
      ((records[-1].get("evidence") or "") if records else "")[:60])

print("=== I: устойчивость и дефолт политики ===")
HOOK = os.path.join(ROOT, "hooks", "audit_flush.py")
for payload in ("", "{битый", json.dumps({"hook_event_name": "PreToolUse"})):
    proc = subprocess.run([sys.executable, HOOK], input=payload,
                          capture_output=True, text=True, env=dict(os.environ))
    check("rc 0 на входе {!r}".format(payload[:12]), proc.returncode == 0,
          proc.stderr[:60])

check("политика по умолчанию — экспорт выключен",
      (config.audit_cfg().get("export") or {}).get("type") == "none",
      str(config.audit_cfg().get("export")))

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
