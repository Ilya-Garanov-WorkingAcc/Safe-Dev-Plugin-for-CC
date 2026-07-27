#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея platform_guard.py (PLAN.md 4.2).

Детект платформы подменяется на уровне открытия /proc/version: тест обязан
проверять обе ветки, а машина, на которой он идёт, всегда одна.
"""

import builtins
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-plg-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)
with open(os.path.join(os.environ["HOME"], ".claude", "secure-dev.local.json"),
          "w", encoding="utf-8") as fh:
    json.dump({"rule_levels": {"platform": "warn"}}, fh)

import importlib.util                                            # noqa: E402

from lib import audit, config                                    # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "platform_guard", os.path.join(ROOT, "hooks", "platform_guard.py"))
plg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plg)

FAILS = []
_counter = [0]
_real_open = builtins.open


def check(name, ok, detail=""):
    print("  [{:6}] {:50} {}".format("PASS" if ok else "FAIL", name[:50], detail[:70]))
    if not ok:
        FAILS.append(name)


def fake_proc_version(content):
    """Подменяет ТОЛЬКО /proc/version, остальные открытия идут как есть."""
    def opener(path, *args, **kwargs):
        if str(path) == "/proc/version":
            if content is None:
                raise OSError("нет такого файла")
            return io.StringIO(content)
        return _real_open(path, *args, **kwargs)
    return opener


def run():
    _counter[0] += 1
    payload = {"hook_event_name": "SessionStart", "source": "startup",
               "session_id": "plg-{}".format(_counter[0]), "cwd": ROOT}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        plg.main()
    except SystemExit:
        pass
    finally:
        out = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    return json.loads(out) if out else {}


print("=== A: детект WSL ===")
builtins.open = fake_proc_version(
    "Linux version 6.6.87.2-microsoft-standard-WSL2 (gcc ...)")
check("microsoft в /proc/version → wsl", audit.is_wsl() is True)
builtins.open = fake_proc_version("Linux version 6.8.0-generic (buildd@lcy02)")
check("обычный Linux → не wsl", audit.is_wsl() is False)
builtins.open = fake_proc_version(None)
check("отсутствие /proc/version → не wsl", audit.is_wsl() is False)

print("=== B: поведение хука вне WSL ===")
builtins.open = fake_proc_version("Linux version 6.8.0-generic")
result = run()
context = (result.get("hookSpecificOutput") or {}).get("additionalContext", "")
check("предупреждение выдано", bool(context), str(result)[:60])
check("названа требуемая платформа", "WSL" in context, context[:70])
check("есть указание, как исправить", "wsl -d" in context, context[:70])
check("сессия не блокируется",
      "permissionDecision" not in (result.get("hookSpecificOutput") or {}))

print("=== C: поведение хука в WSL ===")
builtins.open = fake_proc_version(
    "Linux version 6.6.87.2-microsoft-standard-WSL2")
result = run()
check("в WSL хук молчит", result == {}, str(result)[:60])

print("=== D: аудит ===")
builtins.open = _real_open
records = [r for r in audit.iter_records() if r.get("hook") == "platform_guard"]
check("записана ровно одна запись", len(records) == 1, str(len(records)))
check("правило platform-not-wsl",
      bool(records) and records[0].get("rule") == "platform-not-wsl")
check("класс platform", bool(records) and records[0].get("class") == "platform")

print("=== E: уровень из политики ===")
with open(os.path.join(os.environ["HOME"], ".claude", "secure-dev.local.json"),
          "w", encoding="utf-8") as fh:
    json.dump({}, fh)
config.reset_cache()
check("класс platform в политике по умолчанию — warn",
      config.effective_level("platform-not-wsl", "platform") == "warn",
      config.effective_level("platform-not-wsl", "platform"))

print("=== F: устойчивость ===")
HOOK = os.path.join(ROOT, "hooks", "platform_guard.py")
for payload in ("", "{битый", json.dumps({"hook_event_name": "PreToolUse"})):
    proc = subprocess.run([sys.executable, HOOK], input=payload,
                          capture_output=True, text=True, env=dict(os.environ))
    check("rc 0 на входе {!r}".format(payload[:12]), proc.returncode == 0,
          proc.stderr[:60])

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
