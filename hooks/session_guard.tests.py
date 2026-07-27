#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея session_guard.py (PLAN.md 1.8–1.9).

Основное проверяемое свойство — heartbeat: он и есть ответ на вопрос
«работает ли контроль у сотрудника». Отдельно проверяется формулировка
additionalContext: императивы в нём триггерят собственную защиту Claude от
инъекций, и текст показывается пользователю вместо применения.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-sg-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)

import importlib.util                                            # noqa: E402

from lib import audit, config                                    # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "session_guard", os.path.join(ROOT, "hooks", "session_guard.py"))
sg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sg)

FAILS = []
_counter = [0]

IMPERATIVES = ("не выполняй", "игнорируй", "запрещено выполнять", "ты должен",
               "you must", "do not execute", "never run")


def check(name, ok, detail=""):
    print("  [{:6}] {:50} {}".format("PASS" if ok else "FAIL", name[:50], detail[:70]))
    if not ok:
        FAILS.append(name)


def run(event="SessionStart", source="startup", agent_id=None):
    _counter[0] += 1
    payload = {"hook_event_name": event, "session_id": "sg-{}".format(_counter[0]),
               "cwd": ROOT, "source": source}
    if agent_id:
        payload["agent_id"] = agent_id
        payload["agent_type"] = "general-purpose"
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        sg.main()
    except SystemExit:
        pass
    finally:
        out = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    return json.loads(out) if out else {}


def heartbeats():
    return [r for r in audit.iter_records() if r.get("kind") == "heartbeat"]


print("=== A: heartbeat пишется на каждом старте ===")
run()
records = heartbeats()
check("запись появилась", len(records) == 1, str(len(records)))
beat = records[-1] if records else {}
for field in ("plugin_version", "policy_version", "policy_sha256", "level",
              "rules_loaded", "settings_template_applied", "wsl", "user", "host",
              "session_source", "ts", "policy_tampered"):
    check("поле {}".format(field), field in beat, str(sorted(beat))[:60])
check("версия плагина 2.x", str(beat.get("plugin_version", "")).startswith("2."),
      str(beat.get("plugin_version")))
check("правил загружено больше 30", beat.get("rules_loaded", 0) > 30,
      str(beat.get("rules_loaded")))

run(source="resume")
check("второй старт — вторая запись", len(heartbeats()) == 2, str(len(heartbeats())))

print("=== B: состояние политики ===")
check("состояние печати политики определено",
      beat.get("policy_seal") in ("ok", "tampered", "unsealed"),
      str(beat.get("policy_seal")))
check("sha256 политики непустой", bool(beat.get("policy_sha256")))

print("=== C: контекст сессии ===")
result = run()
context = (result.get("hookSpecificOutput") or {}).get("additionalContext", "")
check("контекст непустой", bool(context))
check("сформулирован фактами, без императивов",
      not any(word in context.lower() for word in IMPERATIVES), context[:70])
check("назван режим", config.level() in context, context[:70])
check("упомянут sudo", "sudo" in context)
check("возвращены watchPaths",
      ".mcp.json" in ((result.get("hookSpecificOutput") or {}).get("watchPaths") or []))

print("=== D: баннер ===")
check("баннер показан", "secure-dev" in result.get("systemMessage", ""),
      result.get("systemMessage", "")[:60])
with open(os.path.join(os.environ["HOME"], ".claude", "secure-dev.local.json"),
          "w", encoding="utf-8") as fh:
    json.dump({"ui": {"banner": False}}, fh)
config.reset_cache()
result = run()
check("ui.banner: false отключает баннер", "systemMessage" not in result,
      str(list(result))[:60])
check("контекст при этом остаётся",
      "additionalContext" in (result.get("hookSpecificOutput") or {}))

print("=== E: субагент ===")
result = run(event="SubagentStart", agent_id="agent-1")
context = (result.get("hookSpecificOutput") or {}).get("additionalContext", "")
check("субагент получает контекст", bool(context))
check("сказано, что политика идентична", "идентич" in context, context[:70])

print("=== F: инвариант — в аудите нет диалога ===")
blob = ""
for path in audit.day_files():
    with open(path, "r", encoding="utf-8") as fh:
        blob += fh.read()
check("нет полей с содержимым диалога",
      not any(k in blob for k in ('"prompt_text"', '"messages"', '"transcript"')))

print("=== G: устойчивость ===")
HOOK = os.path.join(ROOT, "hooks", "session_guard.py")
for payload in ("", "{битый", json.dumps({"hook_event_name": "PreToolUse"})):
    proc = subprocess.run([sys.executable, HOOK], input=payload,
                          capture_output=True, text=True, env=dict(os.environ))
    check("rc 0 на входе {!r}".format(payload[:12]), proc.returncode == 0,
          proc.stderr[:60])

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
