#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея path_guard.py (PLAN.md 4.1, критерий «cat ~/.ssh/id_ed25519 заблокирован»).

Отдельно проверяется Bash-ветка: именно она — расширение относительно
декларативных permissions.deny, которые закрывают инструмент Read, но не
закрывают ту же операцию, выполненную командой.
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

TMP = tempfile.mkdtemp(prefix="secure-dev-pg-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)
with open(os.path.join(os.environ["HOME"], ".claude", "secure-dev.local.json"),
          "w", encoding="utf-8") as fh:
    json.dump({"level": "strict"}, fh)

WORKDIR = os.path.join(TMP, "project")
os.makedirs(WORKDIR, exist_ok=True)

import importlib.util                                            # noqa: E402

from lib import audit                                            # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "path_guard", os.path.join(ROOT, "hooks", "path_guard.py"))
pg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pg)

FAILS = []
_counter = [0]


def check(name, ok, detail=""):
    print("  [{:6}] {:54} {}".format("PASS" if ok else "FAIL", name[:54], detail[:60]))
    if not ok:
        FAILS.append(name)


def run(tool, tool_input):
    _counter[0] += 1
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool,
               "session_id": "pg-{}".format(_counter[0]), "cwd": WORKDIR,
               "tool_input": tool_input}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        pg.main()
    except SystemExit:
        pass
    finally:
        out = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    parsed = json.loads(out) if out else {}
    return (parsed.get("hookSpecificOutput") or {}).get("permissionDecision"), parsed


BLOCKED_BASH = [
    "cat ~/.ssh/id_ed25519",
    "cat ~/.ssh/id_rsa",
    "head -20 ~/.ssh/id_ecdsa",
    "strings ~/.ssh/id_rsa",
    "base64 ~/.ssh/id_ed25519",
    "cp ~/.ssh/id_rsa /tmp/k",
    "cat ~/.aws/credentials",
    "jq . ~/.docker/config.json",
    "cat ~/.kube/config",
    "cat /etc/ssl/private/server.pem",
    "cat ~/.netrc",
    "grep password ~/.pgpass",
    "cat ~/.claude/.credentials.json",
    "cat .env",
    "grep TOKEN .env.production",
    "tail -5 ../other/.env",
]

ALLOWED_BASH = [
    "cat README.md",
    "cat ~/.ssh/id_rsa.pub",
    "ls -la ~/.ssh",
    "cat .env.example",
    "cat .env.template",
    "ssh-add -l",
    "aws sts get-caller-identity",
    "kubectl config current-context",
    "openssl x509 -in cert.crt -noout -subject",
    "git config user.email",
    "grep -rn TODO src/",
    "docker ps",
]

print("=== A: чтение секретов через Bash ({} шт.) ===".format(len(BLOCKED_BASH)))
missed = []
for command in BLOCKED_BASH:
    decision, _ = run("Bash", {"command": command})
    if decision not in ("deny", "ask"):
        missed.append(command)
check("все заблокированы", not missed, str(missed[:3]))

print("=== B: легитимные команды ({} шт.) ===".format(len(ALLOWED_BASH)))
false_positives = []
for command in ALLOWED_BASH:
    decision, result = run("Bash", {"command": command})
    if decision is not None:
        false_positives.append("{} -> {}".format(command, decision))
for item in false_positives:
    print("      FP:", item)
check("ложных срабатываний нет", not false_positives)

print("=== C: файловые инструменты ===")
decision, _ = run("Read", {"file_path": os.path.expanduser("~/.ssh/id_rsa")})
check("Read приватного ключа заблокирован", decision == "deny", str(decision))
decision, _ = run("Read", {"file_path": "README.md"})
check("Read обычного файла разрешён", decision is None, str(decision))
decision, _ = run("Grep", {"pattern": "KEY", "glob": "**/*.pem"})
check("Grep по маске ключей заблокирован", decision in ("deny", "ask"), str(decision))
decision, _ = run("Glob", {"pattern": "**/.ssh/**"})
check("Glob по каталогу ключей заблокирован", decision in ("deny", "ask"),
      str(decision))

print("=== D: содержательность отказа ===")
_, result = run("Bash", {"command": "cat ~/.ssh/id_ed25519"})
reason = (result.get("hookSpecificOutput") or {}).get("permissionDecisionReason", "")
check("есть id правила", "path-ssh-key" in reason)
check("есть альтернатива", "ssh-agent" in reason)
check("назван запрошенный путь", "id_ed25519" in reason, reason[:70])

print("=== E: аудит ===")
records = [r for r in audit.iter_records() if r.get("hook") == "path_guard"]
check("записи есть", bool(records), str(len(records)))
check("указан класс", all(r.get("class") == "path-sensitive" for r in records))
check("указана цель", all(r.get("target") for r in records))

print("=== F: устойчивость ===")
HOOK = os.path.join(ROOT, "hooks", "path_guard.py")
for payload in ("", "{битый", json.dumps({"hook_event_name": "SessionStart"})):
    proc = subprocess.run([sys.executable, HOOK], input=payload,
                          capture_output=True, text=True, env=dict(os.environ))
    check("rc 0 на входе {!r}".format(payload[:12]), proc.returncode == 0,
          proc.stderr[:60])

print("=== G: утечка секрета и диалога (TS.md §16) ===")
SECRET = "AKIAABCDEFGHIJKLMNOP"
decision, result = run("Bash",
                       {"command": "cat ~/.ssh/id_ed25519 # token={}".format(SECRET)})
check("команда с секретом рядом всё ещё блокируется",
      decision in ("deny", "ask"), str(decision))
check("секрета нет в собственном ответе хука", SECRET not in json.dumps(result))
with open(audit.day_file(), "r", encoding="utf-8") as fh:
    raw_audit = fh.read()
check("секрета нет ни в одном байте журнала аудита", SECRET not in raw_audit)
check("в журнале нет полей содержимого диалога",
      not any(key in raw_audit for key in ("prompt_text", "\"messages\"", "transcript")))

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
