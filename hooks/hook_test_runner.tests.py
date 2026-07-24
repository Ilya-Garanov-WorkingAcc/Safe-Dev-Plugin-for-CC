#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея для hook_test_runner.py. Создаёт временные фикстуры-хуки и проверяет,
что мета-раннер правильно реагирует. Код выхода 0 = все прошли, 1 = провал."""
import json, os, subprocess, sys, tempfile, textwrap

RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook_test_runner.py")
FAILS = []

def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL':6}] {name:38} {detail}")
    if not ok: FAILS.append(name)

def call(payload):
    p = subprocess.run(["python3", RUNNER], input=json.dumps(payload),
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def write(path, body, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh: fh.write(textwrap.dedent(body))
    os.chmod(path, mode)

def post_write(fp):
    return {"hook_event_name":"PostToolUse","tool_name":"Write",
            "session_id":"t","tool_input":{"file_path":fp}}

def call_env(payload, env_overrides):
    env = dict(os.environ); env.update(env_overrides)
    p = subprocess.run(["python3", RUNNER], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    return p.returncode, p.stdout, p.stderr

def sysmsg(out):
    """emit_stdout() uses ensure_ascii=True, so emoji/Cyrillic in `out` are
    \\uXXXX-escaped, not literal — decode the JSON to check message content."""
    try:
        return json.loads(out).get("systemMessage", "") if out else ""
    except json.JSONDecodeError:
        return ""

with tempfile.TemporaryDirectory() as tmp:
    hooks = os.path.join(tmp, ".claude", "hooks")

    # Фикстура: проходящий хук + батарея (exit 0)
    write(os.path.join(hooks, "good.py"), "print('hook')\n")
    write(os.path.join(hooks, "good.tests.py"),
          "print('1/1 ok'); import sys; sys.exit(0)\n")
    rc, out, err = call(post_write(os.path.join(hooks, "good.py")))
    check("passing battery -> rc0", rc == 0 and "✅" in sysmsg(out), f"rc={rc}")

    # Фикстура: проваливающийся хук (exit 1) -> блокировка rc2 + stderr
    write(os.path.join(hooks, "bad.py"), "print('hook')\n")
    write(os.path.join(hooks, "bad.tests.py"),
          "print('boom'); import sys; sys.exit(1)\n")
    rc, out, err = call(post_write(os.path.join(hooks, "bad.py")))
    check("failing battery -> rc2 + stderr", rc == 2 and "❌" in err, f"rc={rc}")

    # Фикстура: хук без батареи -> напоминание, rc0
    write(os.path.join(hooks, "lonely.py"), "print('x')\n")
    rc, out, err = call(post_write(os.path.join(hooks, "lonely.py")))
    check("no battery -> nudge rc0", rc == 0 and "не найдена" in sysmsg(out), f"rc={rc}")

    # Правка самого тест-файла -> запускает его напрямую
    rc, out, err = call(post_write(os.path.join(hooks, "good.tests.py")))
    check("editing test file runs it", rc == 0 and "✅" in sysmsg(out), f"rc={rc}")

    # Не-хук файл (вне .claude/hooks) -> тихий no-op
    other = os.path.join(tmp, "src", "app.py"); write(other, "x=1\n")
    rc, out, err = call(post_write(other))
    check("non-hook file -> silent noop", rc == 0 and out == "" and err == "", f"rc={rc}")

    # tests/ поддиректория тоже находится
    write(os.path.join(hooks, "sub.py"), "print('x')\n")
    write(os.path.join(hooks, "tests", "sub.tests.py"),
          "import sys; sys.exit(0)\n")
    rc, out, err = call(post_write(os.path.join(hooks, "sub.py")))
    check("tests/ subdir discovered", rc == 0 and "✅" in sysmsg(out), f"rc={rc}")

# Non-UTF8 console encoding (regression: emoji/Cyrillic in stdout/stderr used
# to crash under a non-UTF8 default encoding, e.g. a Windows console on
# cp1251/cp1252/cp437; fail-open then swallowed the crash — the blocking
# decision and the "no battery" nudge both silently disappeared).
with tempfile.TemporaryDirectory() as tmp3:
    hooks3 = os.path.join(tmp3, ".claude", "hooks")
    write(os.path.join(hooks3, "encbad.py"), "print('hook')\n")
    write(os.path.join(hooks3, "encbad.tests.py"),
          "print('boom'); import sys; sys.exit(1)\n")
    write(os.path.join(hooks3, "enclonely.py"), "print('x')\n")

    for cp in ("cp1251", "cp1252", "cp437"):
        rc, out, err = call_env(post_write(os.path.join(hooks3, "encbad.py")),
                                 {"PYTHONIOENCODING": cp})
        check(f"failing battery survives {cp}", rc == 2 and "encbad.tests.py" in err,
              f"rc={rc} err={err[:60]!r}")

        rc, out, err = call_env(post_write(os.path.join(hooks3, "enclonely.py")),
                                 {"PYTHONIOENCODING": cp})
        check(f"no-battery nudge survives {cp}", rc == 0 and "не найдена" in sysmsg(out),
              f"rc={rc} out={out[:60]!r}")

# События/инструменты вне области -> no-op
rc, out, err = call({"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/x/.claude/hooks/a.py"}})
check("non-PostToolUse -> noop", rc == 0 and out == "", f"rc={rc}")
rc, out, err = call({"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}})
check("non-write tool -> noop", rc == 0 and out == "", f"rc={rc}")
rc, out, err = subprocess.run(["python3", RUNNER], input="", capture_output=True, text=True).returncode, "", ""
check("empty stdin -> rc0", rc == 0, f"rc={rc}")

print("\nSUMMARY:", "ALL PASSED" if not FAILS else f"FAILED {FAILS}")
sys.exit(1 if FAILS else 0)
