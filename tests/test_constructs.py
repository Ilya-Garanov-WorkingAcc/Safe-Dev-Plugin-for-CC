#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Конструкции шелла, которые не должны прятать команду (аудит 03.10.2026, фаза 1).

Корпус строится из ШАБЛОНОВ со слотом `{C}`. Разрушительные команды в файле
не встречаются вовсе:

  • на уровне парсера подставляется безвредный маркер и проверяется, что он
    виден как отдельная команда дерева;
  • на уровне хука подставляется `sudo true` — правило command-sudo блокирует
    его на любом уровне политики, а сама команда ничего не меняет;
  • дифференциальная проверка подставляет `touch MARK` во временном каталоге:
    если его создал настоящий bash, хук обязан был маркер увидеть.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-constructs-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)
WORKDIR = os.path.join(TMP, "project")
os.makedirs(WORKDIR, exist_ok=True)

import importlib.util                                           # noqa: E402

from lib import cmdparse as cp                                  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "command_guard", os.path.join(ROOT, "hooks", "command_guard.py"))
cg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cg)

FAILS = []
MARK = "sd_marker_cmd"              # безвредное имя, которого нет в $PATH
BLOCKED = "sudo true"              # command-sudo → deny на любом уровне


def check(name, ok, detail=""):
    print("  [{:6}] {:56} {}".format("PASS" if ok else "FAIL", name[:56],
                                      str(detail)[:60]))
    if not ok:
        FAILS.append(name)


def decision(command, cwd=None):
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "session_id": "constructs", "cwd": cwd or WORKDIR,
               "tool_input": {"command": command}}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        cg.main()
    except SystemExit:
        pass
    finally:
        text = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    out = json.loads(text) if text else {}
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


def argv0s(command):
    cmds, _ = cp.parse(command)
    allc = cmds + cp.heredoc_script_commands(cp.heredoc_scripts(cmds))
    return [c.argv0 for c in allc]


def sees_marker(command):
    return MARK in argv0s(command)


def blocked(d):
    return d in ("deny", "ask")


# Шаблоны: способ выполнить команду так, что до 2.2 парсер её не видел.
# `{C}` — слот под команду.
TEMPLATES = [
    ("группа",                 "{{ {C}; }}"),
    ("группа после &&",        "true && {{ {C}; }}"),
    ("отрицание",              "! {C}"),
    ("if",                     "if {C}; then :; fi"),
    ("while",                  "while {C}; do break; done"),
    ("until",                  "until {C}; do break; done"),
    ("coproc + группа",        "coproc {{ {C}; }}"),
    ("вложенная группа в f()", "f() {{ {{ {C}; }}; }}; f"),
    ("function с группой",     "function g {{ {C}; }}; g"),
    ("подстановка в ${{:-}}",  "echo ${{v:-$({C})}}"),
    ("подстановка в ${{:=}}",  "echo ${{v:=$({C})}}"),
    ("${{}} в двойных кавычках", 'echo "${{v:-$({C})}}"'),
    ("замена в ${{//}}",       "echo ${{v//a/$({C})}}"),
    ("индекс массива",         "echo ${{a[$({C})]}}"),
    ("цель редиректа $()",     "echo hi > $({C})"),
    ("цель редиректа слитно",  "echo hi >$({C})"),
    ("stdin из $()",           "cat < $({C})"),
    ("bash -c -- ",            "bash -c -- '{C}'"),
    ("bash -x -c",             "bash -x -c '{C}'"),
    ("bash -o pipefail -c",    "bash -o pipefail -c '{C}'"),
    ("here-string в bash",     "bash <<< '{C}'"),
    ("here-string в sh",       "sh <<< '{C}'"),
    ("exec bash <<<",          "exec bash <<< '{C}'"),
    ("process subst в bash",   "bash <(echo '{C}')"),
    ("env -S",                 "env -S '{C}'"),
    ("env --split-string=",    "env --split-string='{C}'"),
    ("time -p",                "time -p {C}"),
    ("flock",                  "flock /tmp/l {C}"),
    ("flock -c",               "flock /tmp/l -c '{C}'"),
    ("watch",                  "watch {C}"),
    ("strace -f",              "strace -f {C}"),
    ("stdbuf",                 "stdbuf -oL {C}"),
    ("eval в группе",          "{{ eval '{C}'; }}"),
    ("ssh localhost строкой",  "ssh localhost '{C}'"),
    ("alias на bash",          "alias c=bash; c <<< '{C}'"),
    ("комментарий + продолжение", "echo hi # x\\\n{C}"),
]

print("=== A: парсер видит команду во всех обёртках ({} шт.) ===".format(len(TEMPLATES)))
# Процесс-подстановка `bash <(echo '…')` исполняет ВЫВОД echo как скрипт:
# статически известен только `echo <маркер>`, сам маркер — аргумент echo.
# Корректный исход здесь — эскалирующее предупреждение, а не видимый argv0.
ESCALATES_OK = {"process subst в bash"}
blind = []
for label, tpl in TEMPLATES:
    command = tpl.format(C=MARK)
    _cmds, warns = cp.parse(command)
    escalates = any(w in cg.ESCALATING_WARNINGS or w.startswith("parse_error")
                    for w in warns)
    if not sees_marker(command) and not (label in ESCALATES_OK and escalates):
        blind.append(label)
check("маркер виден во всех шаблонах", not blind, blind)

print("=== B: хук блокирует опасную команду в тех же обёртках ===")
missed = []
for label, tpl in TEMPLATES:
    if not blocked(decision(tpl.format(C=BLOCKED))):
        missed.append(label)
check("sudo виден и заблокирован во всех обёртках", not missed, missed)

print("=== C: динамическое имя команды → ask ===")
# Имя собирается шеллом: переменной, подстановкой, глобом, фигурными скобками.
for label, command in [
        ("переменная в середине", "r${{x}}m -rf dir".format()),
        ("переменная-аргумент",   "cmd$x -rf dir"),
        ("$() как имя",           "$(echo rm) -rf dir"),
        ("глоб в пути",           "/usr/bin/r?m -rf dir"),
        ("класс символов",        "/usr/bin/r[m] -rf dir"),
        ("brace-список",          "{{rm,-rf,dir}}".format()),
        ("$IFS между словами",    "printf${{IFS}}done"),
        ("$@ как команда",        'set -- true; "$@"')]:
    check("динамическое имя: {} → ask".format(label),
          decision(command) == "ask", decision(command))

print("=== D: переменная в цели rm считается динамической (инцидент 18.09) ===")
for label, command in [
        ("пустая переменная",   'rm -rf "$X/"'),
        ("переменная без слэша", "rm -rf $DIR"),
        ("${{}} форма",         "rm -rf ${{OUT}}")]:
    check("rm по переменной: {} → не тихо".format(label),
          blocked(decision(command)), decision(command))
check("rm по известной из строки переменной внутри проекта — тихо",
      not blocked(decision("D=build; rm -rf $D")), decision("D=build; rm -rf $D"))
check("rm в каталог из mktemp — тихо",
      not blocked(decision("D=$(mktemp -d); rm -rf $D")),
      decision("D=$(mktemp -d); rm -rf $D"))

print("=== E: редирект в любой форме виден правилам персистентности ===")
rc = os.path.join(os.environ["HOME"], ".bashrc")
for label, command in [
        ("слитно >>",          "echo x>>" + rc),
        ("слитно >",           "echo x>" + rc),
        ("в кавычках",         'echo x >"{}"'.format(rc)),
        ("дозапись в кавычках", "echo x >>'{}'".format(rc)),
        ("группа",             "(echo x) >> " + rc)]:
    check("запись в .bashrc: {} → блок (P8)".format(label),
          blocked(decision(command)), decision(command))

print("=== F: cd внутри строки меняет рабочий каталог ===")
check("cd / && rm -rf * → корневая цель",
      decision("cd / && rm -rf *") == "deny", decision("cd / && rm -rf *"))
check("cd в подкаталог проекта — безопасно",
      not blocked(decision("cd build && rm -rf tmp")),
      decision("cd build && rm -rf tmp"))
check("cd в неизвестный каталог → рекурсивный rm не тихий",
      blocked(decision('cd "$HOME/$X" && rm -rf out')),
      decision('cd "$HOME/$X" && rm -rf out'))

print("=== F2: уборка артефактов сборки не блокируется (тест 3.0.0) ===")
# `cd <рабочий каталог> && rm -rf build` ложно блокировалось как «вне cwd»,
# потому что «вне» мерилось от каталога сессии, а не от каталога после cd.
other = os.path.join(TMP, "elsewhere")
os.makedirs(os.path.join(other, "build"), exist_ok=True)
for label, command, cwd in [
        ("rm -rf build в cwd",        "rm -rf build", WORKDIR),
        ("rm -rf ./dist в cwd",       "rm -rf ./dist", WORKDIR),
        ("rm -r t1 в cwd",            "rm -r t1", WORKDIR),
        ("cd другой каталог && rm -rf build", "cd {} && rm -rf build".format(other), WORKDIR),
        ("cd каталог && rm -rf node_modules", "cd {} && rm -rf node_modules".format(other), WORKDIR)]:
    check("уборка: {} — тихо".format(label),
          not blocked(decision(command, cwd=cwd)), decision(command, cwd=cwd))
# но удаление вне рабочего каталога без cd остаётся под контролем
check("rm -rf абсолютного пути вне cwd (без cd) → блок",
      blocked(decision("rm -rf {}/build".format(other), cwd=WORKDIR)),
      decision("rm -rf {}/build".format(other), cwd=WORKDIR))

print("=== G: рабочий каталог — дом или корень ===")
home = os.environ["HOME"]
check("rm -rf подкаталога дома из ~ → ask",
      blocked(decision("rm -rf projects", cwd=home)),
      decision("rm -rf projects", cwd=home))
check("rm -rf в проекте под ~ — тихо",
      not blocked(decision("rm -rf build", cwd=WORKDIR)),
      decision("rm -rf build", cwd=WORKDIR))

print("=== H: xargs без -I дописывает цель из потока ===")
check("ls | xargs sudo виден",
      blocked(decision("ls | xargs sudo true")),
      decision("ls | xargs sudo true"))

print("=== I: дифференциальная сверка с настоящим bash ===")
# Единственная «команда» — touch MARK во временном каталоге. Если bash его
# создал (тело исполнилось), хук обязан был команду увидеть либо выдать
# эскалирующее предупреждение.
DIFF_TEMPLATES = [t for _, t in TEMPLATES
                  if "ssh" not in t and "watch" not in t and "strace" not in t
                  and "flock" not in t and "process subst" not in t
                  and "<(" not in t]
bad = []
for tpl in DIFF_TEMPLATES:
    work = tempfile.mkdtemp(dir=TMP)
    command = tpl.format(C="touch MARK")
    try:
        subprocess.run(["bash", "-c", command], cwd=work, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       stdin=subprocess.DEVNULL,
                       env={"HOME": home, "PATH": os.environ["PATH"]})
    except subprocess.TimeoutExpired:
        pass
    time.sleep(0.02)
    executed = os.path.exists(os.path.join(work, "MARK"))
    cmds, warns = cp.parse(command)
    allc = cmds + cp.heredoc_script_commands(cp.heredoc_scripts(cmds))
    seen = any(c.argv0 == "touch" for c in allc)
    esc = [w for w in warns if w in cg.ESCALATING_WARNINGS or w.startswith("parse_error")]
    if executed and not (seen or esc):
        bad.append(command)
check("каждая исполнившаяся в bash команда видна хуку", not bad, bad[:2])

print("=== J: бюджет не нарушен ===")
sample = "git status && npm run build | tee /tmp/log ; docker compose up -d"
t0 = time.monotonic()
for _ in range(200):
    cp.parse(sample)
per_call_ms = (time.monotonic() - t0) / 200 * 1000
check("разбор типичной команды < 5 мс", per_call_ms < 5.0,
      "{:.2f} мс".format(per_call_ms))

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
