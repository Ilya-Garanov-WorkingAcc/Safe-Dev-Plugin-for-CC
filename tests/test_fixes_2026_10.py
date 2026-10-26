#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Регрессии по итогам проверки 26.10.2026 (docs/TEST-2026-10-26.md).

Пробелы контроля (G*) и ложные срабатывания (FP-*). Разрушительные команды —
данные для проверки решения хука, а не исполняются: каждая строка передаётся
хуку как JSON, целями служат пути во временном каталоге и тестовые имена.
"""

import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-fix-")
HOME = os.path.join(TMP, "home")
os.makedirs(os.path.join(HOME, ".claude", "plugins", "p"), exist_ok=True)
os.makedirs(os.path.join(HOME, ".ssh"), exist_ok=True)
WORK = os.path.join(TMP, "project")
os.makedirs(os.path.join(WORK, ".git", "hooks"), exist_ok=True)
os.environ["HOME"] = HOME
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")

import importlib.util                                           # noqa: E402

from lib import cmdparse                                        # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print("  [{:6}] {:58} {}".format("PASS" if ok else "FAIL", name[:58], str(detail)[:50]))
    if not ok:
        FAILS.append(name)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, "hooks", name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cg = _load("command_guard")
pg = _load("path_guard")
_n = [0]


def _run(mod, tool, tool_input, cwd):
    _n[0] += 1
    payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd,
               "session_id": "fix-{}".format(_n[0]), "tool_input": tool_input}
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = io.StringIO(json.dumps(payload)), io.StringIO()
    try:
        mod.main()
    except SystemExit:
        pass
    finally:
        text = sys.stdout.getvalue().strip()
        sys.stdin, sys.stdout = old_in, old_out
    out = json.loads(text) if text else {}
    return (out.get("hookSpecificOutput") or {}).get("permissionDecision")


def best(a, b):
    order = {None: 0, "warn": 1, "ask": 2, "deny": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def bash(command, cwd=WORK):
    return best(_run(cg, "Bash", {"command": command}, cwd),
                _run(pg, "Bash", {"command": command}, cwd))


def blocked(d):
    return d in ("deny", "ask")


PLUGINDIR = os.path.join(HOME, ".claude", "plugins", "p")
BASHRC = os.path.join(HOME, ".bashrc")
AUTH = os.path.join(HOME, ".ssh", "authorized_keys")
IDRSA = os.path.join(HOME, ".ssh", "id_rsa")
GITCFG = os.path.join(WORK, ".git", "config")

print("=== FP-3: перенаправления fd и чтения не считаются записью в файл ===")
# Дублирование дескрипторов и закрытие — не файлы.
for label, command in [
        ("2>&1 в защищённом каталоге", "echo x 2>&1"),
        (">&2", "echo err >&2"),
        ("1>&2", "echo err 1>&2"),
        ("2>&-", "echo x 2>&-"),
        ("3>&1", "echo x 3>&1")]:
    d = bash(command, cwd=PLUGINDIR)
    check("FP-3 fd-dup не блок: {}".format(label), not blocked(d), d)
# Чтение через stdin-редирект не является записью в файл-цель.
for label, command in [
        ("wc < .bashrc", "wc -l < " + BASHRC),
        ("python < .git/config", "python3 app.py < " + GITCFG),
        ("here-string", "grep foo <<< sometext")]:
    d = bash(command)
    check("FP-3 чтение-редирект не блок как запись: {}".format(label), not blocked(d), d)

print("=== FP-3 (контроль): запись-редирект в защищённый путь по-прежнему блок ===")
for label, command in [
        ("> .bashrc", "echo x > " + BASHRC),
        (">> authorized_keys", "echo k >> " + AUTH),
        ("&> .bashrc", "echo x &> " + BASHRC),
        ("> файл плагина", "echo x > " + os.path.join(PLUGINDIR, "policy.json"))]:
    d = bash(command)
    check("FP-3 запись-редирект блок: {}".format(label), blocked(d), d)
# Чтение секрета через stdin-редирект читателем — по-прежнему блок.
check("FP-3 base64 < id_rsa блок", blocked(bash("base64 < " + IDRSA)), bash("base64 < " + IDRSA))

PLUGINFILE = os.path.join(PLUGINDIR, "policy.json")

print("=== FP-2: чтение защищённого пути не считается записью ===")
# Утилиты, которые пишут только через редирект, не должны блокироваться при
# чтении операнда.
for label, command in [
        ("cat файла плагина",       "cat " + PLUGINFILE),
        ("jq по файлу плагина",     "jq . " + PLUGINFILE),
        ("python json.tool плагин", "python3 -m json.tool " + PLUGINFILE),
        ("cat .git/config",         "cat " + GITCFG),
        ("sed -n по .bashrc",       "sed -n 1,5p " + BASHRC),
        ("cp файла плагина (чтение источника)",
                                    "cp " + PLUGINFILE + " " + os.path.join(WORK, "copy.json"))]:
    d = bash(command)
    check("FP-2 чтение не блок: {}".format(label), not blocked(d), d)

print("=== FP-2 (контроль): запись в защищённый путь по-прежнему блок ===")
for label, command in [
        ("tee в файл плагина",      "echo x | tee " + PLUGINFILE),
        ("sed -i по файлу плагина", "sed -i s/a/b/ " + PLUGINFILE),
        ("cp в .bashrc (назначение)", "cp " + os.path.join(WORK, "src") + " " + BASHRC),
        ("mv в authorized_keys",    "mv " + os.path.join(WORK, "src") + " " + AUTH)]:
    d = bash(command)
    check("FP-2 запись блок: {}".format(label), blocked(d), d)
# Чтение настоящего секрета читателем по-прежнему блок.
check("FP-2 cat id_rsa блок", blocked(bash("cat " + IDRSA)), bash("cat " + IDRSA))

print("=== G1: разрушение ФС кодом интерпретатора (-c/-e, heredoc) ===")
TGT = os.path.join(WORK, "data")
DESTRUCTIVE = [
    ("py shutil.rmtree", 'python3 -c \'import shutil; shutil.rmtree("%s")\'' % TGT),
    ("py os.remove",     'python3 -c \'import os; os.remove("%s")\'' % TGT),
    ("py os.unlink",     'python3 -c \'import os; os.unlink("%s")\'' % TGT),
    ("py pathlib.unlink", 'python3 -c \'import pathlib; pathlib.Path("%s").unlink()\'' % TGT),
    ("py os.remove"+"dirs", 'python3 -c \'import os; os.remove'+'dirs("%s")\'' % TGT),
    ("perl unlink",      'perl -e \'unlink "%s"\'' % TGT),
    ("perl remove_tree", 'perl -e \'use File::Path; remove_tree("%s")\'' % TGT),
    ("node rmSync",      'node -e \'require("fs").rmSync("%s",{recursive:true})\'' % TGT),
    ("node unlinkSync",  'node -e \'require("fs").unlinkSync("%s")\'' % TGT),
    ("ruby rm_rf",       'ruby -e \'require "fileutils"; FileUtils.rm_rf("%s")\'' % TGT),
    ("ruby File.delete", 'ruby -e \'File.delete("%s")\'' % TGT),
    ("py heredoc",       'python3 <<EOF\nimport shutil\nshutil.rmtree("%s")\nEOF' % TGT),
]
for label, command in DESTRUCTIVE:
    d = bash(command)
    check("G1 блок: {}".format(label), blocked(d), d)

print("=== G1 (контроль): безвредный код интерпретатора не блокируется ===")
BENIGN = [
    ("py print",     'python3 -c \'print(1+1)\''),
    ("py json",      'python3 -c \'import json; print(json.dumps({"a":1}))\''),
    ("node log",     'node -e \'console.log(42)\''),
    ("py open read", 'python3 -c \'print(open("%s").read())\'' % os.path.join(WORK, "f.txt")),
]
for label, command in BENIGN:
    d = bash(command)
    check("G1 не блок (безвредно): {}".format(label), not blocked(d), d)
# Тело heredoc-данных (пример кода в документе) не считается исполнением.
doc = 'cat > %s <<EOF\nimport shutil; shutil.rmtree("/")\nEOF' % os.path.join(WORK, "readme.md")
check("G1 heredoc-данные не блок", not blocked(bash(doc)), bash(doc))

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
