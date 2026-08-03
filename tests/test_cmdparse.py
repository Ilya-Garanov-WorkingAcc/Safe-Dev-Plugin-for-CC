#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея lib/cmdparse.py — таблица TS.md §7.2 плюс property-тест.

Property-тест здесь не украшение: контракт парсера — «не падать никогда», и
проверить его можно только обстрелом случайными строками. Падение на входе
означает обход, потому что fail-closed-ветка полагается на предупреждения, а
не на исключения.
"""

import os
import random
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import cmdparse as cp                                  # noqa: E402
from tests import bypass_corpus                                 # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print("  [{:6}] {:44} {}".format("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAILS.append(name)


def argv0s(command):
    cmds, _ = cp.parse(command)
    return [c.argv0 for c in cmds]


def find(command, argv0):
    cmds, _ = cp.parse(command)
    return [c for c in cmds if c.argv0 == argv0]


print("=== A: раскрытие конструкций (TS.md §7.2) ===")

cmds, _ = cp.parse("a && b ; c || d")
check("списки дают 4 команды", len(cmds) == 4, str([c.argv0 for c in cmds]))

cmds, _ = cp.parse("echo x | sh")
sh = [c for c in cmds if c.argv0 == "sh"]
check("пайп: sh с origin=pipe", bool(sh) and sh[0].origin == cp.PIPE)

cmds, _ = cp.parse("echo $(rm -rf /)")
rm = [c for c in cmds if c.argv0 == "rm"]
check("подстановка: rm depth=1 origin=subshell",
      bool(rm) and rm[0].depth == 1 and rm[0].origin == cp.SUBSHELL)

check("обратные кавычки раскрыты", bool(find("echo `rm -rf /`", "rm")))

cmds, _ = cp.parse("FOO=1 git push")
check("env-префикс отброшен, argv0=git",
      len(cmds) == 1 and cmds[0].argv0 == "git" and cmds[0].assignments == ("FOO=1",))

check("bash -c разобран рекурсивно", bool(find("bash -c 'rm -rf /'", "rm")))
check("sh -c разобран рекурсивно", bool(find("sh -c \"rm -rf /\"", "rm")))

cmds, warns = cp.parse("python3 -c \"import os;os.system('rm -rf /')\"")
check("интерпретатор: предупреждение", "interpreter_exec" in warns, str(warns))
check("интерпретатор: origin=interpreter",
      any(c.origin == cp.INTERPRETER for c in cmds))
check("интерпретатор: литерал разобран",
      any(c.argv0 == "rm" for c in cmds), str([c.argv0 for c in cmds]))

cmds, _ = cp.parse("echo cm0gLXJmIC8= | base64 -d | sh")
b64 = [c for c in cmds if c.argv0 == "base64"]
shell = [c for c in cmds if c.argv0 == "sh"]
check("пайплайн: base64 знает про sh ниже по потоку",
      bool(b64) and "sh" in b64[0].downstream)
check("пайплайн: sh знает про base64 выше по потоку",
      bool(shell) and "base64" in shell[0].upstream)
check("base64 -d канонизирован",
      bool(b64) and "--decode" in b64[0].flags,
      str(sorted(b64[0].flags)) if b64 else "нет base64")

grouped = find("rm -rf /", "rm")[0]
longform = find("rm --recursive --force /", "rm")[0]
check("сгруппированные флаги = длинные", grouped.flags == longform.flags,
      "{} vs {}".format(sorted(grouped.flags), sorted(longform.flags)))

cmds, _ = cp.parse("git checkout -- src/")
git = cmds[0]
check("`--` остаётся в args, не во flags",
      "--" in git.args and "--" not in git.flags)
check("операнд после `--` распознан", "src/" in git.operands, str(git.operands))

quoted = find('rm -rf "/my dir"', "rm")[0]
check("кавычки: операнд с пробелом", quoted.operands == ("/my dir",),
      str(quoted.operands))

cmds, warns = cp.parse("$CMD -rf /")
check("переменная в argv0 → предупреждение", "argv0_is_variable" in warns, str(warns))

cmds, _ = cp.parse("$(which sudo) apt install curl")
check("$(which sudo) резолвится в sudo",
      any(c.argv0 == "sudo" for c in cmds), str([c.argv0 for c in cmds]))

check("экранированное имя нормализовано", argv0s("\\rm -rf /")[0] == "rm")
check("абсолютный путь нормализован", argv0s("/usr/bin/rm -rf /")[0] == "rm")
check("склейка кавычек нормализована", argv0s("r''m -rf /")[0] == "rm")

cmds, _ = cp.parse("env sudo rm -rf /")
names = [c.argv0 for c in cmds]
check("env раскрыт, sudo сохранён", "sudo" in names and "rm" in names, str(names))

cmds, _ = cp.parse("timeout 5 rm -rf /")
check("timeout раскрыт с числовым аргументом",
      "rm" in [c.argv0 for c in cmds], str([c.argv0 for c in cmds]))

cmds, _ = cp.parse("echo hi > /tmp/out.txt")
check("цель перенаправления не операнд",
      cmds[0].operands == ("hi",) and cmds[0].redirects == ("/tmp/out.txt",),
      "{} {}".format(cmds[0].operands, cmds[0].redirects))

cmds, _ = cp.parse("git commit -m 'fix /tmp/thing'")
check("значение -m не считается операндом",
      "fix /tmp/thing" not in cmds[0].operands, str(cmds[0].operands))

cmds, _ = cp.parse("rm -rf $(echo /)")
rm = [c for c in cmds if c.argv0 == "rm"][0]
check("динамический операнд помечен", any("$()" in op for op in rm.operands),
      str(rm.operands))

print("=== B: устойчивость ===")
for broken in ("", "   ", "'", '"', "$(", "`", "|", "&&", "rm -rf 'unclosed",
               "$(( ))", "a" * 5000, "\x00\x01", ";;;;", "()()()",
               ":(){ :|:& };:", "echo \\", "${", "$(bash -c '$(bash -c ls)')"):
    try:
        cp.parse(broken)
        ok = True
    except Exception as exc:                                    # noqa: BLE001
        ok = False
        print("      exception:", type(exc).__name__, repr(broken[:40]))
    check("не падает на {!r}".format(broken[:24]), ok)

print("=== C: property — 10 000 случайных строк ===")
random.seed(20260727)
alphabet = list(string.printable[:95]) + ["$(", "`", "&&", "||", "|", ";", "\\",
                                          "'", '"', ">>", "<<", "${", "}"]
crashed = []
t0 = time.time()
for _ in range(10000):
    text = "".join(random.choice(alphabet) for _ in range(random.randint(1, 60)))
    try:
        cp.parse(text)
    except Exception as exc:                                    # noqa: BLE001
        crashed.append((type(exc).__name__, text))
elapsed = time.time() - t0
check("10 000 случайных строк без исключений", not crashed,
      "{} падений, {:.1f}s".format(len(crashed), elapsed))
if crashed:
    for kind, text in crashed[:5]:
        print("      ", kind, repr(text))

print("=== D: корпус обходов виден парсеру ===")
missed = []
for label, command in bypass_corpus.RM_ROOT:
    cmds, warns = cp.parse(command)
    seen_rm = any(c.argv0 in ("rm", "unknown") for c in cmds)
    if not (seen_rm or warns):
        missed.append((label, command))
check("rm-корпус: каждая строка даёт rm либо предупреждение", not missed,
      str(missed[:3]))

missed = []
for label, command in bypass_corpus.SUDO:
    cmds, warns = cp.parse(command)
    if not (any(c.argv0 in ("sudo", "doas", "pkexec") for c in cmds) or warns):
        missed.append((label, command))
check("sudo-корпус: каждая строка даёт sudo либо предупреждение", not missed,
      str(missed[:3]))

print("=== D2: обходы прожарки AGGG — eval/source/trap/alias/function/... ===")

DANGEROUS_ARGV0 = {"rm", "sudo", "doas", "pkexec", "at", "crontab", "sh", "bash",
                   "unknown"}
missed = []
for label, command in bypass_corpus.PARSER_GAPS:
    cmds, warns = cp.parse(command)
    seen = any(c.argv0 in DANGEROUS_ARGV0 for c in cmds)
    if not (seen or warns):
        missed.append((label, command))
check("корпус прожарки: каждая строка даёт опасный argv0 либо предупреждение",
      not missed, str(missed))

check("eval раскрыт", bool(find("eval 'rm -rf /'", "rm")))
check("source из here-string раскрыт",
      bool(find(". /dev/stdin <<< 'rm -rf /'", "rm")))
check("trap раскрыт", bool(find('bash -c \'trap "rm -rf /" EXIT\'', "rm")))
check("alias раскрыт", bool(find("bash -c 'alias r=\"rm -rf\"; r /'", "rm")))
check("function раскрыт", bool(find("bash -c 'f(){ rm -rf /; }; f'", "rm")))

cmds, _ = cp.parse("rm -rf $'\\x2f'")
rm = find("rm -rf $'\\x2f'", "rm")
check("ANSI-C decoded в root-таргет",
      bool(rm) and rm[0].operands == ("/",), str(rm[0].operands) if rm else "нет rm")

cmds, _ = cp.parse("rm -rf <(echo /)")
rm = find("rm -rf <(echo /)", "rm")
check("process substitution помечен динамическим",
      bool(rm) and any("$()" in op for op in rm[0].operands),
      str(rm[0].operands) if rm else "нет rm")

cmds, _ = cp.parse("echo / | xargs -I{} rm -rf {}")
rm = [c for c in cmds if c.argv0 == "rm"]
check("xargs -I{} помечен динамическим",
      bool(rm) and any("$()" in op for op in rm[0].operands),
      str(rm[0].operands) if rm else "нет rm")

check("exec -a раскрывает цель, а не значение флага",
      bool(find("exec -a safe rm -rf /", "rm")))

check("find -exec раскрыт", bool(find("find / -exec rm -rf {} \\;", "rm")))

cmds, warns = cp.parse("echo 'rm -rf /' | xargs -d '\\n' sh -c")
check("xargs -d + sh -c без кода → предупреждение",
      "shell_c_unresolved" in warns, str(warns))

print("=== E: бюджет (TS.md §1.3) ===")
sample = "git status && npm run build | tee /tmp/log ; docker compose up -d"
t0 = time.time()
for _ in range(200):
    cp.parse(sample)
per_call_ms = (time.time() - t0) / 200 * 1000
check("разбор типичной команды < 5 мс", per_call_ms < 5.0,
      "{:.2f} мс".format(per_call_ms))

print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
