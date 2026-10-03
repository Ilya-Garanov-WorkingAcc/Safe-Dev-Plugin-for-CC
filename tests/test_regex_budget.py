#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Бюджет регулярных выражений: ни одно не должно зависать на враждебном вводе.

Хук, не уложившийся в таймаут Claude Code, действие НЕ блокирует. Поэтому
катастрофический бэктрекинг в любом правиле — это не «медленно», а обход:
атакующему достаточно дописать к команде или к выводу балласт нужной формы.
Аудит 03.10.2026 нашёл такие выражения в правилах секретов, инъекций, команд и
в самом парсере.

Проверяется каждое выражение из rules/*.json (в том числе вложенные списки
`args_regex_any`, `dest_regex_any`) и модульные выражения из lib/ на наборе
строк, подобранных под типовые формы квадратичности: длинное слово, повтор
префикса, повтор разделителя, пробельные серии через перевод строки.
"""

import glob
import json
import os
import re
import signal
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lib import cmdparse, injection                              # noqa: E402

LIMIT_S = 0.5            # на одно выражение и одну строку
SIZE = 200000

FAILS = []


def check(name, ok, detail=""):
    print("  [{:6}] {:52} {}".format("PASS" if ok else "FAIL", name[:52], detail[:90]))
    if not ok:
        FAILS.append(name)


def fill(unit):
    return (unit * (SIZE // len(unit) + 1))[:SIZE]


ADVERSARIAL = {
    "длинное слово": fill("a"),
    "слово с цифрами": fill("a1_"),
    "SECRET×N": fill("SECRET"),
    "TOKEN_×N": fill("TOKEN_"),
    "a.×N": fill("a."),
    "a-×N": fill("a-"),
    "eyJ-×N": fill("eyJ-"),
    "eyJa.×N": fill("eyJabcdef."),
    "ya29.×N": fill("ya29."),
    "BEGIN×N": fill("-----BEGIN PRIVATE KEY-----\n"),
    "BEGIN PGP×N": fill("-----BEGIN PGP PRIVATE KEY BLOCK-----\n"),
    "bearer×N": fill("bearer "),
    "http://a:×N": fill("http://a:"),
    "перевод+пробелы": fill("\n  "),
    "перевод+50 пробелов": fill("\n" + " " * 50),
    "пробелы": fill(" "),
    "табы и переводы": fill("\t\n"),
    "<!--×N": fill("<!--"),
    "<!-- ignore×N": fill("<!-- ignore "),
    "кавычки": fill("'\""),
    "скобки": fill("("),
    "f()×N": fill("f() "),
    "f(){×N": fill("f(){ "),
    "{×N": fill("{ "),
    "ignore×N": fill("ignore "),
    "send the×N": fill("send the "),
    "read ×N": fill("read x"),
    "do not tell×N": fill("do not tell "),
    "SYSTEM×N": fill("SYSTEM "),
    "history×N": fill("history "),
    "rm×N": fill("rm "),
    "=×N": fill("="),
    "password=×N": fill("password="),
    "\"key\": ×N": fill('"key": '),
    "base64": fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"),
    "-C ×N": fill("-C "),
    "--delete ×N": fill("--delete "),
    "a:b@×N": fill("a:b@"),
    "кириллица": fill("игнорируй "),
}


def collect():
    """(имя, скомпилированное выражение)."""
    out = []

    def walk(node, where):
        if isinstance(node, dict):
            flags = 0
            for letter in (node.get("flags") or "") if isinstance(node.get("flags"), str) else "":
                flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X}.get(letter, 0)
            for key, value in node.items():
                if key == "pattern" and isinstance(value, str):
                    out.append((where, re.compile(value, flags)))
                elif key.endswith("regex_any") and isinstance(value, list):
                    for i, pattern in enumerate(value):
                        out.append(("{}.{}[{}]".format(where, key, i), re.compile(pattern)))
                else:
                    walk(value, where)
        elif isinstance(node, list):
            for item in node:
                walk(item, where)

    for path in sorted(glob.glob(os.path.join(ROOT, "rules", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for rule in doc.get("rules", []):
            walk(rule, "{}:{}".format(os.path.basename(path), rule.get("id", "?")))

    for module in (cmdparse, injection):
        for name in dir(module):
            value = getattr(module, name)
            if isinstance(value, re.Pattern):
                out.append(("{}.{}".format(module.__name__, name), value))
    return out


print("=== A: каждое выражение на враждебном вводе ({} КБ) ===".format(SIZE // 1000))
patterns = collect()
check("выражения найдены", len(patterns) > 40, str(len(patterns)))
def slow_input(rx):
    """Метка строки, на которой выражение не уложилось в LIMIT_S, либо None.

    Выражение в бэктрекинге не прерывается из Python: поиск идёт в дочернем
    процессе, а таймер с обработчиком по умолчанию убивает его на уровне ОС.
    Перед каждой строкой ребёнок сообщает её метку — по последней и видно,
    на чём он погиб.
    """
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        for label, text in ADVERSARIAL.items():
            os.write(write_fd, (label + "\n").encode("utf-8"))
            signal.setitimer(signal.ITIMER_REAL, LIMIT_S)
            for _ in rx.finditer(text):
                pass
            signal.setitimer(signal.ITIMER_REAL, 0)
        os._exit(0)
    os.close(write_fd)
    seen = b""
    while True:
        block = os.read(read_fd, 4096)
        if not block:
            break
        seen += block
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return None
    return seen.decode("utf-8").strip().split("\n")[-1]


slow = []
for name, rx in patterns:
    label = slow_input(rx)
    if label is not None:
        slow.append("{} — дольше {} с на «{}»".format(name, LIMIT_S, label))
for item in slow:
    print("      SLOW:", item)
check("нет выражений медленнее {} с".format(LIMIT_S), not slow,
      "{} медленных".format(len(slow)))

print("=== B: разбор команды целиком ===")
for label, command in [
        ("слово 100 КБ", "echo " + "a" * 100000),
        ("30000 слов", "echo " + "a " * 30000),
        ("5000 команд", "true; " * 5000),
        ("3000 {", "{ " * 3000 + "x"),
        ("3000 $(", "echo " + "$(" * 3000 + "x" + ")" * 3000),
        ("heredoc 300 КБ", "cat > f <<'EOF'\n" + "| a | b |\n" * 30000 + "EOF"),
        ("f() ×10000", "f() " * 10000)]:
    t0 = time.monotonic()
    cmdparse.parse(command)
    took = time.monotonic() - t0
    check("parse: {}".format(label), took < 1.0, "{:.2f} с".format(took))

print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
