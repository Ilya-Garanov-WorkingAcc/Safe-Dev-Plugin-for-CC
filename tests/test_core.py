#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Батарея ядра: hookio, config, policy, ruleset, redact, audit (TS.md §16).

Здесь проверяются инварианты, на которые опираются все модули. Если падает
что-то отсюда, отдельные хуки разбирать уже не имеет смысла.
"""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="secure-dev-core-")
os.environ["HOME"] = os.path.join(TMP, "home")
os.environ["CLAUDE_PLUGIN_DATA"] = os.path.join(TMP, "data")
os.makedirs(os.path.join(os.environ["HOME"], ".claude"), exist_ok=True)

from lib import audit, config, hookio, policy, redact, ruleset   # noqa: E402

FAILS = []
RULE_SETS = ("secrets", "commands", "paths", "injection", "config")


def check(name, ok, detail=""):
    print("  [{:6}] {:52} {}".format("PASS" if ok else "FAIL", name[:52], detail[:60]))
    if not ok:
        FAILS.append(name)


def set_local(payload):
    with open(config.LOCAL_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    config.reset_cache()


print("=== A: hookio — режимы отказа ===")


def _capture(fail_mode, event):
    @hookio.guard(fail_mode, "test")
    def boom():
        raise ValueError("искусственный сбой с секретом ghp_" + "a" * 36)

    hookio._LAST_EVENT = event
    old_out = sys.stdout
    sys.stdout = io.StringIO()
    code = None
    try:
        boom()
    except SystemExit as exc:
        code = exc.code
    finally:
        out = sys.stdout.getvalue()
        sys.stdout = old_out
    return code, out


code, out = _capture(hookio.FAIL_OPEN, "PostToolUse")
check("fail-open: exit 0 без вывода", code in (0, None) and not out.strip(),
      "{} {}".format(code, out[:40]))

code, out = _capture(hookio.FAIL_CLOSED, "PreToolUse")
parsed = json.loads(out) if out.strip() else {}
check("fail-closed: ask",
      (parsed.get("hookSpecificOutput") or {}).get("permissionDecision") == "ask",
      out[:60])
check("fail-closed: причина без деталей ошибки",
      "ValueError" not in out and "искусственный" not in out, out[:60])
check("fail-closed: секрет не утёк в вывод", "ghp_" not in out)

blob = ""
for path in audit.day_files():
    with open(path, "r", encoding="utf-8") as fh:
        blob += fh.read()
check("ошибка записана в аудит", "PARSER_ERROR" in blob)
check("секрет не утёк в аудит", "ghp_aaa" not in blob)

print("=== A2: hookio.data_dir() — CLI видит тот же каталог, что и хуки ===")
# secret-egress finding: /secure-dev:trust, :report, :policy выполняются как
# обычный Bash, а не как объявленный хук, поэтому CLAUDE_PLUGIN_DATA у них не
# задан. Без указателя CLI молча читал бы и писал ДРУГОЙ каталог, чем живые
# хуки — ровно это и наблюдал ручной прогон (аудит из report почти пуст).
_saved_data_env = os.environ.pop("CLAUDE_PLUGIN_DATA", None)
_fallback = hookio._fallback_data_dir()
shutil.rmtree(_fallback, ignore_errors=True)
try:
    check("без CLAUDE_PLUGIN_DATA и без хука — фолбэк",
          hookio.data_dir() == _fallback, hookio.data_dir())

    real_dir = os.path.join(TMP, "real-hook-data")
    os.environ["CLAUDE_PLUGIN_DATA"] = real_dir
    seen = hookio.data_dir()
    check("хук (переменная задана) видит реальный каталог", seen == real_dir, seen)
    pointer = os.path.join(_fallback, hookio._POINTER_NAME)
    check("хук оставил указатель в фолбэк-каталоге", os.path.isfile(pointer))

    del os.environ["CLAUDE_PLUGIN_DATA"]
    seen = hookio.data_dir()
    check("CLI без переменной подхватывает каталог хуков через указатель",
          seen == real_dir, seen)
finally:
    if _saved_data_env is not None:
        os.environ["CLAUDE_PLUGIN_DATA"] = _saved_data_env
    else:
        os.environ.pop("CLAUDE_PLUGIN_DATA", None)

print("=== B: config — только ужесточение ===")
set_local({"level": "strict"})
check("ужесточение принято", config.level() == "strict", config.level())

set_local({"level": "audit", "rule_levels": {"secret-egress": "audit"}})
check("смягчение глобального уровня отклонено", config.level() == "audit",
      config.level())
check("смягчение уровня правила отклонено",
      config.effective_level("secret-egress", "secret-egress") == "strict",
      config.effective_level("secret-egress", "secret-egress"))
check("записан LOCAL_OVERRIDE_REJECTED",
      "LOCAL_OVERRIDE_REJECTED" in [p[0] for p in config.problems()],
      str(config.problems())[:60])

set_local({"audit": {"export": {"type": "http", "url": "https://evil.example"}}})
check("правка экспорта отклонена",
      (config.audit_cfg().get("export") or {}).get("type") == "none",
      str(config.audit_cfg().get("export")))
check("отклонение записано",
      "LOCAL_OVERRIDE_REJECTED" in [p[0] for p in config.problems()])

set_local({"exemptions": [{"rule": "command-sudo", "reason": "хочу",
                           "expires": "2030-01-01", "approved_by": "я"}]})
check("собственное исключение не применяется",
      config.exemption_for("command-sudo", None) is None)

set_local({"неизвестный_ключ": 1})
check("неизвестный ключ помечен",
      "LOCAL_OVERRIDE_UNKNOWN" in [p[0] for p in config.problems()],
      str(config.problems())[:60])

set_local({"ui": {"banner": False, "verbosity": "quiet"}})
check("косметика разрешена", config.ui().get("banner") is False)

set_local({})
check("приоритет id над классом",
      config.effective_level("secret-egress", "path-sensitive") == "strict")
check("класс действует при отсутствии id",
      config.effective_level("новое-правило", "path-sensitive") == "warn")
check("иначе глобальный уровень",
      config.effective_level("новое-правило", "новый-класс") == "audit")

print("=== C: config — исключения и хеш политики ===")
check("исключение из политики применяется",
      config.exemption_for("command-rm-recursive-outside-cwd",
                           "/x/node_modules/pkg") is not None)
check("исключение не применяется к чужой цели",
      config.exemption_for("command-rm-recursive-outside-cwd", "/x/src") is None)
check("sha256 политики считается", len(config.policy_sha256() or "") == 64)
check("состояние печати определено",
      config.seal_status() in ("ok", "tampered", "unsealed"), config.seal_status())
check("валидация политики без ошибок", config.validate() == [],
      str(config.validate()))
check("исключение тестовых путей", config.is_excluded("src/tests/test_a.py"))
check("обычный путь не исключён", not config.is_excluded("src/app.py"))

# Регрессия: репозиторий, лежащий по пути с сегментом "test" ВЫШЕ своего
# корня (~/test/proj, /tmp/test-42/proj — обычное дело для CI и локальных
# песочниц), не должен ложно попадать под "**/test/**" целиком. Найдено
# боевым прогоном: injection_scanner ни разу не сработал на файле в
# .../projects/test/test-SafeDev/…, хотя сам scan() инъекцию находил.
check("абсолютный путь вне репозитория с 'test' в предках — не тестовая фикстура",
      not config.is_excluded(
          "/home/user/projects/test/my-app/readme.md", cwd="/home/user/projects/test/my-app"))
check("тестовая фикстура ВНУТРИ репозитория распознаётся и по абсолютному пути",
      config.is_excluded(
          "/home/user/projects/test/my-app/tests/fixture.py",
          cwd="/home/user/projects/test/my-app"))

print("=== D: policy — severity, память, решения ===")
check("CRITICAL в strict → deny",
      policy.decision_for("CRITICAL", "strict") == policy.DENY)
check("HIGH в strict → deny", policy.decision_for("HIGH", "strict") == policy.DENY)
check("MEDIUM в strict → ask", policy.decision_for("MEDIUM", "strict") == policy.ASK)
check("LOW в strict → warn", policy.decision_for("LOW", "strict") == policy.WARN)
check("в warn всё сводится к warn",
      policy.decision_for("CRITICAL", "warn") == policy.WARN)
check("в audit всё сводится к записи",
      policy.decision_for("CRITICAL", "audit") == policy.LOG)
check("CRITICAL нельзя подтвердить",
      policy.is_final("CRITICAL", policy.DENY)
      and not policy.is_final("HIGH", policy.DENY))

rule = {"id": "r-medium", "class": "тест", "severity": "MEDIUM",
        "message": "м", "remediation": "р", "reference": "ссылка"}
set_local({"level": "strict"})
first = policy.resolve(rule, target="a.py", agent_id=None, session_id="s1")
second = policy.resolve(rule, target="a.py", agent_id=None, session_id="s1")
check("первый ask не подавлен", not first["suppressed"])
check("повторный ask подавлен памятью", second["suppressed"])
third = policy.resolve(rule, target="a.py", agent_id="agent-9", session_id="s1")
check("память субагента отдельная", not third["suppressed"])

hard = dict(rule, id="r-critical", severity="CRITICAL")
one = policy.resolve(hard, target="a.py", session_id="s1")
two = policy.resolve(hard, target="a.py", session_id="s1")
check("deny не подавляется никогда",
      one["decision"] == two["decision"] == policy.DENY
      and not one["suppressed"] and not two["suppressed"])

reason = policy.format_reason(rule, "деталь")
for part in ("r-medium", "MEDIUM", "деталь", "Альтернатива", "/secure-dev:policy",
             "ссылка"):
    check("в отказе есть {}".format(part), part in reason)

set_local({})

print("=== E: ruleset — толерантный разбор ===")
check("наборы правил загружены",
      all(len(ruleset.load(name)) > 0 for name in RULE_SETS))
check("все правила имеют обучающие поля",
      all(all(rule.get(field) for field in ("message", "remediation", "reference"))
          for name in RULE_SETS for rule in ruleset.load(name)))
check("severity всегда из допустимых",
      all(rule["severity"] in ruleset.SEVERITIES
          for name in RULE_SETS for rule in ruleset.load(name)))
check("id уникальны в пределах набора",
      all(len({r["id"] for r in ruleset.load(name)}) == len(ruleset.load(name))
          for name in RULE_SETS))

ok, why = ruleset._validate({"id": "x", "class": "c", "severity": "HIGH",
                             "match": {"kind": "чужой"}, "message": "m",
                             "remediation": "r", "reference": "ref"})
check("неизвестный kind отбрасывается", not ok and why == "RULE_SCHEMA_UNKNOWN", why)
ok, why = ruleset._validate({"id": "x"})
check("неполное правило отбрасывается", not ok and why == "RULE_SCHEMA_INVALID", why)
check("отсутствующий файл правил не роняет загрузку",
      ruleset._load_raw("несуществующий-набор")[0] == [])

print("=== F: ruleset — глобы ===")
check("** пропускает каталоги", ruleset.glob_match("**/.ssh/**", "/home/u/.ssh/id"))
check("* не пересекает /", not ruleset.glob_match("*.py", "src/app.py"))
check("**/*.py находит вложенное", ruleset.glob_match("**/*.py", "src/lib/app.py"))
check("точное совпадение", ruleset.glob_match("/etc/wsl.conf", "/etc/wsl.conf"))
check("несовпадение", not ruleset.glob_match("**/.env", "src/.env.example"))

print("=== G: redact — маскирование ===")
secret = "ghp_" + "b" * 36
cleaned, findings = redact.redact("token={}".format(secret))
check("секрет заменён плейсхолдером",
      secret not in cleaned and "REDACTED" in cleaned, cleaned[:50])
check("тип определён", bool(findings) and findings[0][0] == "GITHUB_TOKEN",
      str(findings[:1]))
check("превью маскировано", secret not in findings[0][1], str(findings[0][1]))
check("mask короткой строки", redact.mask("abc") == "***")
check("вложенные структуры чистятся",
      "REDACTED" in json.dumps(redact.redact_any({"a": [{"b": secret}]})[0]))
check("чистый текст не меняется",
      redact.redact("обычный текст") == ("обычный текст", []))

print("=== H: audit — права, формат, инварианты ===")
audit.write({"hook": "test", "rule": "r", "action": "logged",
             "evidence": "AWS_SECRET_ACCESS_KEY=" + "c" * 40}, {})
day = audit.day_file()
mode = stat.S_IMODE(os.stat(day).st_mode)
check("права на журнал 0600", mode == 0o600, oct(mode))
with open(day, "r", encoding="utf-8") as fh:
    lines = [line for line in fh if line.strip()]
check("каждая строка — валидный JSON",
      all(json.loads(line) for line in lines), str(len(lines)))
last = json.loads(lines[-1])
check("evidence отредактирован", "REDACTED" in (last.get("evidence") or ""),
      str(last.get("evidence"))[:50])
check("есть обязательные поля",
      all(field in last for field in ("v", "kind", "ts", "user", "host", "cwd",
                                      "plugin_version", "action")))
check("ts в ISO-8601 с зоной",
      "T" in last["ts"] and ("+" in last["ts"] or "Z" in last["ts"]), last["ts"])
audit.write({"hook": "test", "evidence": "x" * 2000}, {})
records = list(audit.iter_records())
check("evidence усечён до 512", len(records[-1]["evidence"]) <= 512,
      str(len(records[-1]["evidence"])))
check("сбой записи не поднимает исключение",
      audit.write({"hook": "t"}, {"cwd": "/несуществующий"}) is None)

print("=== I: кодировки ===")
script = ("import sys; sys.path.insert(0, {!r});"
          "from lib import hookio;"
          "hookio.emit({{'systemMessage': 'кириллица и эмодзи \\U0001f680'}})"
          ).format(ROOT)
env = dict(os.environ)
env["LC_ALL"] = "C"
env["PYTHONIOENCODING"] = "cp1251"
proc = subprocess.run([sys.executable, "-c", script], capture_output=True,
                      text=True, env=env)
check("emit переживает LC_ALL=C и cp1251", proc.returncode == 0,
      (proc.stdout or proc.stderr)[:60])
try:
    ok = json.loads(proc.stdout)["systemMessage"].startswith("кириллица")
except Exception:                                                # noqa: BLE001
    ok = False
check("JSON корректно разбирается обратно", ok, proc.stdout[:60])

shutil.rmtree(TMP, ignore_errors=True)
print("\nSUMMARY:", "ALL PASSED" if not FAILS else "FAILED({}) {}".format(
    len(FAILS), FAILS))
sys.exit(1 if FAILS else 0)
