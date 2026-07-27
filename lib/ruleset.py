#!/usr/bin/env python3
"""ruleset.py — загрузка и применение rules/*.json (TS.md §5, ADR-005).

Правила живут в данных, а не в коде: обновление набора правил не требует
изменения Python и, значит, полного цикла ревью security-критичной логики.

Разбор толерантный: неизвестный `kind` или битое правило отбрасываются с
записью в аудит, остальные продолжают работать. Один битый файл правил не
должен отключать весь плагин.

Модуль отвечает за «что за конструкция», но НЕ за «что с ней делать»:
решение принимает policy.py, разбор команды — cmdparse.py.
"""

import fnmatch
import json
import os
import re

from lib import hookio

KINDS = {"command", "regex", "path", "entropy", "config_key"}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
_REQUIRED = ("id", "class", "severity", "match", "message", "remediation", "reference")

_CACHE = {}
_GLOB_CACHE = {}


# --- Загрузка --------------------------------------------------------------

def path_for(name):
    return os.path.join(hookio.plugin_root(), "rules", name + ".json")


def load(name):
    """Вернуть список валидных правил из rules/<name>.json.

    Результат кешируется на время жизни процесса: хук живёт миллисекунды,
    перечитывать файл незачем.
    """
    if name in _CACHE:
        return _CACHE[name]
    rules, problems = _load_raw(name)
    _CACHE[name] = rules
    for rule_id, why in problems:
        _report(name, rule_id, why)
    return rules


def _load_raw(name):
    problems = []
    try:
        with open(path_for(name), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return [], [("-", "RULES_FILE_MISSING")]
    except Exception:
        return [], [("-", "RULES_FILE_INVALID")]

    raw = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        return [], [("-", "RULES_FILE_INVALID")]

    out = []
    for item in raw:
        ok, why = _validate(item)
        if not ok:
            problems.append((_safe_id(item), why))
            continue
        prepared = _prepare(item)
        if prepared is None:
            problems.append((_safe_id(item), "RULE_REGEX_INVALID"))
            continue
        out.append(prepared)
    return out, problems


def _safe_id(item):
    return item.get("id", "-") if isinstance(item, dict) else "-"


def _validate(item):
    if not isinstance(item, dict):
        return False, "RULE_SCHEMA_INVALID"
    for field in _REQUIRED:
        if field not in item:
            return False, "RULE_SCHEMA_INVALID"
    if item["severity"] not in SEVERITIES:
        return False, "RULE_SCHEMA_INVALID"
    match = item.get("match")
    if not isinstance(match, dict) or "kind" not in match:
        return False, "RULE_SCHEMA_INVALID"
    if match["kind"] not in KINDS:
        return False, "RULE_SCHEMA_UNKNOWN"
    if item.get("enabled") is False:
        return False, "RULE_DISABLED"
    return True, ""


def _prepare(item):
    """Скомпилировать регулярки один раз при загрузке."""
    rule = dict(item)
    match = dict(rule["match"])
    if match["kind"] == "regex":
        flags = 0
        for letter in (match.get("flags") or ""):
            flags |= {"i": re.IGNORECASE, "m": re.MULTILINE,
                      "s": re.DOTALL, "x": re.VERBOSE}.get(letter, 0)
        try:
            match["_rx"] = re.compile(match["pattern"], flags)
        except re.error:
            return None
    rule["match"] = match
    return rule


def _report(name, rule_id, why):
    """Проблема набора правил — событие аудита, а не исключение."""
    if why == "RULE_DISABLED":
        return
    try:
        from lib import audit
        audit.write({
            "kind": "event", "hook": "ruleset", "rule": why,
            "class": "internal", "severity": "LOW", "action": "logged",
            "target": name, "evidence": "rule_id={}".format(rule_id),
        }, {})
    except Exception:
        pass


def loaded_count():
    """Число загруженных правил всех наборов — идёт в heartbeat."""
    total = 0
    for name in ("secrets", "commands", "paths", "injection", "config"):
        try:
            total += len(load(name))
        except Exception:
            pass
    return total


# --- Глобы -----------------------------------------------------------------

def glob_re(pattern):
    """Компиляция glob c поддержкой `**`.

    fnmatch не различает `*` и `**`, поэтому `**/tests/**` у него совпал бы с
    чем угодно посередине пути. Для исключений (policy.exclusions) и для
    target_glob это критично.
    """
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    i, out = 0, ["^"]
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                out.append(pattern[i:j + 1])
                i = j + 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    rx = re.compile("".join(out))
    _GLOB_CACHE[pattern] = rx
    return rx


def glob_match(pattern, value):
    if glob_re(pattern).match(value):
        return True
    # `**/x` должен ловить и путь без ведущих каталогов, и абсолютный путь.
    return glob_re(pattern).match(value.lstrip("/")) is not None


def any_glob(patterns, value):
    return any(glob_match(p, value) for p in (patterns or []))


# --- Матчеры ---------------------------------------------------------------

def match_command(cmd, rule, ctx=None):
    """kind: "command" — семантическое совпадение с разобранной командой.

    Работает по структуре Cmd из cmdparse, а не по тексту: `rm -rf /`,
    `rm --recursive --force /` и `bash -c 'rm -fr /'` дают одно совпадение.
    """
    ctx = ctx or {}
    m = rule["match"]
    if m["kind"] != "command":
        return False

    argv0 = m.get("argv0")
    if argv0 and not any(fnmatch.fnmatchcase(cmd.argv0, p) for p in argv0):
        return False
    argv0_not = m.get("argv0_not")
    if argv0_not and any(fnmatch.fnmatchcase(cmd.argv0, p) for p in argv0_not):
        return False

    args = tuple(cmd.args)
    if not all(a in args for a in m.get("args_contain_all", [])):
        return False
    any_args = m.get("args_contain_any")
    if any_args and not any(a in args for a in any_args):
        return False
    none_args = m.get("args_not_contain_any")
    if none_args and any(a in args for a in none_args):
        return False

    if not all(f in cmd.flags for f in m.get("flags_all", [])):
        return False
    any_flags = m.get("flags_any")
    if any_flags and not any(f in cmd.flags for f in any_flags):
        return False
    none_flags = m.get("flags_not_any")
    if none_flags and any(f in cmd.flags for f in none_flags):
        return False

    rx_any = m.get("args_regex_any")
    if rx_any:
        joined = " ".join(args)
        if not any(re.search(p, joined) for p in rx_any):
            return False

    origins = m.get("origin")
    if origins and cmd.origin not in origins:
        return False

    piped_to = m.get("piped_to_any")
    if piped_to and not any(fnmatch.fnmatchcase(d, p)
                            for d in cmd.downstream for p in piped_to):
        return False
    piped_from = m.get("piped_from_any")
    if piped_from and not any(fnmatch.fnmatchcase(u, p)
                              for u in cmd.upstream for p in piped_from):
        return False

    tg = m.get("target_glob")
    if tg:
        # Сверяем и как написано, и как разрешилось: `~/.bashrc` и
        # `/home/user/.bashrc` — один файл, а `../../etc` виден только после
        # раскрытия.
        targets = list(cmd.operands) + list(ctx.get("expanded_operands") or ())
        if not any(any_glob(tg, t) for t in targets):
            return False

    rg = m.get("redirect_glob")
    if rg:
        # `echo evil >> ~/.bashrc` — цель не операнд, а перенаправление;
        # без этой ветки персистентный RCE через shell-конфиг не виден.
        targets = list(cmd.redirects) + list(ctx.get("expanded_redirects") or ())
        if not any(any_glob(rg, t) for t in targets):
            return False

    if m.get("branch_protected") and not ctx.get("branch_protected"):
        return False
    if m.get("branch_unprotected") and ctx.get("branch_protected", True):
        return False

    if m.get("target_outside_cwd"):
        if not ctx.get("has_operand_outside_cwd"):
            return False
    if m.get("target_root"):
        # Корень, домашний каталог и выход вверх по дереву резолвит вызывающий:
        # ему доступны cwd и realpath, парсеру — нет.
        if not ctx.get("has_root_target"):
            return False
    if m.get("target_dynamic"):
        if not any("$()" in t for t in cmd.operands):
            return False
    if m.get("require_operands") and not cmd.operands:
        return False
    return True


def match_regex(text, rule):
    """kind: "regex" — вернуть список совпадений (match-объектов)."""
    m = rule["match"]
    if m["kind"] != "regex" or not isinstance(text, str):
        return []
    return list(m["_rx"].finditer(text))


def match_path(path, tool, rule):
    """kind: "path" — чувствительный путь для данного инструмента."""
    m = rule["match"]
    if m["kind"] != "path":
        return False
    tools = m.get("tools")
    if tools and tool not in tools:
        return False
    if any_glob(m.get("path_glob_not"), path):
        # `.env.example` — часть репозитория, а не секрет; без исключения
        # правило по `.env*` ловило бы каждый шаблон конфигурации.
        return False
    return any_glob(m.get("path_glob"), path)


def bash_readers(rule):
    """argv0, для которых путь из rules/paths.json считается прочитанным
    через Bash (TS.md §12.1): `cat ~/.ssh/id_rsa` — то же чтение, что Read."""
    return set(rule["match"].get("bash_readers") or [])


def match_config_key(present_keys, rule):
    """kind: "config_key" — «горячие» ключи конфигурации репозитория."""
    m = rule["match"]
    if m["kind"] != "config_key":
        return []
    hot = m.get("hot_keys") or []
    return sorted({k for k in present_keys
                   if any(fnmatch.fnmatchcase(k, p) for p in hot)})


def shannon_entropy(value):
    """Энтропия Шеннона в битах на символ — второй слой детекции секретов."""
    if not value:
        return 0.0
    import math
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def match_entropy(token, rule):
    m = rule["match"]
    if m["kind"] != "entropy":
        return False
    if len(token) < m.get("min_length", 20):
        return False
    charset = m.get("charset")
    if charset and not re.fullmatch(charset, token):
        return False
    return shannon_entropy(token) >= m.get("min_entropy", 4.0)


def by_id(rules, rule_id):
    for rule in rules:
        if rule["id"] == rule_id:
            return rule
    return None


def worst(severities):
    """Максимальная severity из набора."""
    ranked = [s for s in severities if s in SEVERITIES]
    if not ranked:
        return None
    return max(ranked, key=SEVERITIES.index)
