#!/usr/bin/env python3
"""policy.py — решение по правилу и память сессии (TS.md §4).

Разделение ответственности: ruleset говорит «сработало правило X», config —
«для X действует уровень Y», policy — «значит, делаем Z». Детекцией policy не
занимается.

Память решений (практика из secure-claude-code) не даёт плагину повторять одно
и то же предупреждение всю сессию. Область её действия ограничена жёстко:
подавляются только `warn` и `ask`. Решение `deny` не подавляется НИКОГДА —
иначе первый отказ в сессии становится последним, и повторная попытка проходит.
"""

import datetime
import json
import os
import time

from lib import audit, config

DENY = "deny"
ASK = "ask"
WARN = "warn"
LOG = "log"


# --- Severity → решение ----------------------------------------------------

def decision_for(severity, level):
    """TS.md §4.1 и §4.2. Уровень решает, действует ли severity вообще."""
    if level == "audit":
        return LOG
    if level == "warn":
        return WARN
    if severity in ("CRITICAL", "HIGH"):
        return DENY
    if severity == "MEDIUM":
        return ASK
    return WARN


def is_final(severity, decision):
    """CRITICAL блокируется без возможности подтвердить (TS.md §4.2).
    Эскалация — человеком в отдельном терминале, а не кнопкой в диалоге."""
    return decision == DENY and severity == "CRITICAL"


def resolve(rule, target=None, agent_id=None, session_id=None):
    """Полный резолв: уровень, решение, исключение, память сессии.

    Возвращает dict с полями level/decision/suppressed/exempt — модулю остаётся
    только оформить сообщение.
    """
    rule_id = rule.get("id", "?")
    rule_class = rule.get("class")
    level = config.effective_level(rule_id, rule_class)
    decision = decision_for(rule.get("severity", "LOW"), level)

    exempt = config.exemption_for(rule_id, target)
    if exempt is not None:
        return {"level": level, "decision": LOG, "suppressed": False,
                "exempt": exempt, "rule": rule}

    suppressed = False
    if decision in (WARN, ASK) and session_id:
        if seen(session_id, rule_id, target, agent_id):
            suppressed = True
        else:
            mark(session_id, rule_id, target, agent_id)

    return {"level": level, "decision": decision, "suppressed": suppressed,
            "exempt": None, "rule": rule}


# --- Состояние сессии ------------------------------------------------------

def state_path(session_id):
    safe = "".join(ch for ch in str(session_id or "unknown")
                   if ch.isalnum() or ch in "-_")[:64] or "unknown"
    return os.path.join(audit.state_dir(), "session-{}.json".format(safe))


def _ttl_seconds():
    hours = (config.session_memory_cfg() or {}).get("ttl_hours", 24)
    try:
        return float(hours) * 3600.0
    except Exception:
        return 24 * 3600.0


def _empty_state():
    return {"v": 1, "created": audit.now_iso(), "seen": {}, "kv": {}}


def state_load(session_id):
    """Состояние сессии; протухшее по TTL считается пустым."""
    path = state_path(session_id)
    data = audit.read_json(path, None)
    if not isinstance(data, dict):
        return _empty_state()
    try:
        if os.path.getmtime(path) + _ttl_seconds() < time.time():
            return _empty_state()
    except OSError:
        pass
    data.setdefault("seen", {})
    data.setdefault("kv", {})
    return data


def state_save(session_id, data):
    try:
        audit.write_json(state_path(session_id), data)
    except Exception:
        pass        # состояние — оптимизация, а не источник истины


def state_get(session_id, key, default=None):
    return state_load(session_id).get("kv", {}).get(key, default)


def state_set(session_id, key, value):
    """Координация между хуками одного события идёт через это хранилище:
    injection_scanner не нормализует вывод, если secret_redactor в том же
    tool_use_id уже нашёл секреты (ARCHITECTURE §4.2)."""
    data = state_load(session_id)
    data.setdefault("kv", {})[key] = value
    state_save(session_id, data)


def _memory_key(rule_id, target, agent_id):
    """Ключ расширен до (rule, target, agent_id): в исходной практике был
    только (rule, file), и субагент подавлял предупреждения главного потока."""
    return "{}|{}|{}".format(rule_id, target or "-", agent_id or "-")


def seen(session_id, rule_id, target, agent_id):
    if not (config.session_memory_cfg() or {}).get("enabled", True):
        return False
    key = _memory_key(rule_id, target, agent_id)
    stamp = state_load(session_id).get("seen", {}).get(key)
    if not stamp:
        return False
    try:
        when = datetime.datetime.fromisoformat(stamp)
    except Exception:
        return False
    age = (datetime.datetime.now(when.tzinfo) - when).total_seconds()
    return age < _ttl_seconds()


def mark(session_id, rule_id, target, agent_id):
    if not (config.session_memory_cfg() or {}).get("enabled", True):
        return
    data = state_load(session_id)
    data.setdefault("seen", {})[_memory_key(rule_id, target, agent_id)] = audit.now_iso()
    state_save(session_id, data)


def cleanup_states(max_age_hours=48):
    """Уборка протухших файлов состояния. Вызывается из audit_flush."""
    removed = 0
    cutoff = time.time() - max_age_hours * 3600.0
    try:
        names = os.listdir(audit.state_dir())
    except OSError:
        return 0
    for name in names:
        if not name.startswith(("session-", "git-")):
            continue
        path = os.path.join(audit.state_dir(), name)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except OSError:
            continue
    return removed


# --- Оформление сообщения --------------------------------------------------

def format_reason(rule, detail=None, escalation=True):
    """Обязательный состав отказа (TS.md §8.3): id правила, severity, что
    именно сработало, рабочая альтернатива, путь эскалации.

    Отказ без рабочей альтернативы приводит к тому, что агент перебирает
    обходные пути — это хуже, чем разрешить.
    """
    parts = ["secure-dev [{}, {}]: {}".format(
        rule.get("id", "?"), rule.get("severity", "?"),
        detail or rule.get("message", ""))]
    remediation = rule.get("remediation")
    if remediation:
        parts.append("Альтернатива: {}".format(remediation))
    if escalation:
        parts.append("Если операция действительно нужна — выполните её сами в "
                     "терминале либо запросите исключение: /secure-dev:policy")
    reference = rule.get("reference")
    if reference:
        parts.append("Подробно: {}".format(reference))
    return "\n\n".join(parts)


def audit_action(decision, suppressed=False):
    """Отображение решения в поле `action` записи аудита (TS.md §6.1)."""
    if suppressed:
        return "logged"
    return {DENY: "denied", ASK: "asked", WARN: "warned", LOG: "logged"}.get(
        decision, "logged")


def dump_state(session_id):
    """Для отладки и тестов."""
    return json.dumps(state_load(session_id), ensure_ascii=False, indent=2)
