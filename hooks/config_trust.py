#!/usr/bin/env python3
"""config_trust.py — доверие к конфигурации репозитория (TS.md §10, P0).

Два события, разные возможности:

  • SessionStart — decision control отсутствует, заблокировать нельзя. Более
    того, хук стартует ПАРАЛЛЕЛЬНО с вредоносным хуком того же события из
    .claude/settings.json клонированного репозитория, а не до него. В первой
    сессии детект происходит пост-фактум (ARCHITECTURE §4.3), и ценность
    здесь — видимость: перечень конкретных команд и URL в контексте.
  • ConfigChange — блокировать умеет, и гонки здесь нет.

Компенсация гонки — pre-flight `secure-dev scan`, единственный контроль,
работающий до запуска claude.

Режим отказа — CLOSED: модуль относится к блокирующим.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, hookio, policy, ruleset, trust    # noqa: E402

HOOK = "config_trust"

EXECUTABLE_ARTIFACTS = (".claude/settings.json", ".claude/settings.local.json",
                        ".mcp.json", ".claude/hooks/", ".claude/agents/",
                        ".claude/commands/", ".claude/skills/")


def _rule(rule_id):
    """Правило по id; если набор не загрузился — минимальная заглушка, чтобы
    контроль не исчез вместе с файлом правил."""
    found = ruleset.by_id(ruleset.load("config"), rule_id)
    return found or {
        "id": rule_id, "class": "config-trust", "severity": "HIGH",
        "message": "Конфигурация репозитория может исполнять код.",
        "remediation": "Подтвердите репозиторий: /secure-dev:trust",
        "reference": "docs/RUNBOOK.md#config-trust",
    }


def _audit(data, rule, result, action, level):
    audit.write({
        "hook": HOOK,
        "rule": rule["id"],
        "class": rule.get("class"),
        "severity": rule.get("severity"),
        "level": level,
        "action": action,
        "target": result["remote"] or result["root"],
        "evidence": "; ".join(
            "{}:{}".format(f["file"], f["key"]) for f in result["findings"])[:512],
        "latency_ms": hookio.elapsed_ms(),
    }, data)


def handle_session_start(data):
    result = trust.evaluate(data.get("cwd") or os.getcwd())

    if result["status"] == trust.STATUS_TRUSTED:
        if result["baseline"] is None:
            # Чистый репозиторий: запоминаем слепок молча. Без этого первая же
            # правка собственного .claude/ выглядела бы как чужое изменение.
            trust.remember(result, trust.STATUS_TRUSTED)
        hookio.passthrough()

    if result["baseline"] is None:
        rule_id = "config-untrusted-new"
    elif result["status"] == trust.STATUS_QUARANTINED:
        rule_id = "config-quarantined"
    else:
        rule_id = "config-changed-hot"
    rule = _rule(rule_id)
    level = config.effective_level(rule["id"], rule.get("class"))

    # Статус фиксируется в baseline: напоминание должно повторяться каждую
    # сессию, пока расхождение не разобрано.
    trust.remember(result, result["status"])
    _audit(data, rule, result,
           "blocked_config" if result["status"] == trust.STATUS_QUARANTINED
           else "warned", level)

    if level == "audit":
        hookio.passthrough()

    hookio.context("SessionStart", "[secure-dev] {}\n\n{}\n\n{}".format(
        rule["message"], trust.format_report(result), rule["remediation"]))


def handle_config_change(data):
    result = trust.evaluate(data.get("cwd") or os.getcwd())
    source = data.get("source") or "unknown"

    if not result["changed"] and result["status"] != trust.STATUS_QUARANTINED:
        hookio.passthrough()

    hot_changed = bool(result["findings"]) or any(
        name in EXECUTABLE_ARTIFACTS for name in result["changed"])

    rule = _rule("config-changed-hot")
    level = config.effective_level(rule["id"], rule.get("class"))

    if not hot_changed:
        # Изменение не затрагивает исполняемых элементов — обновляем эталон
        # и молчим, иначе плагин станет шумом на каждой правке настроек.
        previous = (result["baseline"] or {}).get("status", trust.STATUS_TRUSTED)
        trust.remember(result, previous)
        _audit(data, rule, result, "logged", level)
        hookio.passthrough()

    _audit(data, rule, result,
           "blocked_config" if level == "strict" else "warned", level)

    detail = "Источник: {}. Изменились: {}.".format(
        source, ", ".join(result["changed"]) or "исполняемые ключи")

    if level == "strict":
        trust.remember(result, trust.STATUS_QUARANTINED)
        hookio.block_config(policy.format_reason(rule, detail))
    if level == "warn":
        hookio.warn("secure-dev [{}]: {} {}".format(
            rule["id"], rule["message"], detail))
    hookio.passthrough()


@hookio.guard(hookio.FAIL_CLOSED, HOOK)
def main():
    data = hookio.read()
    event = data.get("hook_event_name")
    if event == "SessionStart":
        handle_session_start(data)
    elif event == "ConfigChange":
        handle_config_change(data)
    hookio.passthrough()


if __name__ == "__main__":
    main()
