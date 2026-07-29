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

Событий на смену `cwd` посреди сессии (`cd` в другой репозиторий через Bash)
нет — доверие не переоценивается до следующего `SessionStart`/`ConfigChange`.
Осознанное решение (round-6 red-team, finding 6, подтверждено): Claude Code
сам подгружает `hooks`/`settings.json`/`mcpServers` только на старте сессии,
а не при смене `cwd`, так что исполняемого риска здесь нет — команды и файлы
в новом каталоге уже проверяются per-call через `command_guard`/
`secret_redactor`/`path_guard`/`injection_scanner` (они берут живой `cwd`
на каждый вызов). Единственная потеря — баннер «репозиторий не проверен»
для человека. Закрывать это пришлось бы хешированием на каждый `Bash`-вызов
с `cd`, что бьёт по бюджету производительности (§1.3) ради узкой пользы
видимости, а не безопасности — решено не делать в рамках пилота.

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


def _hot_changed(result):
    """Затронуло ли изменение горячие ключи (TS.md §10.6), а не просто «сейчас
    где-то в репозитории есть горячий ключ».

    `result["findings"]` — полный пере-скан текущего состояния репозитория,
    он не говорит, что именно изменилось. Репозиторий, который когда-то был
    доверен с `hooks` в settings.json, иначе блокировал бы вообще любую
    последующую правку `.claude/*` — вплоть до файла, не имеющего отношения
    к горячим ключам, — потому что `hooks` там всё ещё присутствует.
    """
    changed = set(result["changed"])
    if not changed:
        return False

    baseline_hot_keys = set((result["baseline"] or {}).get("hot_keys_present") or [])
    current_hot_keys = {f["key"] for f in result["findings"]}
    if baseline_hot_keys != current_hot_keys:
        return True                    # набор горячих ключей реально изменился

    # Набор ключей тот же — но значение под уже известным горячим ключом
    # могло смениться (например, команда в hooks заменена на другую).
    # Ловим это, только если изменился именно файл/каталог, несущий ключ.
    hot_bearing = {f["file"] for f in result["findings"]}
    if changed & hot_bearing:
        return True

    return bool(changed & set(EXECUTABLE_ARTIFACTS))


def _change_evidence(result):
    """Конкретные команды/URL для изменившихся артефактов (PLAN.md 1.7).

    Путь файла в отказе не даёт человеку основания решить, блокировать
    подтверждённое расхождение или это ожидаемая правка — нужна именно та
    строка, которая появилась. `findings` уже несёт `detail` (см.
    `trust._executables`); здесь отбираются только записи по файлам, которые
    реально входят в `result["changed"]`, а не все горячие ключи репозитория.
    """
    changed = set(result["changed"])
    lines = []
    for finding in result["findings"]:
        if finding["file"] not in changed:
            continue
        for item in finding["detail"]:
            lines.append("{} → {}".format(finding["key"], item))
    return lines


def handle_config_change(data):
    result = trust.evaluate(data.get("cwd") or os.getcwd())
    source = data.get("source") or "unknown"

    if not result["changed"] and result["status"] != trust.STATUS_QUARANTINED:
        hookio.passthrough()

    hot_changed = _hot_changed(result)

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
    evidence = _change_evidence(result)
    if evidence:
        detail += "\n" + "\n".join(evidence[:10])

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
