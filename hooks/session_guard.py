#!/usr/bin/env python3
"""session_guard.py — баннер, контекст сессии и heartbeat (TS.md §13, P1).

Heartbeat — центральный механизм всей пилотной конфигурации. Плагин ставится
вручную и не защищён managed settings, поэтому технически запретить его
отключение невозможно (T11). Зато отключивший его сотрудник перестаёт
появляться в сводке — вопрос переходит из технической плоскости, где он не
решается, в управленческую, где рычаг есть (ADR-001).

additionalContext формулируется ФАКТАМИ, а не императивами. Императив вида
«не выполняй…» триггерит собственную защиту Claude от инъекций, и текст будет
показан пользователю вместо применения.

Режим отказа — OPEN: баннер не стоит того, чтобы ломать сессию.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, hookio, ruleset, trust            # noqa: E402

HOOK = "session_guard"

WATCH_PATHS = [".claude/settings.json", ".claude/settings.local.json", ".mcp.json"]


def heartbeat_fields(data):
    cfg = config.load()
    return {
        "policy_version": cfg.get("policy_version"),
        "policy_sha256": config.policy_sha256(),
        "policy_tampered": config.is_tampered(),
        "policy_seal": config.seal_status(),
        "level": config.level(),
        "rules_loaded": ruleset.loaded_count(),
        "settings_template_applied": config.settings_template_applied(),
        "wsl": audit.is_wsl(),
        "claude_code_version": audit.claude_code_version(data),
        "session_source": data.get("source"),
    }


def banner(fields, repo_line):
    """Строка состояния для человека. Отключается через ui.banner."""
    export_label = {"none": "локально", "file": "сетевой каталог",
                    "http": "коллектор"}.get(
                        (config.audit_cfg().get("export") or {}).get("type", "none"),
                        "локально")
    return "\n".join([
        "┌─ secure-dev {} {}".format(audit.plugin_version(), "─" * 28),
        "│ Режим: {:<10} Правил: {}".format(
            fields["level"].upper(), fields["rules_loaded"]),
        "│ Политика: {}{}".format(
            fields["policy_version"],
            "  ⚠ изменена локально" if fields["policy_tampered"] else ""),
        "│ {}".format(repo_line),
        "│ Экспорт аудита: {}".format(export_label),
        "└" + "─" * 44,
    ])


def _sudo_clause():
    """Формулировка обязана отражать реальный уровень privilege, а не
    декларировать блокировку, которой на audit/warn нет (red-team finding:
    баннер утверждал недоступность sudo, пока реально шли только логи)."""
    sudo_level = config.effective_level("command-sudo", "privilege")
    if sudo_level == "strict":
        return "Команда sudo агенту недоступна по политике."
    return "Попытки sudo фиксируются в журнале, но не блокируются на " \
           "текущем уровне политики ({}).".format(sudo_level)


def context_text(fields):
    """Факты о сессии. Ни одного повелительного наклонения — см. TS.md §13.1."""
    parts = [
        "В этой сессии активен контроль secure-dev в режиме {}.".format(
            fields["level"]),
        "Деструктивные команды файловой системы и git фиксируются в журнале"
        + (" и блокируются." if fields["level"] == "strict" else "."),
        "Секреты в выводе инструментов заменяются плейсхолдерами.",
        _sudo_clause(),
    ]
    if not fields["wsl"]:
        parts.append("Сессия запущена вне WSL; политика отдела требует WSL, "
                     "часть контролей на этой платформе не гарантирована.")
    if not fields["settings_template_applied"]:
        parts.append("Рекомендуемый ~/.claude/settings.json не применён — "
                     "декларативные запреты чтения секретов не действуют.")
    return " ".join(parts)


def handle_session_start(data):
    fields = heartbeat_fields(data)
    audit.heartbeat(fields, data)

    repo_line = "Репозиторий: —"
    try:
        result = trust.evaluate(data.get("cwd") or os.getcwd())
        label = {trust.STATUS_TRUSTED: "доверенный",
                 trust.STATUS_PENDING: "не подтверждён",
                 trust.STATUS_QUARANTINED: "карантин"}.get(result["status"], "?")
        repo_line = "Репозиторий: {}  [{}]".format(
            result["remote"] or os.path.basename(result["root"]), label)
    except Exception:
        pass                       # доверие — забота config_trust, не баннера

    out = {"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "additionalContext": context_text(fields),
        "watchPaths": WATCH_PATHS,
    }}
    if (config.ui() or {}).get("banner", True):
        out["systemMessage"] = banner(fields, repo_line)
    hookio.emit(out)


def handle_subagent_start(data):
    """Политика для субагента идентична: иначе делегирование задачи
    становится способом обхода (T10)."""
    hookio.context("SubagentStart",
                   "В этой сессии активен контроль secure-dev в режиме {}. "
                   "Политика для субагентов идентична основной: деструктивные "
                   "команды фиксируются, {} секреты в выводе "
                   "заменяются плейсхолдерами.".format(
                       config.level(),
                       "sudo недоступен," if config.effective_level(
                           "command-sudo", "privilege") == "strict"
                       else "попытки sudo фиксируются в журнале,"))


@hookio.guard(hookio.FAIL_OPEN, HOOK)
def main():
    data = hookio.read()
    event = data.get("hook_event_name")
    if event == "SessionStart":
        handle_session_start(data)
    elif event == "SubagentStart":
        handle_subagent_start(data)
    hookio.passthrough()


if __name__ == "__main__":
    main()
