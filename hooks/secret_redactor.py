#!/usr/bin/env python3
"""secret_redactor.py — анонимизация секретов (T1, T2). Перенос v1.x на ядро.

Поведение НЕ меняется относительно v1.x — это условие приёмки фазы 0
(PLAN.md 0.10): тест-батарея v1.x гоняется на этом коде без правок.
Меняется только внутреннее устройство: правила приехали в rules/secrets.json
(ADR-005), аудит стал JSONL (TS.md §6.1), уровень берётся из политики.

Три ветки, все три сохранены из v1.x:
  • Исходящий канал (Bash / WebFetch / WebSearch / MCP) с секретом в аргументах
        → `ask`. Команда НЕ портится: ломать легальные аутентифицированные
          вызовы дороже, чем спросить.
  • Write / Edit / MultiEdit с секретом в содержимом
        → только предупреждение. Блокировать запись файла значит ломать
          основной рабочий процесс ради побочного риска.
  • Любой вывод инструмента (PostToolUse)
        → `updatedToolOutput` с плейсхолдерами: модель не должна увидеть
          реальное значение.

Режим отказа — OPEN: сбой не должен ломать работу Claude Code.
Это единственный модуль, возвращающий updatedToolOutput (ARCHITECTURE §4.2).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, hookio, policy                    # noqa: E402
from lib import redact as _redact                                # noqa: E402

HOOK = "secret_redactor"

EGRESS_TOOLS = {"Bash", "WebFetch", "WebSearch"}     # + любой инструмент mcp__*
WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}

EGRESS_FIELDS = {
    "Bash": ["command"],
    "WebFetch": ["url", "prompt"],
    "WebSearch": ["query"],
}
WRITE_FIELDS = ["content", "new_string"]             # + MultiEdit.edits[].new_string

# Публичный API, на который опирается тест-батарея v1.x. Реэкспорт, а не копия:
# единственная реализация живёт в lib/redact.py и используется ещё и аудитом.
mask = _redact.mask
redact = _redact.redact
redact_any = _redact.redact_any
PLACEHOLDER = _redact.PLACEHOLDER


def _level(findings, rule_class):
    """Самый строгий уровень среди сработавших типов секретов.

    Класс подставляется контекстом, а не правилом: один и тот же паттерн на
    выходе инструмента — это secret-output, а в исходящем вызове —
    secret-egress, и раскатываются они по разному графику (PLAN.md фаза 8).
    """
    best = "audit"
    for kind, _ in findings:
        rule = _redact.rule_for_type(kind)
        best = config.harder(best, config.effective_level(
            rule["id"] if rule else kind, rule_class))
    return best


def _audit(data, findings, rule_class, action, level, target=None):
    audit.write({
        "hook": HOOK,
        "rule": "secret-detected",
        "class": rule_class,
        "severity": _redact.worst_severity(findings),
        "level": level,
        "action": action,
        "target": target,
        "masked": _redact.masked_records(findings),
        "latency_ms": hookio.elapsed_ms(),
    }, data)


def handle_pre(data, tool):
    tool_input = data.get("tool_input") or {}
    is_mcp = tool.startswith("mcp__")

    # 1) Запись в файл — предупреждаем, содержимое не трогаем.
    if tool in WRITE_TOOLS:
        path = tool_input.get("file_path")
        if config.is_excluded(path):
            hookio.passthrough()          # фикстуры и тесты — вне проверки
        chunks = []
        for field in WRITE_FIELDS:
            value = tool_input.get(field)
            if isinstance(value, str):
                chunks.append(value)
        for edit in (tool_input.get("edits") or []):             # MultiEdit
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                chunks.append(edit["new_string"])
        _, findings = _redact.redact("\n".join(chunks))
        if not findings:
            hookio.passthrough()
        level = _level(findings, "secret-output")
        _audit(data, findings, "secret-output", "warned", level, target=path)
        if level == "audit":
            hookio.passthrough()
        types = ", ".join(_redact.types_of(findings))
        hookio.warn("⚠️  Секрет(ы) в записываемом файле: {}. "
                    "Запись разрешена как есть — проверь перед коммитом.".format(types),
                    event="PreToolUse")

    # 2) Исходящие каналы — спрашиваем пользователя, команду не портим.
    if tool in EGRESS_TOOLS or is_mcp:
        if is_mcp:
            _, findings = _redact.redact_any(tool_input)
        else:
            chunks = []
            for field in EGRESS_FIELDS.get(tool, []):
                value = tool_input.get(field)
                if isinstance(value, str):
                    chunks.append(value)
            _, findings = _redact.redact("\n".join(chunks))
        if not findings:
            hookio.passthrough()
        level = _level(findings, "secret-egress")
        types = ", ".join(_redact.types_of(findings))
        if level == "strict":
            _audit(data, findings, "secret-egress", "asked", level, target=tool)
            hookio.ask("PreToolUse",
                       "\U0001f512 Обнаружены секреты ({}) в исходящем вызове {}. "
                       "Возможна утечка данных. Подтверди, только если "
                       "действительно намерен отправить эти данные.".format(types, tool))
        _audit(data, findings, "secret-egress",
               "warned" if level == "warn" else "logged", level, target=tool)
        if level == "warn":
            hookio.warn("\U0001f512 secure-dev: секреты ({}) в исходящем вызове "
                        "{}.".format(types, tool), event="PreToolUse")
        hookio.passthrough()

    hookio.passthrough()


def handle_post(data, tool):
    response = data.get("tool_response")
    if response is None:
        hookio.passthrough()
    new_response, findings = _redact.redact_any(response)
    if not findings:
        hookio.passthrough()

    level = _level(findings, "secret-output")
    types = ", ".join(_redact.types_of(findings))

    # Отметка для injection_scanner: нормализовать вывод в том же вызове ему
    # нельзя, иначе два updatedToolOutput на одном событии (ARCHITECTURE §4.2).
    tool_use_id = data.get("tool_use_id")
    if tool_use_id:
        try:
            policy.state_set(data.get("session_id"),
                             "secrets:{}".format(tool_use_id), True)
        except Exception:
            pass

    _audit(data, findings, "secret-output",
           "redacted" if level == "strict" else "warned", level, target=tool)

    if level == "strict":
        hookio.updated_output(
            "PostToolUse", new_response,
            additional=("[security] В выводе {} были вычищены секреты ({}); "
                        "модель видит плейсхолдеры вместо реальных "
                        "значений.".format(tool, types)),
            system="\U0001f512 Из вывода {} удалено секретов: {} ({}).".format(
                tool, len(findings), types))
    if level == "warn":
        hookio.context("PostToolUse",
                       "[security] В выводе {} присутствуют секреты ({}). "
                       "Не копируй их в файлы и в исходящие вызовы.".format(
                           tool, types))
    hookio.passthrough()


@hookio.guard(hookio.FAIL_OPEN, HOOK)
def main():
    data = hookio.read()
    event = data.get("hook_event_name", "")
    tool = data.get("tool_name", "") or ""
    if event == "PreToolUse":
        handle_pre(data, tool)
    elif event == "PostToolUse":
        handle_post(data, tool)
    hookio.passthrough()


if __name__ == "__main__":
    main()
