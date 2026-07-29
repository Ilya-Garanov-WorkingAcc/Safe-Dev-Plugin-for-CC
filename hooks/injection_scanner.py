#!/usr/bin/env python3
"""injection_scanner.py — косвенные prompt injection (TS.md §9, T6, P1).

НИКОГДА не блокирует. Инъекция в README — не повод останавливать работу,
повод сделать её видимой: возвращается additionalContext с классом,
уверенностью и номерами строк.

Главная инженерная трудность здесь — не детект, а отсутствие ложных
срабатываний. Легитимный контент, который обязан проходить чисто: статьи ПРО
prompt injection, README security-репозиториев и сама спецификация этого
плагина, где перечислены все ловимые формулировки. Поэтому совпадение внутри
кавычек, обратных кавычек или блока кода весит ноль: цитата — это упоминание,
а не указание.

Обфускация нормализуется (zero-width удаляются, гомоглифы приводятся к
латинице), но только если secret_redactor в том же tool_use_id секретов не
нашёл: два updatedToolOutput на одном событии дают неопределённое поведение
(ARCHITECTURE §4.2). Координация — через session-state.

Детект-ядро живёт в lib/injection.py — тот же код использует config_trust.py
для сканирования CLAUDE.md на SessionStart (round-6 red-team, finding 3).

Режим отказа — OPEN.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, hookio, policy                    # noqa: E402
from lib import injection as _injection                          # noqa: E402

HOOK = "injection_scanner"

# Публичный API, на который опирается тест-батарея. Реэкспорт, а не копия:
# единственная реализация живёт в lib/injection.py и используется ещё и
# config_trust.py (тот же принцип, что и lib/redact.py для secret_redactor.py).
strip_zero_width = _injection.strip_zero_width
has_homoglyph_word = _injection.has_homoglyph_word
normalize = _injection.normalize
line_number = _injection.line_number
scan = _injection.scan
confidence_of = _injection.confidence_of
extract_text = _injection.extract_text
format_context = _injection.format_context
PERMISSION_REF_RE = _injection.PERMISSION_REF_RE


@hookio.guard(hookio.FAIL_OPEN, HOOK)
def main():
    data = hookio.read()
    if data.get("hook_event_name") != "PostToolUse":
        hookio.passthrough()

    response = data.get("tool_response")
    if response is None:
        hookio.passthrough()

    tool = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}
    target = (tool_input.get("file_path") or tool_input.get("url")
              or tool_input.get("command"))
    if isinstance(target, str) and config.is_excluded(target, cwd=data.get("cwd")):
        hookio.passthrough()

    text = extract_text(response)
    if not text.strip():
        hookio.passthrough()

    findings, score = scan(text)
    if not findings:
        hookio.passthrough()

    confidence = confidence_of(findings, score)
    rule = _injection.ruleset.by_id(_injection.ruleset.load("injection"),
                                    findings[0]["rule"]) or {}
    level = config.effective_level(findings[0]["rule"], "injection")

    audit.write({
        "hook": HOOK,
        "rule": findings[0]["rule"],
        "class": "injection",
        "severity": rule.get("severity", "MEDIUM"),
        "level": level,
        "action": "warned" if confidence != "low" else "logged",
        "target": target[:200] if isinstance(target, str) else tool,
        "evidence": " | ".join(f["evidence"] for f in findings[:3]),
        "latency_ms": hookio.elapsed_ms(),
    }, data)

    # Низкая уверенность — только запись в журнал. Контекст, который срабатывает
    # на корректном содержимом, обучает игнорировать все предупреждения плагина.
    if confidence == "low" or level == "audit":
        hookio.passthrough()

    context = format_context(tool, target, findings, confidence)

    obfuscated = any(f["class"] == "obfuscation" and not f["quoted"]
                     for f in findings)
    if obfuscated and isinstance(response, str):
        tool_use_id = data.get("tool_use_id")
        conflict = bool(policy.state_get(
            data.get("session_id"), "secrets:{}".format(tool_use_id), False)
        ) if tool_use_id else False
        if not conflict:
            hookio.updated_output("PostToolUse", normalize(response),
                                  additional=context)

    hookio.context("PostToolUse", context)


if __name__ == "__main__":
    main()
