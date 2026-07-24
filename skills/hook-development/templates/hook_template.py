#!/usr/bin/env python3
"""
<name>.py — <одна строка: что делает хук и на каком событии>.

Регистрация в settings.json (пример для PreToolUse+PostToolUse):
  "hooks": {
    "PreToolUse":  [{"matcher": "Bash|Edit|Write",
                     "hooks": [{"type":"command",
                                "command":"python3 /abs/path/<name>.py"}]}],
    "PostToolUse": [{"matcher": "*",
                     "hooks": [{"type":"command",
                                "command":"python3 /abs/path/<name>.py"}]}]
  }

Батарея тестов: <name>.tests.py рядом с этим файлом (обязательна — авто-раннер
блокирует изменения без прохождения тестов).
"""
import sys
import json

# Если в сообщениях ниже есть не-ASCII (кириллица, эмодзи) — на Windows-консоли
# с не-UTF8 кодировкой по умолчанию (cp1251/cp1252/cp437) sys.stdout.write()
# падает с UnicodeEncodeError, а fail-open в конце файла тихо проглатывает
# исключение: JSON-решение хука теряется целиком. Форсируем UTF-8 заранее.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def emit(obj):
    """Отдать stdout-JSON и выйти 0.
    ensure_ascii=True — вторая, независимая линия защиты от кодировки консоли:
    JSON-текст состоит только из ASCII (\\uXXXX-escape для не-ASCII), Claude
    Code корректно разэкранирует его при разборе."""
    sys.stdout.write(json.dumps(obj, ensure_ascii=True))
    sys.exit(0)


def handle_pre(data):
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    # ... логика; при необходимости заблокировать/спросить:
    # emit({"hookSpecificOutput": {"hookEventName": "PreToolUse",
    #       "permissionDecision": "ask",           # allow | deny | ask
    #       "permissionDecisionReason": "почему"}})
    sys.exit(0)


def handle_post(data):
    tool = data.get("tool_name", "")
    resp = data.get("tool_response")
    if resp is None:
        sys.exit(0)
    # ВАЖНО: сохраняй тип resp (dict->dict, str->str) при переписывании.
    # new_resp = transform(resp)
    # if changed:
    #     emit({"hookSpecificOutput": {"hookEventName": "PostToolUse",
    #           "updatedToolOutput": new_resp,
    #           "additionalContext": "..."}})
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)
    data = json.loads(raw)
    event = data.get("hook_event_name", "")
    if event == "PreToolUse":
        handle_pre(data)
    elif event == "PostToolUse":
        handle_post(data)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)   # fail-open: баг в хуке не должен ломать сессию
