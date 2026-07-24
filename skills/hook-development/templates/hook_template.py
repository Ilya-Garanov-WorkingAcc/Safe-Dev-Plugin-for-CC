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


def emit(obj):
    """Отдать stdout-JSON и выйти 0."""
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
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
