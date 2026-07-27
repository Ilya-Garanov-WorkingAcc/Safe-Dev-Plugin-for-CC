#!/usr/bin/env python3
"""hookio.py — ввод/вывод хука и режим отказа (TS.md §2).

Единственный модуль ядра, не зависящий ни от чего внутри плагина: остальные
модули импортируют отсюда пути (`plugin_root`, `data_dir`), поэтому обратная
зависимость создала бы цикл.

Инвариант режимов отказа (ARCHITECTURE.md §4.1):
  • FAIL_OPEN   — модуль редактирует/предупреждает. Сбой → exit 0, действие идёт.
  • FAIL_CLOSED — модуль блокирует. Сбой → ask, а НЕ allow: иначе атакующий
    подбирает вход, роняющий парсер, и получает обход. И не deny: баг плагина
    не должен останавливать работу команды.

Текст исключения идёт ТОЛЬКО в аудит: сообщение об ошибке парсера — подсказка
атакующему о том, какой вход его ломает.
"""

import json
import os
import sys
import time

# На консолях с не-UTF8 локалью stdout кодирует строго и падает с
# UnicodeEncodeError на первом кириллическом символе; fail-open-обёртка глотает
# исключение, и хук молча перестаёт работать. Форсируем UTF-8 до первой
# операции чтения/записи (TS.md §1.2, регрессия v1.0.2).
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAIL_OPEN = "open"
FAIL_CLOSED = "closed"

_T0 = time.time()
_LAST_EVENT = ""
_LAST_INPUT = {}


# --- Пути ------------------------------------------------------------------

def plugin_root():
    """Корень плагина (каталог с plugin.json, hooks/, lib/, rules/).

    Каталог кеша плагина меняется при каждом обновлении, поэтому вычисляется
    от __file__, а не берётся из окружения.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def data_dir():
    """Каталог состояния, переживающий обновление плагина (ARCHITECTURE §7.2).

    ${CLAUDE_PLUGIN_DATA} задаётся Claude Code; фолбэк нужен для запуска вне
    плагина — тесты, CLI, `secure-dev doctor`.
    """
    return os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.expanduser(
        os.path.join("~", ".claude", "secure-dev"))


def ensure_dir(path, mode=0o700):
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
    except OSError:
        pass
    return path


def elapsed_ms():
    """Латентность хука от импорта hookio до вызова. Пишется в каждую запись
    аудита; тесты падают при превышении p95 из TS.md §1.3."""
    return int((time.time() - _T0) * 1000)


# --- Вход ------------------------------------------------------------------

def read():
    """Прочитать и разобрать stdin. Пустой ввод → exit 0 (штатный no-op)."""
    global _LAST_EVENT, _LAST_INPUT
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)
    data = json.loads(raw)
    if not isinstance(data, dict):
        sys.exit(0)
    _LAST_EVENT = data.get("hook_event_name", "") or ""
    _LAST_INPUT = data
    return data


def last_event():
    return _LAST_EVENT


def last_input():
    return _LAST_INPUT


def common_fields(data):
    """Поля входа, общие для всех событий (TS.md §2).

    `agent_id`/`agent_type` не-null только внутри субагента — обязательны для
    разбора инцидентов при работе роя (T10).
    """
    return {
        "session_id": data.get("session_id"),
        "prompt_id": data.get("prompt_id"),
        "agent_id": data.get("agent_id"),
        "agent_type": data.get("agent_type"),
        "cwd": data.get("cwd") or os.getcwd(),
        "permission_mode": data.get("permission_mode"),
        "event": data.get("hook_event_name"),
        "tool": data.get("tool_name"),
        "tool_use_id": data.get("tool_use_id"),
        "source": data.get("source"),
    }


# --- Выход -----------------------------------------------------------------

def emit(obj):
    """Отдать JSON-решение и выйти.

    ensure_ascii=True — вторая, независимая от reconfigure() линия защиты:
    JSON состоит только из ASCII-байт и кодируется в любой локали.
    """
    sys.stdout.write(json.dumps(obj, ensure_ascii=True))
    sys.stdout.flush()
    sys.exit(0)


def passthrough():
    """Молчаливое разрешение: ни решения, ни сообщения."""
    sys.exit(0)


def deny(event, reason):
    emit({"hookSpecificOutput": {
        "hookEventName": event or "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }})


def ask(event, reason):
    emit({"hookSpecificOutput": {
        "hookEventName": event or "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": reason,
    }})


def warn(message, event=None):
    """systemMessage без изменения решения: пользователь видит, агент — нет."""
    out = {"systemMessage": message, "suppressOutput": True}
    if event:
        out["hookSpecificOutput"] = {"hookEventName": event}
    emit(out)


def context(event, text, extra=None):
    """additionalContext — аккумулируется без конфликта между хуками одного
    события (ARCHITECTURE §4.2), в отличие от updatedToolOutput."""
    hso = {"hookEventName": event, "additionalContext": text}
    if extra:
        hso.update(extra)
    emit({"hookSpecificOutput": hso})


def updated_output(event, new_output, additional=None, system=None):
    """updatedToolOutput. Единственный модуль, который его возвращает, —
    secret_redactor: два таких вывода на одном событии дают неопределённое
    поведение (ARCHITECTURE §4.2)."""
    hso = {"hookEventName": event, "updatedToolOutput": new_output}
    if additional:
        hso["additionalContext"] = additional
    out = {"hookSpecificOutput": hso}
    if system:
        out["systemMessage"] = system
    emit(out)


def block_config(reason):
    """ConfigChange умеет блокировать изменение конфигурации (TS.md §10.6).
    Здесь, в отличие от SessionStart, гонки с вредоносным хуком нет."""
    emit({"decision": "block", "reason": reason,
          "systemMessage": reason, "suppressOutput": True})


# --- Режим отказа ----------------------------------------------------------

_FAIL_CLOSED_MESSAGE = (
    "secure-dev: не удалось проверить операцию. Подтвердите вручную, "
    "если она ожидаема."
)


def guard(fail_mode, hook_name="unknown"):
    """Декоратор main(). Ловит всё, что не SystemExit, и применяет режим отказа."""
    def deco(fn):
        def wrapper(*a, **kw):
            try:
                return fn(*a, **kw)
            except SystemExit:
                raise
            except BaseException as exc:            # noqa: BLE001 — это и есть точка
                _audit_error(hook_name, exc)
                if fail_mode == FAIL_CLOSED and _LAST_EVENT == "PreToolUse":
                    ask(_LAST_EVENT, _FAIL_CLOSED_MESSAGE)
                sys.exit(0)
        return wrapper
    return deco


def _audit_error(hook_name, exc):
    """Ошибка идёт в аудит, но её текст никогда — пользователю."""
    try:
        from lib import audit
        audit.write({
            "kind": "event", "hook": hook_name, "event": _LAST_EVENT or None,
            "rule": "PARSER_ERROR", "class": "internal", "severity": "LOW",
            "action": "error", "evidence": repr(exc)[:512],
            "latency_ms": elapsed_ms(),
        }, _LAST_INPUT)
    except Exception:
        pass


def bootstrap():
    """Вызывается хуком первой строкой: добавляет корень плагина в sys.path.

    Хук запускается как `python3 ${CLAUDE_PLUGIN_ROOT}/hooks/<name>.py`, то есть
    sys.path[0] — каталог hooks/, а не корень плагина.
    """
    root = plugin_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    return root
