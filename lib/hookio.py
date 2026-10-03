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
import select
import signal
import stat
import sys
import tempfile
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
_PRELOADED = None          # stdin, уже прочитанный сторожем (см. guard)

# Бюджет хука по событию, секунды. Он заведомо меньше `timeout` в hooks.json:
# хук, убитый Claude Code по таймауту, действие НЕ блокирует, поэтому отвечать
# надо самому и раньше — «не успел проверить» вместо молчаливого пропуска.
BUDGETS = {"PreToolUse": 3.5, "ConfigChange": 3.5, "PostToolUse": 7.0,
           "SessionStart": 7.0, "SubagentStart": 3.5}


# --- Пути ------------------------------------------------------------------

def plugin_root():
    """Корень плагина (каталог с plugin.json, hooks/, lib/, rules/).

    Каталог кеша плагина меняется при каждом обновлении, поэтому вычисляется
    от __file__, а не берётся из окружения.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fallback_data_dir():
    return os.path.expanduser(os.path.join("~", ".claude", "secure-dev"))


_POINTER_NAME = "data_dir_pointer.txt"


def data_dir():
    """Каталог состояния, переживающий обновление плагина (ARCHITECTURE §7.2).

    ${CLAUDE_PLUGIN_DATA} задаётся Claude Code только для процессов хуков,
    объявленных в hooks.json. bin/secure-dev (а значит и команды
    /secure-dev:trust, :report, :policy — они выполняют его через обычный
    Bash-инструмент, не как хук) этой переменной не видит и без явной
    синхронизации молча читал бы и писал ДРУГОЙ каталог, чем настоящие хуки —
    аудит и доверие репозитория расходились бы между CLI и живой сессией.

    Поэтому хук-процесс (у которого переменная есть) оставляет в фолбэк-
    каталоге указатель на реальный путь; CLI без переменной подхватывает его.
    """
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    fallback = _fallback_data_dir()
    if env:
        _remember_data_dir(env, fallback)
        return env
    return _recall_data_dir(fallback) or fallback


def _remember_data_dir(real_dir, fallback):
    if os.path.abspath(real_dir) == os.path.abspath(fallback):
        return
    try:
        target = os.path.abspath(real_dir)
        if _recall_data_dir(fallback) == target:
            return                      # указатель актуален — лишней записи нет
        ensure_dir(fallback)
        atomic_write(os.path.join(fallback, _POINTER_NAME), target)
    except OSError:
        pass


def _recall_data_dir(fallback):
    try:
        with open(os.path.join(fallback, _POINTER_NAME), "r", encoding="utf-8") as fh:
            path = fh.read().strip()
    except OSError:
        return None
    return path or None


def ensure_dir(path, mode=0o700):
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
    except OSError:
        pass
    return path


# --- Запись файлов плагина -------------------------------------------------
#
# Каталог данных доступен на запись агенту. Предсказуемое имя временного
# файла и открытие по пути превращали сам хук в инструмент: симлинк на месте
# `<файл>.tmp` или дневного журнала заставлял плагин перезаписать `~/.bashrc`
# или `authorized_keys` своими руками, в обход собственных правил.

def atomic_write(path, text, mode=0o600):
    """Запись через mkstemp (O_EXCL, случайное имя) и rename.

    rename заменяет сам симлинк, а не его цель, поэтому подложенная ссылка на
    месте `path` не уводит запись в чужой файл.
    """
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".sd-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_line(path, line, mode=0o600):
    """Дописать строку, не следуя симлинку и только в свой обычный файл."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (
                hasattr(os, "getuid") and info.st_uid != os.getuid()):
            raise OSError("audit target is not a regular file owned by the user")
        os.write(fd, line.encode("utf-8", errors="replace"))
        try:
            os.fchmod(fd, mode)
        except OSError:
            pass
    finally:
        os.close(fd)


def elapsed_ms():
    """Латентность хука от импорта hookio до вызова. Пишется в каждую запись
    аудита; тесты падают при превышении p95 из TS.md §1.3."""
    return int((time.time() - _T0) * 1000)


# --- Вход ------------------------------------------------------------------

def read():
    """Прочитать и разобрать stdin. Пустой ввод → exit 0 (штатный no-op)."""
    global _LAST_EVENT, _LAST_INPUT
    raw = _PRELOADED if _PRELOADED is not None else sys.stdin.read()
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
_TIMEOUT_MESSAGE = (
    "secure-dev: проверка не уложилась в отведённое время (слишком длинный "
    "или сложный ввод). Подтвердите вручную, если операция ожидаема."
)


def guard(fail_mode, hook_name="unknown", on_timeout=None, default_event=""):
    """Декоратор main(). Ловит всё, что не SystemExit, и применяет режим отказа.

    Плюс сторож по времени: логика хука выполняется в дочернем процессе, а
    родитель ждёт её не дольше BUDGETS[событие]. Сигналом или потоком это не
    сделать — регулярное выражение в катастрофическом бэктрекинге держит GIL
    и не прерывается. По истечении бюджета ребёнок убивается, и срабатывает
    `on_timeout(data)` либо режим отказа (FAIL_CLOSED на PreToolUse → ask).
    Сторож включается только у настоящего хука (stdout не подменён): батареи
    вызывают main() в процессе теста и перехватывают вывод через StringIO.

    `default_event` — событие, на которое хук зарегистрирован: если вход не
    разобрался как JSON, fail-closed-хуку всё равно нужно знать, чем отвечать.

    Механизм эскалации зависит от события — decision control не единообразен
    (ARCHITECTURE §4.1, §10.5-10.6):
      • PreToolUse   — ask() через permissionDecision.
      • ConfigChange — умеет блокировать; эскалация через block_config(),
        а не ask() (permissionDecision там не читается).
      • SessionStart и прочие события без decision control — заблокировать
        нечем, сбой неизбежно fail-open. Это не дыра, а факт возможностей
        события: TS.md §10.5 явно говорит, что SessionStart не может
        заблокировать сессию даже штатным путём.
    """
    def deco(fn):
        def guarded(*a, **kw):
            try:
                return fn(*a, **kw)
            except SystemExit:
                raise
            except BaseException as exc:            # noqa: BLE001 — это и есть точка
                _audit_error(hook_name, exc)
                _fail(fail_mode, _LAST_EVENT or default_event, _FAIL_CLOSED_MESSAGE)
                sys.exit(0)

        def wrapper(*a, **kw):
            if not _watchdog_available():
                return guarded(*a, **kw)
            return _run_with_deadline(guarded, a, kw, fail_mode, hook_name,
                                      on_timeout, default_event)
        return wrapper
    return deco


def _fail(fail_mode, event, message):
    if fail_mode != FAIL_CLOSED:
        return
    if event == "PreToolUse":
        ask(event, message)
    elif event == "ConfigChange":
        block_config(message)


def _watchdog_available():
    return (hasattr(os, "fork") and sys.stdout is sys.__stdout__
            and os.environ.get("SECURE_DEV_NO_WATCHDOG") != "1")


def _run_with_deadline(fn, a, kw, fail_mode, hook_name, on_timeout, default_event):
    """Выполнить хук в дочернем процессе с ограничением по времени."""
    global _PRELOADED, _LAST_EVENT, _LAST_INPUT
    _PRELOADED = sys.stdin.read()
    data = {}
    try:
        parsed = json.loads(_PRELOADED) if _PRELOADED.strip() else {}
        if isinstance(parsed, dict):
            data = parsed
    except (ValueError, RecursionError):
        data = {}
    event = data.get("hook_event_name") or default_event
    budget = BUDGETS.get(event, 3.5) - (time.time() - _T0)

    sys.stdout.flush()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:                                    # ребёнок: собственно хук
        code = 0
        try:
            os.close(read_fd)
            os.dup2(write_fd, 1)
            os.close(write_fd)
            fn(*a, **kw)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 0
        except BaseException:                       # noqa: BLE001
            code = 1
        try:
            sys.stdout.flush()
        except Exception:
            pass
        os._exit(code)

    os.close(write_fd)
    chunks, deadline, timed_out = [], time.time() + max(budget, 0.2), False
    while True:
        left = deadline - time.time()
        if left <= 0:
            timed_out = True
            break
        ready, _, _ = select.select([read_fd], [], [], left)
        if not ready:
            timed_out = True
            break
        block = os.read(read_fd, 65536)
        if not block:
            break
        chunks.append(block)
    os.close(read_fd)

    if timed_out:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        os.waitpid(pid, 0)
        _LAST_EVENT, _LAST_INPUT = event, data
        _audit_error(hook_name, TimeoutError("hook budget exceeded"), rule="HOOK_TIMEOUT")
        if on_timeout is not None:
            try:
                on_timeout(data)
            except SystemExit:
                raise
            except BaseException:                   # noqa: BLE001
                pass
        _fail(fail_mode, event, _TIMEOUT_MESSAGE)
        sys.exit(0)

    _, status = os.waitpid(pid, 0)
    out = b"".join(chunks)
    if out:
        sys.stdout.buffer.write(out)
        sys.stdout.flush()
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 0)


def _audit_error(hook_name, exc, rule="PARSER_ERROR"):
    """Ошибка идёт в аудит, но её текст никогда — пользователю."""
    try:
        from lib import audit
        audit.write({
            "kind": "event", "hook": hook_name, "event": _LAST_EVENT or None,
            "rule": rule, "class": "internal", "severity": "LOW",
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
