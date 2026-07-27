#!/usr/bin/env python3
"""audit.py — JSONL-аудит и heartbeat (TS.md §6).

Два инварианта, проверяемые тестами (TS.md §16) — именно они делают фразу
«мониторим агента, а не разработчика» правдой:

  • §1.4 — реальное значение секрета не попадает в запись. `evidence`
    прогоняется через redact() и усекается до 512 символов.
  • §1.5 — содержимое диалога не собирается: ни промптов, ни ответов модели,
    ни полного содержимого файлов. Только метаданные операции.

Сбой записи НИКОГДА не поднимает исключение наружу: логирование не должно
ломать решение хука. Это не «на всякий случай», а требование — иначе полный
диск превращается в отказ в обслуживании.
"""

import datetime
import getpass
import hashlib
import json
import os
import socket
import subprocess
import time

from lib import hookio

SCHEMA_VERSION = 1
EVIDENCE_LIMIT = 512
_GIT_TIMEOUT_S = 0.5
_GIT_CACHE_TTL_S = 60

_plugin_version_cache = None
_git_cache = {}


# --- Пути ------------------------------------------------------------------

def audit_dir():
    return hookio.ensure_dir(os.path.join(hookio.data_dir(), "audit"))


def state_dir():
    return hookio.ensure_dir(os.path.join(hookio.data_dir(), "state"))


def trust_dir():
    return hookio.ensure_dir(os.path.join(hookio.data_dir(), "trust"))


def day_file(day=None):
    day = day or datetime.date.today().strftime("%Y-%m-%d")
    return os.path.join(audit_dir(), day + ".jsonl")


def now_iso():
    """ISO-8601 с офсетом локальной зоны: записи с разных машин сравнимы."""
    return datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")


# --- Окружение -------------------------------------------------------------

def plugin_version():
    global _plugin_version_cache
    if _plugin_version_cache is not None:
        return _plugin_version_cache
    version = "unknown"
    try:
        manifest = os.path.join(hookio.plugin_root(), ".claude-plugin", "plugin.json")
        with open(manifest, "r", encoding="utf-8") as fh:
            version = json.load(fh).get("version", "unknown")
    except Exception:
        pass
    _plugin_version_cache = version
    return version


def user():
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or "unknown"


def host():
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def is_wsl():
    """WSL — обязательная платформа (ADR-007). Признак идёт в heartbeat:
    запуск вне WSL означает, что часть контролей не гарантирована."""
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as fh:
            marker = fh.read().lower()
    except OSError:
        return False
    return "microsoft" in marker or "wsl" in marker


def claude_code_version(hook_input=None):
    """Версия Claude Code, если её сообщил хост."""
    for key in ("claude_code_version", "version"):
        value = (hook_input or {}).get(key)
        if isinstance(value, str) and value:
            return value
    return os.environ.get("CLAUDE_CODE_VERSION")


# --- Git-контекст ----------------------------------------------------------

def _git(cwd, *args):
    try:
        proc = subprocess.run(("git",) + args, cwd=cwd, capture_output=True,
                              encoding="utf-8", errors="replace",
                              timeout=_GIT_TIMEOUT_S)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def normalize_remote(url):
    """`git@github.com:corp/x.git` и `https://github.com/corp/x` — один репозиторий.

    Без нормализации доверие, выданное клону по ssh, не переносится на клон по
    https, и сотрудник получает повторный запрос на том же коде (TS.md §10.3).
    """
    if not url:
        return None
    value = url.strip()
    for prefix in ("ssh://", "git+ssh://", "https://", "http://", "git://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    else:
        if "@" in value and ":" in value:          # scp-подобный git@host:path
            value = value.split("@", 1)[1].replace(":", "/", 1)
    if "@" in value.split("/", 1)[0]:              # user@host/... → host/...
        value = value.split("@", 1)[1]
    if value.endswith(".git"):
        value = value[:-4]
    return value.rstrip("/") or None


def repo_root(cwd):
    return _git(cwd, "rev-parse", "--show-toplevel")


def git_context(cwd):
    """(repo, branch) с кешем: git-вызов в PreToolUse съел бы бюджет §1.3."""
    cwd = cwd or os.getcwd()
    key = os.path.realpath(cwd)
    cached = _git_cache.get(key)
    if cached:
        return cached
    disk = _read_git_cache(key)
    if disk is not None:
        _git_cache[key] = disk
        return disk
    ctx = {
        "repo": normalize_remote(_git(cwd, "remote", "get-url", "origin")),
        "git_branch": _git(cwd, "rev-parse", "--abbrev-ref", "HEAD"),
    }
    _git_cache[key] = ctx
    _write_git_cache(key, ctx)
    return ctx


def _git_cache_path(key):
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    return os.path.join(state_dir(), "git-" + digest + ".json")


def _read_git_cache(key):
    path = _git_cache_path(key)
    try:
        if os.path.getmtime(path) + _GIT_CACHE_TTL_S < time.time():
            return None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _write_git_cache(key, ctx):
    try:
        write_json(_git_cache_path(key), ctx)
    except Exception:
        pass


# --- Запись ----------------------------------------------------------------

def base_record(hook_input):
    hook_input = hook_input or {}
    cwd = hook_input.get("cwd") or os.getcwd()
    ctx = {"repo": None, "git_branch": None}
    try:
        ctx = git_context(cwd)
    except Exception:
        pass
    return {
        "v": SCHEMA_VERSION,
        "kind": "event",
        "ts": now_iso(),
        "session_id": hook_input.get("session_id"),
        "prompt_id": hook_input.get("prompt_id"),
        "agent_id": hook_input.get("agent_id"),
        "agent_type": hook_input.get("agent_type"),
        "user": user(),
        "host": host(),
        "cwd": cwd,
        "repo": ctx.get("repo"),
        "git_branch": ctx.get("git_branch"),
        "hook": None,
        "event": hook_input.get("hook_event_name"),
        "tool": hook_input.get("tool_name"),
        "rule": None,
        "class": None,
        "severity": None,
        "level": None,
        "action": "logged",
        "target": None,
        "evidence": None,
        "masked": [],
        "latency_ms": None,
        "plugin_version": plugin_version(),
    }


def sanitize_evidence(value):
    """Усечение до 512 символов и обязательный прогон через redact().

    Порядок именно такой: усекаем сначала, чтобы длинный вывод не стоил лишнего
    прохода регулярками, но редактируем всегда — усечение защитой не является.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        try:
            value = json.dumps(value, ensure_ascii=False)[:EVIDENCE_LIMIT * 2]
        except Exception:
            value = str(value)
    value = value[:EVIDENCE_LIMIT]
    try:
        from lib import redact as _redact
        cleaned, _ = _redact.redact(value)
        return cleaned
    except Exception:
        return "[unredactable]"


def write(record, hook_input=None):
    """Дописать запись в дневной JSONL. Никогда не бросает исключений."""
    try:
        full = base_record(hook_input)
        full.update({k: v for k, v in (record or {}).items()})
        full["evidence"] = sanitize_evidence(full.get("evidence"))
        _append(day_file(), full)
    except Exception:
        pass


def heartbeat(fields, hook_input=None):
    """Ответ на вопрос «работает ли контроль у сотрудника» (TS.md §6.2).

    Отсутствие heartbeat за период = плагин не установлен или отключён. Это и
    есть механизм, заменяющий недоступный на пилоте managed-enforcement.
    """
    try:
        record = {
            "v": SCHEMA_VERSION,
            "kind": "heartbeat",
            "ts": now_iso(),
            "session_id": (hook_input or {}).get("session_id"),
            "user": user(),
            "host": host(),
            "plugin_version": plugin_version(),
        }
        record.update(fields or {})
        _append(day_file(), record)
    except Exception:
        pass


def _append(path, record):
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_json(path, obj, mode=0o600):
    """Атомарная запись: .tmp + rename. Оборванная запись состояния хуже, чем
    её отсутствие — при следующем старте битый JSON выглядел бы как сброс
    доверия к репозиторию."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


# --- Чтение и ротация ------------------------------------------------------

def day_files():
    try:
        names = sorted(n for n in os.listdir(audit_dir()) if n.endswith(".jsonl"))
    except OSError:
        return []
    return [os.path.join(audit_dir(), n) for n in names]


def iter_records(paths=None):
    for path in (paths if paths is not None else day_files()):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue        # битая строка не должна ронять отчёт
        except OSError:
            continue


def rotate(retention_days):
    """Удаление файлов старше retention_days. Возвращает число удалённых."""
    if not retention_days or retention_days <= 0:
        return 0
    cutoff = datetime.date.today() - datetime.timedelta(days=int(retention_days))
    removed = 0
    for path in day_files():
        name = os.path.basename(path)[: len("YYYY-MM-DD")]
        try:
            day = datetime.datetime.strptime(name, "%Y-%m-%d").date()
        except ValueError:
            continue
        if day < cutoff:
            for candidate in (path, path + ".exported"):
                try:
                    os.remove(candidate)
                    removed += 1
                except OSError:
                    pass
    return removed
