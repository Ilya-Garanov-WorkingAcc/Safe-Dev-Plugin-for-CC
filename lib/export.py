#!/usr/bin/env python3
"""export.py — выгрузка аудита: none | file | http (TS.md §6.4).

Три режима реализованы сразу, хотя на пилоте активен `none`: смена варианта
должна быть правкой одной строки в policy.json, а не разработкой. Путь
раскатки — none → file (сетевой шар) → http (коллектор).

Экспортируется только обработанный и замаскированный JSONL. Нативные
`type: "http"` хуки Claude Code для этого не используются: они шлют сырые
tool_input/tool_response, то есть ровно те секреты, которые плагин обязан
вычищать (ARCHITECTURE §7.3).

Вызывается из SessionEnd и помечен async: сетевой вызов внутри PreToolUse
добавил бы недопустимую задержку в цикл агента и создал бы новый канал
эксфильтрации.
"""

import json
import os
import shutil

from lib import audit

HTTP_TIMEOUT_S = 10
HTTP_RETRIES = 2
MARKER_SUFFIX = ".exported"


class ExportResult(object):
    __slots__ = ("ok", "sent", "skipped", "reason")

    def __init__(self, ok=True, sent=0, skipped=0, reason=None):
        self.ok = ok
        self.sent = sent
        self.skipped = skipped
        self.reason = reason

    def as_dict(self):
        return {"ok": self.ok, "sent": self.sent,
                "skipped": self.skipped, "reason": self.reason}

    def __repr__(self):
        return "ExportResult({})".format(self.as_dict())


# --- Точки входа -----------------------------------------------------------

def export(records, cfg):
    """Документированный API TS.md §6.4: выгрузить готовый список записей."""
    kind = (cfg or {}).get("type", "none")
    if kind == "none" or not records:
        return ExportResult(True, 0, len(records or []), "export disabled")
    if kind == "http":
        return _http_send(records, cfg)
    if kind == "file":
        return _file_write_records(records, cfg)
    return ExportResult(False, 0, len(records), "unknown export type")


def export_pending(cfg):
    """Выгрузить все ещё не выгруженные дневные файлы.

    Файл текущего дня отправляется тоже: сессия закончилась, а данные должны
    быть видны сегодня, а не завтра. Повторная отправка исключена маркером
    `.exported`, который считается устаревшим при дозаписи файла.
    """
    kind = (cfg or {}).get("type", "none")
    if kind == "none":
        return ExportResult(True, 0, 0, "export disabled")

    sent = skipped = 0
    problems = []
    for path in audit.day_files():
        if _already_exported(path):
            skipped += 1
            continue
        # Размер снимается ДО выгрузки: то, что допишется в процессе, уйдёт
        # следующей выгрузкой, а не потеряется.
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if kind == "file":
            result = _file_copy(path, cfg)
        elif kind == "http":
            result = _http_send(_read_records(path, _exported_size(path)), cfg)
        else:
            result = ExportResult(False, 0, 0, "unknown export type")
        if result.ok:
            _mark_exported(path, size)
            sent += 1
        else:
            problems.append(result.reason)
    return ExportResult(not problems, sent, skipped,
                        "; ".join(p for p in problems if p) or None)


# --- Маркеры ---------------------------------------------------------------

def _marker(path):
    return path + MARKER_SUFFIX


def _exported_size(path):
    """Сколько байт дневного файла уже выгружено.

    Изначально маркер сравнивался по mtime, и это оказалось неверно: ядро
    проставляет временные метки из грубого таймера, поэтому дозапись в тот же
    тик не меняет mtime и запись молча не уходила бы в выгрузку. Размер файла
    для append-only JSONL точен и монотонен.
    """
    data = audit.read_json(_marker(path), None)
    if isinstance(data, dict):
        try:
            return int(data.get("size", 0))
        except (TypeError, ValueError):
            return 0
    return 0                       # маркер старого формата — выгрузить заново


def _already_exported(path):
    try:
        return _exported_size(path) >= os.path.getsize(path)
    except OSError:
        return False


def _mark_exported(path, size):
    try:
        audit.write_json(_marker(path), {"ts": audit.now_iso(), "size": size})
    except OSError:
        pass


def _read_records(path, offset=0):
    """Записи, начиная с байтового смещения: в режиме http повторная отправка
    уже отданных строк создала бы дубликаты в коллекторе."""
    records = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            fh.seek(offset)
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return records


# --- Режим file ------------------------------------------------------------

def _dest_dir(cfg):
    return os.path.join(cfg.get("path") or "", audit.user(), audit.host())


def _file_copy(path, cfg):
    """Копирование дневного файла в <path>/<user>/<host>/.

    Недоступность каталога — не ошибка: сетевой шар может быть не примонтирован,
    маркер не ставится, попытка повторится на следующей сессии.
    """
    dest_dir = _dest_dir(cfg)
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as exc:
        return ExportResult(False, 0, 1, "недоступен путь экспорта: {}".format(exc))
    dest = os.path.join(dest_dir, os.path.basename(path))
    tmp = dest + ".tmp"
    try:
        shutil.copyfile(path, tmp)
        os.replace(tmp, dest)
    except OSError as exc:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return ExportResult(False, 0, 1, "ошибка записи: {}".format(exc))
    return ExportResult(True, 1, 0, None)


def _file_write_records(records, cfg):
    dest_dir = _dest_dir(cfg)
    try:
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(audit.day_file()))
        with open(dest, "a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        return ExportResult(False, 0, len(records), str(exc))
    return ExportResult(True, len(records), 0, None)


# --- Режим http ------------------------------------------------------------

def _http_send(records, cfg):
    if not records:
        return ExportResult(True, 0, 0, None)
    url = cfg.get("url")
    if not url:
        return ExportResult(False, 0, len(records), "audit.export.url не задан")

    import urllib.request

    payload = json.dumps({"records": records}, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token_env = cfg.get("token_env")
    if token_env:
        # В политике хранится ИМЯ переменной, а не токен: policy.json лежит в
        # git, и секрет в нём был бы ровно той утечкой, которую плагин ловит.
        token = os.environ.get(token_env)
        if token:
            headers["Authorization"] = "Bearer " + token

    last = None
    for _ in range(HTTP_RETRIES + 1):
        request = urllib.request.Request(url, data=payload, headers=headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_S) as resp:
                if 200 <= resp.status < 300:
                    return ExportResult(True, len(records), 0, None)
                last = "HTTP {}".format(resp.status)
        except Exception as exc:                 # сеть, TLS, таймаут
            last = type(exc).__name__
    return ExportResult(False, 0, len(records), last or "http error")
