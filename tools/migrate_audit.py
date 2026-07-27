#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migrate_audit.py — конвертер журнала v1.x (TSV) в JSONL v2.0 (PLAN.md 0.12).

v1.x писал одну строку на срабатывание в ~/.claude/safe-development-audit.log:

    ts \t event \t tool \t action \t session=<id> \t types=<A,B> \t count=<n>
       \t <TYPE:маска; TYPE:маска> \t <extra>

Формат v2.0 — JSONL по TS.md §6.1. Конвертация нужна, чтобы история пилота не
обнулилась при переходе: без неё сравнивать «было/стало» не с чем.

Значения секретов в исходном файле уже маскированы, поэтому конвертация их не
восстанавливает и не может восстановить — переносятся маски как есть.

    python3 tools/migrate_audit.py [--input ФАЙЛ] [--output ФАЙЛ] [--dry-run]
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit                                            # noqa: E402

DEFAULT_INPUT = os.path.expanduser(
    os.path.join("~", ".claude", "safe-development-audit.log"))

# Действия v1.x → словарь действий v2.0 (TS.md §6.1).
ACTION_MAP = {
    "ASK_EGRESS": ("asked", "secret-egress"),
    "WARN_WRITE": ("warned", "secret-output"),
    "REDACT_OUTPUT": ("redacted", "secret-output"),
    "EXCEPTION": ("error", "internal"),
}


def parse_line(line):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 4:
        return None

    ts, event, tool, action = parts[0], parts[1], parts[2], parts[3]
    fields = {}
    previews = ""
    for chunk in parts[4:]:
        chunk = chunk.strip()
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            fields[key.strip()] = value.strip()
        elif ":" in chunk:
            previews = chunk

    masked = []
    for item in (previews.split(";") if previews else []):
        item = item.strip()
        if ":" in item:
            kind, preview = item.split(":", 1)
            masked.append({"type": kind.strip(), "preview": preview.strip()})

    mapped_action, rule_class = ACTION_MAP.get(action, ("logged", "secret-output"))

    try:
        stamp = datetime.datetime.fromisoformat(ts).astimezone().isoformat(
            timespec="milliseconds")
    except ValueError:
        stamp = ts

    return {
        "v": 1,
        "kind": "event",
        "ts": stamp,
        "session_id": fields.get("session"),
        "prompt_id": None,
        "agent_id": None,
        "agent_type": None,
        "user": audit.user(),
        "host": audit.host(),
        "cwd": None,
        "repo": None,
        "git_branch": None,
        "hook": "secret_redactor",
        "event": event,
        "tool": tool,
        "rule": "secret-detected",
        "class": rule_class,
        "severity": "HIGH",
        "level": "strict",
        "action": mapped_action,
        "target": tool,
        "evidence": None,
        "masked": masked,
        "latency_ms": None,
        "plugin_version": "1.x",
        "migrated_from": "tsv",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Конвертер TSV-журнала v1.x в JSONL")
    parser.add_argument("--input", default=DEFAULT_INPUT)
    parser.add_argument("--output", default=None,
                        help="по умолчанию — migrated-v1.jsonl в каталоге журнала")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.input):
        print("Журнал v1.x не найден: {}".format(args.input))
        return 0

    records, skipped = [], 0
    with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            record = parse_line(line)
            if record is None:
                skipped += 1
                continue
            records.append(record)

    output = args.output or os.path.join(audit.audit_dir(), "migrated-v1.jsonl")

    print("Прочитано записей: {} (пропущено нераспознанных: {})".format(
        len(records), skipped))
    if args.dry_run:
        for record in records[:3]:
            print(json.dumps(record, ensure_ascii=False)[:200])
        print("Пробный запуск: файл не записан. Цель была бы: {}".format(output))
        return 0

    with open(output, "a", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    try:
        os.chmod(output, 0o600)
    except OSError:
        pass
    print("Записано в {}".format(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
