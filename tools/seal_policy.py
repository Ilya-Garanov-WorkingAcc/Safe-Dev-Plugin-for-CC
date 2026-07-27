#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seal_policy.py — фиксация эталонного хеша политики при сборке релиза.

Записывает policy.lock.json рядом с policy.json. Дальше config.seal_status()
сравнивает фактический хеш с эталонным, и расхождение попадает в heartbeat как
`policy_tampered: true`.

Отклонение от TS.md §3.3 зафиксировано осознанно: спецификация предлагала
хранить эталон внутри plugin.json, но манифест проверяется схемой Claude Code,
и лишнее поле в нём стоило бы совместимости с будущими версиями. Отдельный
файл даёт тот же эффект и не трогает манифест.

Запускается ОДИН раз перед выпуском версии:

    python3 tools/seal_policy.py            # записать лок
    python3 tools/seal_policy.py --check    # проверить, ничего не меняя
"""

import argparse
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.path.join(ROOT, "policy.json")
LOCK = os.path.join(ROOT, "policy.lock.json")


def policy_sha256():
    with open(POLICY, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _field(path, key):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh).get(key, "unknown")
    except Exception:
        return "unknown"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Фиксация хеша policy.json")
    parser.add_argument("--check", action="store_true",
                        help="только проверить совпадение, ничего не записывать")
    parser.add_argument("--stamp", default=None,
                        help="метка времени ISO-8601 для поля sealed_at")
    args = parser.parse_args(argv)

    actual = policy_sha256()

    if args.check:
        try:
            with open(LOCK, encoding="utf-8") as fh:
                expected = json.load(fh).get("policy_sha256")
        except Exception:
            print("policy.lock.json отсутствует или нечитаем: политика не опечатана")
            return 1
        if expected == actual:
            print("Совпадает: {}".format(actual))
            return 0
        print("РАСХОЖДЕНИЕ\n  эталон:  {}\n  фактич.: {}".format(expected, actual))
        return 1

    payload = {
        "policy_sha256": actual,
        "policy_version": _field(POLICY, "policy_version"),
        "plugin_version": _field(
            os.path.join(ROOT, ".claude-plugin", "plugin.json"), "version"),
    }
    if args.stamp:
        payload["sealed_at"] = args.stamp
    with open(LOCK, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print("Записано {}\n  policy_sha256 = {}".format(LOCK, actual))
    return 0


if __name__ == "__main__":
    sys.exit(main())
