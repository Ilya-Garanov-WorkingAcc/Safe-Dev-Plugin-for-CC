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


# Файлы, определяющие поведение плагина. Их подмена — обход (аудит 03.10.2026,
# L4): раньше печать покрывала только policy.json, и агент, изменив правило в
# rules/commands.json или строку в lib/, снимал контроль без следа.
import glob


def manifest_sha256():
    entries = []
    for pat in ("lib/*.py", "hooks/*.py", "rules/*.json", "policy.json",
                "policy.schema.json", "bin/secure-dev", "hooks/hooks.json"):
        for path in sorted(glob.glob(os.path.join(ROOT, pat))):
            if path.endswith(".tests.py"):
                continue
            rel = os.path.relpath(path, ROOT)
            with open(path, "rb") as fh:
                entries.append("{}:{}".format(
                    rel, hashlib.sha256(fh.read()).hexdigest()))
    return hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()


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
        try:
            with open(LOCK, encoding="utf-8") as fh:
                expected_code = json.load(fh).get("code_sha256")
        except Exception:
            expected_code = None
        actual_code = manifest_sha256()
        if expected == actual and expected_code == actual_code:
            print("Совпадает: policy {} code {}".format(actual[:12], actual_code[:12]))
            return 0
        if expected_code != actual_code:
            print("РАСХОЖДЕНИЕ кода плагина\n  эталон:  {}\n  фактич.: {}".format(
                expected_code, actual_code))
            return 1
        print("РАСХОЖДЕНИЕ\n  эталон:  {}\n  фактич.: {}".format(expected, actual))
        return 1

    payload = {
        "policy_sha256": actual,
        "code_sha256": manifest_sha256(),
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
