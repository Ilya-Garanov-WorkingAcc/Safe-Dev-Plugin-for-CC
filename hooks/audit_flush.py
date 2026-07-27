#!/usr/bin/env python3
"""audit_flush.py — ротация и выгрузка аудита на SessionEnd (TS.md §6, P2).

Почему именно SessionEnd и почему async: сетевой вызов внутри PreToolUse
добавил бы недопустимую задержку в цикл агента и создал бы новый канал
эксфильтрации. Выгрузка не должна и задерживать завершение сессии, поэтому в
hooks.json хук помечен `async: true`.

Экспортируется только обработанный и замаскированный JSONL — никогда сырые
tool_input/tool_response (ARCHITECTURE §7.3).

Режим отказа — OPEN: неудачная выгрузка не ошибка. Недоступный сетевой шар —
штатная ситуация ноутбука вне офиса, маркер не ставится, попытка повторится
на следующей сессии.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, export, hookio, policy             # noqa: E402

HOOK = "audit_flush"


@hookio.guard(hookio.FAIL_OPEN, HOOK)
def main():
    data = hookio.read()
    if data.get("hook_event_name") != "SessionEnd":
        hookio.passthrough()

    cfg = config.audit_cfg()
    removed = audit.rotate(cfg.get("retention_days", 30))
    states = policy.cleanup_states()
    result = export.export_pending(cfg.get("export") or {})

    audit.write({
        "hook": HOOK,
        "rule": "audit-flush",
        "class": "internal",
        "severity": "LOW",
        "level": config.level(),
        "action": "logged",
        "target": (cfg.get("export") or {}).get("type", "none"),
        "evidence": "rotated={} states={} sent={} skipped={} ok={} reason={}".format(
            removed, states, result.sent, result.skipped, result.ok, result.reason),
        "latency_ms": hookio.elapsed_ms(),
    }, data)
    hookio.passthrough()


if __name__ == "__main__":
    main()
