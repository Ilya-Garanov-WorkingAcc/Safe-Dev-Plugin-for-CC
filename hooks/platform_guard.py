#!/usr/bin/env python3
"""platform_guard.py — контроль платформы (TS.md §12.2, ADR-007, P2).

Работа Claude Code вне WSL на рабочих машинах отдела запрещена политикой.
Технически плагин это не запрещает — только предупреждает и пишет признак в
heartbeat: запрет платформы решается организационно, а не хуком.

Почему платформа вообще ограничена: разбор cmd.exe и PowerShell — второй
лексер с другой моделью кавычек, около четверти объёма разработки при нулевом
приросте ценности; хуки на Windows без Git Bash молча переключаются с bash на
PowerShell, то есть один и тот же хук исполнялся бы разными интерпретаторами;
семантика путей (регистр, разделители, буквы дисков, UNC) удваивает поверхность
path_guard и config_trust.

Режим отказа — OPEN.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, config, hookio                            # noqa: E402

HOOK = "platform_guard"

MESSAGE = (
    "Сессия запущена вне WSL. Политика отдела требует запуска Claude Code в "
    "WSL2/Ubuntu: часть контролей secure-dev — семантический разбор команд и "
    "проверка путей — на этой платформе не гарантирована."
)
REMEDIATION = (
    "Запустите Claude Code внутри дистрибутива WSL: wsl -d Ubuntu, затем "
    "перейдите в каталог проекта и запустите claude."
)


@hookio.guard(hookio.FAIL_OPEN, HOOK)
def main():
    data = hookio.read()
    if data.get("hook_event_name") != "SessionStart":
        hookio.passthrough()
    if audit.is_wsl():
        hookio.passthrough()

    level = config.effective_level("platform-not-wsl", "platform")
    audit.write({
        "hook": HOOK,
        "rule": "platform-not-wsl",
        "class": "platform",
        "severity": "MEDIUM",
        "level": level,
        "action": "warned" if level != "audit" else "logged",
        "target": sys.platform,
        "evidence": "platform={} os={}".format(sys.platform, os.name),
        "latency_ms": hookio.elapsed_ms(),
    }, data)

    if level == "audit":
        hookio.passthrough()
    hookio.context("SessionStart",
                   "[secure-dev] {}\n\n{}".format(MESSAGE, REMEDIATION))


if __name__ == "__main__":
    main()
