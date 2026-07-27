#!/usr/bin/env python3
"""path_guard.py — запрет чтения чувствительных путей (TS.md §12.1, P2).

Декларативные `permissions.deny` из рекомендуемых настроек закрывают
инструмент Read, но не закрывают `cat ~/.ssh/id_rsa`: для Claude Code это
обычная Bash-команда. Этот модуль закрывает именно Bash-ветку, разбирая
операнды через cmdparse, — расширение относительно исходной практики, где
проверялся только путь у файловых инструментов.

Оба контроля нужны одновременно: secret_redactor маскирует по содержимому и
может не распознать нестандартный формат ключа, path_guard не даёт прочитать
файл вовсе, потому что путь известен заранее.

Режим отказа — CLOSED.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, cmdparse, hookio, policy, ruleset          # noqa: E402

HOOK = "path_guard"

FILE_TOOLS = {"Read", "Glob", "Grep", "Edit", "Write", "MultiEdit", "NotebookEdit"}
PATH_FIELDS = ("file_path", "path", "notebook_path")


def _candidate_paths(tool, tool_input):
    """Пути, которые инструмент собирается открыть.

    `pattern` у Grep — регулярное выражение, а не путь, поэтому не берётся;
    `glob` у Grep и `pattern` у Glob — берутся, они адресуют файлы.
    """
    paths = []
    for field in PATH_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            paths.append(value)
    if tool == "Glob" and isinstance(tool_input.get("pattern"), str):
        paths.append(tool_input["pattern"])
    if tool == "Grep" and isinstance(tool_input.get("glob"), str):
        paths.append(tool_input["glob"])
    return paths


def _match_file_tool(tool, paths, cwd):
    for rule in ruleset.load("paths"):
        for path in paths:
            expanded = cmdparse.expand_operand(path, cwd)
            if (ruleset.match_path(path, tool, rule)
                    or ruleset.match_path(expanded, tool, rule)):
                return rule, path
    return None, None


def _match_bash(command, cwd):
    """Bash-ветка: чтение защищённого пути утилитой из bash_readers."""
    cmds, _ = cmdparse.parse(command)
    for rule in ruleset.load("paths"):
        readers = ruleset.bash_readers(rule)
        if not readers:
            continue
        for cmd in cmds:
            if cmd.argv0 not in readers:
                continue
            for operand in cmd.operands:
                expanded = cmdparse.expand_operand(operand, cwd)
                if (ruleset.match_path(operand, "Bash", rule)
                        or ruleset.match_path(expanded, "Bash", rule)):
                    return rule, operand
    return None, None


@hookio.guard(hookio.FAIL_CLOSED, HOOK)
def main():
    data = hookio.read()
    if data.get("hook_event_name") != "PreToolUse":
        hookio.passthrough()

    tool = data.get("tool_name") or ""
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()

    if tool == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            hookio.passthrough()
        rule, target = _match_bash(command, cwd)
        evidence = command
    elif tool in FILE_TOOLS:
        paths = _candidate_paths(tool, tool_input)
        rule, target = _match_file_tool(tool, paths, cwd)
        evidence = target
    else:
        hookio.passthrough()

    if rule is None:
        hookio.passthrough()

    resolution = policy.resolve(rule, target=target,
                                agent_id=data.get("agent_id"),
                                session_id=data.get("session_id"))
    audit.write({
        "hook": HOOK,
        "rule": rule["id"],
        "class": rule.get("class"),
        "severity": rule.get("severity"),
        "level": resolution["level"],
        "action": ("logged" if resolution["exempt"]
                   else policy.audit_action(resolution["decision"],
                                            resolution["suppressed"])),
        "target": target,
        "evidence": evidence,
        "latency_ms": hookio.elapsed_ms(),
    }, data)

    if resolution["exempt"] is not None or resolution["suppressed"]:
        hookio.passthrough()

    detail = "{} Запрошен путь: {}".format(rule.get("message", ""), target)
    decision = resolution["decision"]
    if decision == policy.DENY:
        hookio.deny("PreToolUse", policy.format_reason(rule, detail))
    if decision == policy.ASK:
        hookio.ask("PreToolUse", policy.format_reason(rule, detail))
    if decision == policy.WARN:
        hookio.warn("secure-dev [{}]: {}".format(rule["id"], detail))
    hookio.passthrough()


if __name__ == "__main__":
    main()
