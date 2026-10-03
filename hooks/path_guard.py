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

# С 2.3 покрываются и инструменты записи (Write/Edit/MultiEdit/NotebookEdit) и
# файловые MCP-инструменты: чтение закрывает одни правила (`tools`), запись —
# другие (`write_tools`), в том числе самозащита плагина и персистентность.
READ_TOOLS = {"Read", "Glob", "Grep", "NotebookRead"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
FILE_TOOLS = READ_TOOLS | WRITE_TOOLS
PATH_FIELDS = ("file_path", "path", "notebook_path", "uri", "source", "destination")

# Поля пути у файловых MCP-инструментов разных серверов. MCP-инструмент с
# файловой операцией иначе прошёл бы мимо правил (аудит 03.10.2026, C5).
MCP_PATH_FIELDS = PATH_FIELDS + ("paths", "edits", "files")


def _candidate_paths(tool, tool_input):
    """Пути, которые инструмент собирается открыть.

    `pattern` у Grep — регулярное выражение, а не путь, поэтому не берётся;
    `glob` у Grep и `pattern` у Glob — берутся, они адресуют файлы.
    """
    fields = MCP_PATH_FIELDS if tool.startswith("mcp__") else PATH_FIELDS
    paths = []
    for field in fields:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            paths.append(value)
        elif isinstance(value, list):
            paths.extend(v for v in value if isinstance(v, str) and v)
    if tool == "Glob" and isinstance(tool_input.get("pattern"), str):
        paths.append(tool_input["pattern"])
    if tool == "Grep" and isinstance(tool_input.get("glob"), str):
        paths.append(tool_input["glob"])
    return paths


def _tool_class(tool):
    """Какие правила применимы: чтение или запись."""
    if tool in WRITE_TOOLS:
        return "write"
    if tool.startswith("mcp__"):
        name = tool.lower()
        if any(w in name for w in ("write", "edit", "create", "put", "save",
                                   "delete", "remove", "move", "append")):
            return "write"
        return "read"
    return "read"


def _match_file_tool(tool, paths, cwd):
    want = _tool_class(tool)
    # MCP-инструмент матчится по псевдо-инструменту "Write"/"Read": правило не
    # перечисляет каждый сервер, а срабатывает по классу операции.
    probe = tool
    if tool.startswith("mcp__"):
        probe = "Write" if want == "write" else "Read"
    for rule in ruleset.load("paths"):
        rule_tools = rule["match"].get("write_tools" if want == "write" else "tools")
        if not rule_tools:
            continue
        for path in paths:
            expanded = cmdparse.expand_operand(path, cwd)
            if (ruleset.match_path(path, probe, rule, want)
                    or ruleset.match_path(expanded, probe, rule, want)):
                return rule, path
    return None, None


def _match_bash(command, cwd):
    """Bash-ветка: чтение защищённого пути читателем или запись в него писателем.

    Чтение: утилита из `bash_readers`, путь в операндах. Запись: утилита из
    `bash_writers` либо перенаправление `>`/`>>` в защищённый путь. До 2.3
    проверялось только чтение, и `echo key >> ~/.ssh/authorized_keys` проходил.
    """
    cmds, _ = cmdparse.parse(command)
    cmds = cmds + cmdparse.heredoc_script_commands(cmdparse.heredoc_scripts(cmds))
    for rule in ruleset.load("paths"):
        readers = ruleset.bash_readers(rule)
        writers = ruleset.bash_writers(rule)
        for cmd in cmds:
            base = cmdparse.effective_cwd(cmd, cwd) or cwd
            if readers and cmd.argv0 in readers:
                candidates = list(cmd.operands) + _at_values(cmd) + list(cmd.redirects)
                hit = _bash_hit(rule, candidates, base, "read")
                if hit:
                    return rule, hit
            if writers and cmd.argv0 in writers:
                hit = _bash_hit(rule, cmd.operands, base, "write")
                if hit:
                    return rule, hit
            if rule["match"].get("write_tools"):
                hit = _bash_hit(rule, cmd.redirects, base, "write")
                if hit:
                    return rule, hit
    return None, None


def _at_values(cmd):
    """Значения вида @file, file://, if= в аргументах: `curl --data @ключ`,
    `dd if=ключ` читают файл, а не передают имя."""
    out = []
    for arg in cmd.args:
        for prefix in ("@", "file://", "if=", "-T"):
            if arg.startswith(prefix) and len(arg) > len(prefix):
                out.append(arg[len(prefix):])
        if "@" in arg and not arg.startswith("-T"):
            tail = arg.rsplit("@", 1)[1]
            if tail and ("/" in tail or tail.startswith("~") or "." in tail):
                out.append(tail)
    return out


def _bash_hit(rule, operands, cwd, mode):
    for operand in operands:
        expanded = cmdparse.expand_operand(operand, cwd)
        if (ruleset.match_path(operand, "Bash", rule, mode)
                or ruleset.match_path(expanded, "Bash", rule, mode)):
            return operand
    return None


@hookio.guard(hookio.FAIL_CLOSED, HOOK, default_event="PreToolUse")
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
