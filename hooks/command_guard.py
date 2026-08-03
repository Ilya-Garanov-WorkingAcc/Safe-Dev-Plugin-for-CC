#!/usr/bin/env python3
"""command_guard.py — блокировка деструктивных команд (TS.md §8, P0).

Закрывает T4 (разрушение машины), T5 (потеря работы в git), T8 (эскалация до
root), T9 (персистентность через shell-конфиг).

Режим отказа — CLOSED. Если разбор не удался, хук обязан вернуть `ask`, а не
пропустить: иначе атакующему достаточно подобрать вход, роняющий парсер.
Промежуточный режим — именно `ask`, а не `deny`: баг плагина не должен
останавливать работу команды.
"""

import fnmatch
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, cmdparse, config, hookio, policy, ruleset  # noqa: E402

HOOK = "command_guard"
MAX_AUDIT_RECORDS = 8

# Предупреждения парсера, при которых команда считается неразобранной.
# Все они означают одно: статически неизвестно, что будет выполнено.
ESCALATING_WARNINGS = {
    "argv0_is_variable", "argv0_from_substitution", "interpreter_exec",
    "max_depth_exceeded", "too_many_commands", "recursion_limit",
    "source_unresolved", "shell_c_unresolved",
}

_ROOT_LITERALS = {"/", "/.", "/*", "/**", "~", "~/", "~/*", "$HOME", "${HOME}",
                  "$HOME/", "$HOME/*", "${HOME}/*", "..", "../", "../*", "../.."}


def build_context(cmd, cwd):
    """Контекст для матчера: то, что знает хук, но не знает парсер."""
    expanded = [cmdparse.expand_operand(op, cwd) for op in cmd.operands]
    expanded_redirects = [cmdparse.expand_operand(r, cwd) for r in cmd.redirects]
    return {
        "expanded_operands": expanded,
        "expanded_redirects": expanded_redirects,
        "has_operand_outside_cwd": any(
            cmdparse.outside_cwd(op, cwd) for op in cmd.operands
            if not op.startswith("-")),
        "has_root_target": any(_is_root_target(raw, exp, cwd)
                               for raw, exp in zip(cmd.operands, expanded)),
        "branch_protected": _branch_protected(cmd, cwd),
    }


def _is_root_target(raw, expanded, cwd):
    """Корень, домашний каталог или каталог выше рабочего.

    Проверяются обе формы — написанная и разрешённая: `~` и `/home/user` это
    один каталог, а `../..` виден только после раскрытия. Каталог-предок cwd
    считается корневой целью: удаление родителя уносит и проект, и всё вокруг.
    """
    if raw in _ROOT_LITERALS:
        return True
    if not expanded:
        return False
    home = os.path.realpath(os.path.expanduser("~"))
    if expanded in ("/", home):
        return True
    try:
        here = os.path.realpath(cwd or os.getcwd())
    except OSError:
        return False
    return here != expanded and here.startswith(expanded.rstrip("/") + os.sep)


def _branch_protected(cmd, cwd):
    """Защищена ли ветка, в которую идёт push.

    Учитывается и текущая ветка, и явно названная в аргументах: `git push -f
    origin main` из feature-ветки — это push в main. Ветку определить не
    удалось → считаем защищённой (fail-closed): цена ошибки в другую сторону —
    молча переписанная история main.
    """
    patterns = config.protected_branches()
    for operand in cmd.operands:
        if any(fnmatch.fnmatchcase(operand, p) for p in patterns):
            return True
    try:
        branch = audit.git_context(cwd).get("git_branch")
    except Exception:
        return True
    if not branch:
        return True
    return any(fnmatch.fnmatchcase(branch, p) for p in patterns)


def collect_matches(command, cmds, cwd):
    """Все сработавшие правила: (rule, cmd_или_None, target)."""
    rules = ruleset.load("commands") + _extra_rules()
    matches = []

    for rule in rules:
        kind = rule["match"]["kind"]
        if kind == "regex":
            # Правила по сырому тексту нужны там, где конструкция не является
            # командой в смысле argv0 — форк-бомба, работа с историей шелла.
            if ruleset.match_regex(command, rule):
                matches.append((rule, None, None))
            continue
        if kind != "command":
            continue
        for cmd in cmds:
            ctx = build_context(cmd, cwd)
            if ruleset.match_command(cmd, rule, ctx):
                target = (cmd.operands[0] if cmd.operands
                          else (cmd.redirects[0] if cmd.redirects else cmd.argv0))
                matches.append((rule, cmd, target))
                break            # одного срабатывания правила достаточно
    return matches


def _extra_rules():
    """Локальные правила сотрудника: только запрещающие, только добавляют."""
    out = []
    for rule in (config.extra_rules() or []):
        if rule.get("match", {}).get("kind") not in ("command", "regex"):
            continue
        prepared = ruleset._prepare(rule)
        if prepared is not None:
            out.append(prepared)
    return out


def decide(matches, session_id, agent_id):
    """Наиболее ограничительное решение среди сработавших правил."""
    order = {policy.DENY: 3, policy.ASK: 2, policy.WARN: 1, policy.LOG: 0}
    best = None
    resolutions = []
    for rule, cmd, target in matches:
        resolution = policy.resolve(rule, target=target, agent_id=agent_id,
                                    session_id=session_id)
        resolution["cmd"] = cmd
        resolution["target"] = target
        resolutions.append(resolution)
        effective = policy.LOG if resolution["suppressed"] else resolution["decision"]
        current = (policy.LOG if best and best["suppressed"]
                   else best["decision"] if best else None)
        if best is None or order[effective] > order[current]:
            best = resolution
    return best, resolutions


@hookio.guard(hookio.FAIL_CLOSED, HOOK)
def main():
    data = hookio.read()
    if data.get("hook_event_name") != "PreToolUse":
        hookio.passthrough()
    if data.get("tool_name") != "Bash":
        hookio.passthrough()

    command = (data.get("tool_input") or {}).get("command")
    if not isinstance(command, str) or not command.strip():
        hookio.passthrough()

    cwd = data.get("cwd") or os.getcwd()
    session_id = data.get("session_id")
    agent_id = data.get("agent_id")

    cmds, warnings = cmdparse.parse(command)
    matches = collect_matches(command, cmds, cwd)
    best, resolutions = decide(matches, session_id, agent_id)

    for resolution in resolutions[:MAX_AUDIT_RECORDS]:
        rule = resolution["rule"]
        audit.write({
            "hook": HOOK,
            "rule": rule["id"],
            "class": rule.get("class"),
            "severity": rule.get("severity"),
            "level": resolution["level"],
            "action": ("logged" if resolution["exempt"]
                       else policy.audit_action(resolution["decision"],
                                                resolution["suppressed"])),
            "target": resolution["target"],
            "evidence": command,
            "latency_ms": hookio.elapsed_ms(),
        }, data)

    # Команда не разобрана: пропускать её нельзя, но и блокировать баг парсера
    # тоже нельзя — решение отдаётся человеку (ARCHITECTURE §4.1).
    #
    # ВАЖНО: этот gate раньше срабатывал только при config.level()=="strict",
    # то есть на дефолтном уровне "audit" неразобранная команда (например,
    # `RM=rm; $RM -rf /`, дающая предупреждение argv0_is_variable) проходила
    # молча — fail-closed был объявлен, но не действовал ни разу вне strict.
    # Эскалация не зависит от уровня политики: сам факт «статически неизвестно,
    # что выполнится» — это про парсер, а не про то, насколько строго сейчас
    # настроен плагин.
    unresolved = [w for w in warnings
                  if w in ESCALATING_WARNINGS or w.startswith("parse_error")]
    if unresolved and (best is None or best["decision"] in (policy.LOG, policy.WARN)):
        audit.write({
            "hook": HOOK, "rule": "PARSER_UNRESOLVED", "class": "internal",
            "severity": "MEDIUM", "level": config.level(), "action": "asked",
            "target": None, "evidence": command,
            "latency_ms": hookio.elapsed_ms(),
        }, data)
        hookio.ask("PreToolUse",
                   "secure-dev: команда собирается динамически, статически "
                   "проверить её невозможно. Подтвердите, если она ожидаема.")

    if best is None or best["exempt"] is not None or best["suppressed"]:
        hookio.passthrough()

    rule = best["rule"]
    detail = rule.get("message", "")
    cmd = best.get("cmd")
    if cmd is not None and cmd.raw:
        detail += "\nСработало на: {}".format(cmd.raw[:200])

    decision = best["decision"]
    if decision == policy.DENY:
        hookio.deny("PreToolUse", policy.format_reason(
            rule, detail, escalation=not policy.is_final(rule["severity"], decision)))
    if decision == policy.ASK:
        hookio.ask("PreToolUse", policy.format_reason(rule, detail))
    if decision == policy.WARN:
        hookio.warn("secure-dev [{}]: {}".format(rule["id"], rule.get("message", "")))
    hookio.passthrough()


if __name__ == "__main__":
    main()
