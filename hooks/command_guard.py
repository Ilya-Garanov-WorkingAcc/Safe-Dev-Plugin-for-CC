#!/usr/bin/env python3
"""command_guard.py — блокировка деструктивных команд (TS.md §8, P0).

Закрывает T4 (разрушение машины), T5 (потеря работы в git), T8 (эскалация до
root), T9 (персистентность через shell-конфиг).

Режим отказа — CLOSED. Если разбор не удался, хук обязан вернуть `ask`, а не
пропустить: иначе атакующему достаточно подобрать вход, роняющий парсер.
Промежуточный режим — именно `ask`, а не `deny`: баг плагина не должен
останавливать работу команды.
"""

import dataclasses
import fnmatch
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, cmdparse, config, hookio, policy, ruleset  # noqa: E402

HOOK = "command_guard"
MAX_AUDIT_RECORDS = 8

# Прозрачность скриптов: команда `bash deploy/e2e-test.sh` сама по себе
# безобидна, опасно содержимое файла. Файл читается и разбирается теми же
# правилами — один уровень вглубь, с ограничением размера, чтобы уложиться в
# бюджет PreToolUse. Инцидент 18.09.2026: rsync --delete с назначением `~`
# был внутри тестового скрипта деплоя, и по командной строке его не видно.
SCRIPT_MAX_BYTES = 256 * 1024
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
SCRIPT_SHEBANG_RE = re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:\S*/)?(?:ba|z|k|da|a)?sh\b")

# Назначение вычисляется на лету: подстановка, обратные кавычки, переменная
# (`"$HOME/$EMPTY/"` при пустой переменной — это `~/`), пустая строка.
DYNAMIC_DEST_RE = re.compile(r"\$\(\)|`|\$\{?[A-Za-z_]")

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
    positional = [op for op in cmd.operands if not op.startswith("-")]
    # Назначение — последний позиционный операнд (rsync, cp, mv, tar -C — нет,
    # у tar это значение флага, см. правило по args_regex_any).
    dest = positional[-1] if len(positional) >= 2 else None
    dest_expanded = cmdparse.expand_operand(dest, cwd) if dest else None
    return {
        "expanded_operands": expanded,
        "expanded_redirects": expanded_redirects,
        "has_operand_outside_cwd": any(
            cmdparse.outside_cwd(op, cwd) for op in cmd.operands
            if not op.startswith("-")),
        "has_root_target": any(_is_root_target(raw, exp, cwd)
                               for raw, exp in zip(cmd.operands, expanded)),
        "branch_protected": _branch_protected(cmd, cwd),
        "dest": dest or "",
        "dest_root": bool(dest) and _is_root_target(dest, dest_expanded, cwd),
        "dest_outside_cwd": bool(dest) and cmdparse.outside_cwd(dest, cwd),
        "dest_dynamic": dest is not None and (dest == "" or
                                              bool(DYNAMIC_DEST_RE.search(dest))),
    }


def script_path(cmd, cwd):
    """Путь к shell-скрипту, который выполняет команда, либо None.

    Три формы: явный интерпретатор (`bash x.sh`, `sh -x x.sh`), прямой запуск
    файла (`./x.sh`, `/opt/app/deploy.sh`) и подключение (`source x.sh`).
    `bash -c '...'` сюда не попадает — код уже разобран парсером.
    """
    candidate = None
    if cmd.argv0 in cmdparse.SHELLS or cmd.argv0 in ("source", "."):
        if "-c" in cmd.flags:
            return None
        positional = [op for op in cmd.operands if not op.startswith("-")]
        candidate = positional[0] if positional else None
    elif "/" in cmd.argv0_text or cmd.argv0_text.endswith(SCRIPT_SUFFIXES):
        candidate = cmd.argv0_text
    if not candidate or "$()" in candidate or candidate.startswith("-"):
        return None
    path = cmdparse.expand_operand(candidate, cwd)
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > SCRIPT_MAX_BYTES:
            return None
        with open(path, "rb") as fh:
            head = fh.read(200)
    except OSError:
        return None
    if b"\x00" in head:
        return None                                   # бинарник, не скрипт
    first = head.split(b"\n", 1)[0].decode("utf-8", "replace")
    if (cmd.argv0 in cmdparse.SHELLS or cmd.argv0 in ("source", ".")
            or path.endswith(SCRIPT_SUFFIXES) or SCRIPT_SHEBANG_RE.match(first)):
        return path
    return None


def script_commands(cmds, cwd):
    """Команды из файлов скриптов, которые запускает командная строка.

    Один уровень вглубь: скрипт, вызывающий скрипт, дальше не раскрывается —
    бюджет PreToolUse важнее полноты, а первый уровень закрывает типовой
    случай «агент написал скрипт и запустил его».
    """
    extra = []
    seen = set()
    for cmd in cmds:
        path = script_path(cmd, cwd)
        if not path or path in seen:
            continue
        seen.add(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(SCRIPT_MAX_BYTES)
        except OSError:
            continue
        inner, _warnings = cmdparse.parse(text)
        label = os.path.relpath(path, cwd) if cwd else path
        for c in inner:
            extra.append(dataclasses.replace(
                c, origin=cmdparse.SCRIPT, depth=c.depth + 1,
                raw="{}: {}".format(label, c.raw)))
    return extra


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
        dest_rule = any(k.startswith("dest_") for k in rule["match"])
        for cmd in cmds:
            ctx = build_context(cmd, cwd)
            if ruleset.match_command(cmd, rule, ctx):
                if dest_rule and ctx.get("dest"):
                    target = ctx["dest"]
                else:
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
    # Предупреждения парсера из файлов скриптов не эскалируются: в любом
    # install.sh полно `$CMD "$@"`, и ask на каждый такой запуск — ложное
    # срабатывание. Правила по разобранным командам скрипта действуют в полную
    # силу, а всё динамическое в НАЗНАЧЕНИИ синхронизации ловит dest_dynamic.
    cmds = cmds + script_commands(cmds, cwd)
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
