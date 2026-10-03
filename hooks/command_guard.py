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
import glob as _glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import audit, cmdparse, config, hookio, policy, ruleset  # noqa: E402

HOOK = "command_guard"
MAX_AUDIT_RECORDS = 8
# Команда длиннее — `ask` без разбора: анализ мегабайтного ввода не уложится
# в бюджет хука, а пропускать непроверенное нельзя.
MAX_COMMAND_BYTES = 512 * 1024
# Код (без тел heredoc-данных) длиннее — `ask` после разбора: в таком объёме
# опасную команду проще спрятать, чем найти.
MAX_CODE_BYTES = 16 * 1024
# Раскрывать через realpath больше операндов бессмысленно дорого; остальные
# считаются «вне рабочего каталога» — консервативно.
MAX_EXPANDED_OPERANDS = 64

# Прозрачность скриптов: команда `bash deploy/e2e-test.sh` сама по себе
# безобидна, опасно содержимое файла. Файл читается и разбирается теми же
# правилами — до трёх уровней вглубь, с общим лимитом объёма, чтобы уложиться
# в бюджет PreToolUse. Инцидент 18.09.2026: rsync --delete с назначением `~`
# был внутри тестового скрипта деплоя, и по командной строке его не видно.
SCRIPT_MAX_BYTES = 256 * 1024
SCRIPT_TOTAL_BYTES = 512 * 1024
SCRIPT_MAX_LEVELS = 3
SCRIPT_GLOB_LIMIT = 8
# Команды, способные создать файл, который та же строка затем исполняет:
# `curl -o x.sh … && bash x.sh`, `git clone … && ./repo/install.sh`.
PRODUCERS = {"curl", "wget", "aria2c", "git", "tar", "unzip", "7z", "bsdtar",
             "cp", "mv", "ln", "install", "scp", "rsync", "gh"}
SCRIPT_SUFFIXES = cmdparse.SCRIPT_SUFFIXES
SCRIPT_SHEBANG_RE = cmdparse.SCRIPT_SHEBANG_RE

# Назначение вычисляется на лету: подстановка, обратные кавычки, переменная
# (`"$HOME/$EMPTY/"` при пустой переменной — это `~/`), пустая строка.
DYNAMIC_DEST_RE = re.compile(r"\$\(\)|`|\$\{?[A-Za-z_]")

# Предупреждения парсера, при которых команда считается неразобранной.
# Все они означают одно: статически неизвестно, что будет выполнено.
ESCALATING_WARNINGS = {
    "argv0_is_variable", "argv0_from_substitution", "interpreter_exec",
    "max_depth_exceeded", "too_many_commands", "recursion_limit",
    "source_unresolved", "shell_c_unresolved", "heredoc_unresolved",
    "command_too_long", "argv0_dynamic", "ifs_split", "shell_stdin_unresolved",
    "script_unresolved",
}

_ROOT_LITERALS = {"/", "/.", "/*", "/**", "~", "~/", "~/*", "$HOME", "${HOME}",
                  "$HOME/", "$HOME/*", "${HOME}/*", "..", "../", "../*", "../.."}
_GLOB_TAIL_RE = re.compile(r"(?:/(?:\*\*?|\.\*|\.\[!.\]\*))+/?$")


def build_context(cmd, cwd):
    """Контекст для матчера: то, что знает хук, но не знает парсер.

    Цели раскрываются от каталога, в который команду привёл `cd` раньше в
    той же строке (`cd / && rm -rf *` — это `rm -rf /*`), а «вне проекта»
    по-прежнему считается относительно каталога, из которого запущена вся
    строка.
    """
    base = cmdparse.effective_cwd(cmd, cwd)
    cwd_known = base is not None
    base = base or cwd
    operands = [op for op in cmd.operands[:MAX_EXPANDED_OPERANDS]
                if not cmdparse.is_mktemp_path(op)]
    truncated = len(cmd.operands) > MAX_EXPANDED_OPERANDS
    expanded = [cmdparse.expand_operand(_target_dir(op), base) for op in operands]
    expanded_redirects = [cmdparse.expand_operand(r, base)
                          for r in cmd.redirects[:MAX_EXPANDED_OPERANDS]]
    positional = [op for op in cmd.operands if not op.startswith("-")]
    # Назначение — последний позиционный операнд (rsync, cp, mv, tar -C — нет,
    # у tar это значение флага, см. правило по args_regex_any).
    dest = positional[-1] if len(positional) >= 2 else None
    if dest is not None and cmdparse.is_mktemp_path(dest):
        dest = None
    dest_expanded = cmdparse.expand_operand(_target_dir(dest), base) if dest else None
    pairs = [(raw, exp) for raw, exp in zip(operands, expanded)
             if not raw.startswith("-")]
    return {
        "expanded_operands": expanded,
        "expanded_redirects": expanded_redirects,
        "has_operand_outside_cwd": truncated or any(
            _outside(exp, cwd) for _, exp in pairs),
        "has_root_target": any(_is_root_target(raw, exp, cwd) for raw, exp in pairs),
        "exempt_targets": _exempt_targets(pairs, cwd, truncated),
        "operand_dynamic": not cwd_known and any(
            not raw.startswith(("/", "~")) for raw, _ in pairs),
        "cwd_unsafe": _unsafe_cwd(base),
        "branch_protected": _branch_protected(cmd, cwd),
        "dest": dest or "",
        "dest_root": bool(dest) and _is_root_target(dest, dest_expanded, cwd),
        "dest_outside_cwd": bool(dest) and _outside(dest_expanded, cwd),
        "dest_dynamic": dest is not None and (dest == "" or not cwd_known or
                                              bool(DYNAMIC_DEST_RE.search(dest))),
    }


def _target_dir(raw):
    """Каталог, который затрагивает цель с глобом на конце.

    `rm -rf /home/*` удаляет содержимое /home — по смыслу это цель `/home`;
    `rm -rf *` — содержимое текущего каталога. Без этого `/home/*` раскрывался
    в несуществующий путь со звёздочкой и не считался корневой целью.
    """
    if raw in ("*", "**", ".*", "./*", "./.*", "./"):
        return "."
    stripped = _GLOB_TAIL_RE.sub("", raw)
    if stripped != raw:
        return stripped or "/"
    return raw


def _outside(expanded, cwd):
    if not expanded or not cwd:
        return False
    try:
        root = os.path.realpath(cwd)
    except OSError:
        return True
    return not (expanded == root or expanded.startswith(root + os.sep))


def _unsafe_cwd(path):
    """Рабочий каталог, внутри которого «относительный путь» ничего не
    гарантирует: корень, домашний каталог или его предок. Агент, запущенный
    из `~`, иначе удалял бы `~/projects` как «файлы внутри проекта»."""
    try:
        real = os.path.realpath(path or os.getcwd())
        home = os.path.realpath(os.path.expanduser("~"))
    except OSError:
        return True
    return real in ("/", home) or home.startswith(real.rstrip("/") + os.sep)


def _exempt_targets(pairs, cwd, truncated):
    """Цели, с которыми сверяется исключение из политики.

    Пустой список — «исключение неприменимо»; None здесь не возвращается
    (None означает вызывающего, который цели не раскрывал).

    Исключение `**/node_modules/**` раньше проверялось по первому операнду как
    написано: `rm -rf /tmp/a/node_modules/x /tmp/victim` и
    `rm -rf /tmp/node_modules/../victim` проходили. Теперь исключению должен
    удовлетворять КАЖДЫЙ операнд вне рабочего каталога, причём в раскрытом
    виде; `..` в операнде исключение отменяет вовсе.
    """
    if truncated:
        return []
    if any(".." in raw.split("/") or "$" in raw or "`" in raw for raw, _ in pairs):
        return []
    outside = [exp for _, exp in pairs if _outside(exp, cwd)]
    return outside or [exp for _, exp in pairs]


def script_candidates(cmd, cwd, cmds=()):
    """Файлы shell-скриптов, которые выполняет команда: (существующие, отсутствующие).

    Формы: явный шелл (`bash x.sh`, `bash -o pipefail x.sh`, `bash < x.sh`),
    прямой запуск (`./x.sh`, `/opt/app/deploy.sh`), подключение (`source x.sh`)
    и `cat x.sh | bash`. Глоб в имени (`bash ev*.sh`) раскрывается.
    `bash -c '...'` сюда не попадает — код уже разобран парсером.
    """
    base = cmdparse.effective_cwd(cmd, cwd) or cwd
    names = []
    if cmd.argv0 in cmdparse.SHELLS:
        _code, has_c, script = cmdparse.shell_invocation(cmd.args)
        if has_c:
            return [], []
        if script:
            names.append(script)
        elif cmd.stdin_file:
            names.append(cmd.stdin_file)
        elif cmd.shell_stdin and cmd.position > 0:
            for other in cmds:                       # `cat x.sh | bash`
                if (other.pipeline == cmd.pipeline and other.depth == cmd.depth
                        and other.position == cmd.position - 1
                        and other.argv0 == "cat" and other.operands):
                    names.extend(other.operands)
    elif cmd.argv0 in ("source", "."):
        positional = [op for op in cmd.operands if not op.startswith("-")]
        names.extend(positional[:1])
    elif "/" in cmd.argv0_text or cmd.argv0_text.endswith(SCRIPT_SUFFIXES):
        names.append(cmd.argv0_text)

    found, missing = [], []
    for name in names:
        if not name or "$()" in name or name.startswith("-") or "$" in name:
            continue
        path = cmdparse.expand_operand(name, base)
        paths = ([p for p in sorted(_glob.glob(path))[:SCRIPT_GLOB_LIMIT]]
                 if re.search(r"[*?\[]", name) else [path])
        for candidate in paths:
            if not os.path.isfile(candidate):
                missing.append(candidate)
                continue
            if _is_script(cmd, candidate):
                found.append(candidate)
    return found, missing


def _is_script(cmd, path):
    try:
        if os.path.getsize(path) > SCRIPT_MAX_BYTES:
            return False
        with open(path, "rb") as fh:
            head = fh.read(200)
    except OSError:
        return False
    if b"\x00" in head:
        return False                                  # бинарник, не скрипт
    first = head.split(b"\n", 1)[0].decode("utf-8", "replace")
    return (cmd.argv0 in cmdparse.SHELLS or cmd.argv0 in ("source", ".", "cat")
            or path.endswith(SCRIPT_SUFFIXES) or bool(SCRIPT_SHEBANG_RE.match(first)))


def script_commands(cmds, cwd):
    """Команды из файлов скриптов, которые запускает командная строка.

    Возвращает (команды, неразрешённые запуски). До трёх уровней вглубь
    (скрипт, вызывающий скрипт, …) с общим лимитом объёма. Неразрешённый
    запуск — скрипт, которого ещё нет, но та же строка его скачивает,
    распаковывает или копирует: проверить нечего, пропускать нельзя.
    """
    extra, unresolved = [], []
    seen, budget = set(), [SCRIPT_TOTAL_BYTES]
    written = {os.path.basename(target) for _, target in cmdparse.heredoc_scripts(cmds)}
    producer = any(c.argv0 in PRODUCERS for c in cmds)

    def visit(batch, level):
        for cmd in batch:
            found, missing = script_candidates(cmd, cwd, batch)
            if producer and cmd.origin != cmdparse.SCRIPT:
                unresolved.extend(m for m in missing
                                  if os.path.basename(m) not in written)
            for path in found:
                if path in seen or budget[0] <= 0:
                    continue
                seen.add(path)
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read(min(SCRIPT_MAX_BYTES, budget[0]))
                except OSError:
                    continue
                budget[0] -= len(text)
                inner, _warnings = cmdparse.parse(text, script_dir=os.path.dirname(path))
                label = os.path.relpath(path, cwd) if cwd else path
                nested = [dataclasses.replace(
                    c, origin=cmdparse.SCRIPT, depth=c.depth + level,
                    raw="{}: {}".format(label, c.raw)) for c in inner]
                extra.extend(nested)
                if level < SCRIPT_MAX_LEVELS:
                    visit(nested, level + 1)

    visit(cmds, 1)
    return extra, unresolved


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
    contexts = {}

    for rule in rules:
        kind = rule["match"]["kind"]
        if kind == "regex":
            # Правила по сырому тексту нужны там, где конструкция не является
            # командой в смысле argv0 — форк-бомба, работа с историей шелла.
            if ruleset.match_regex(command, rule):
                matches.append((rule, None, None, None))
            continue
        if kind != "command":
            continue
        dest_rule = any(k.startswith("dest_") for k in rule["match"])
        for index, cmd in enumerate(cmds):
            # Контекст считается один раз на команду, а не на каждую пару
            # правило × команда: realpath операндов — самая дорогая часть.
            ctx = contexts.get(index)
            if ctx is None:
                ctx = contexts[index] = build_context(cmd, cwd)
            if ruleset.match_command(cmd, rule, ctx):
                if dest_rule and ctx.get("dest"):
                    target = ctx["dest"]
                else:
                    target = (cmd.operands[0] if cmd.operands
                              else (cmd.redirects[0] if cmd.redirects else cmd.argv0))
                matches.append((rule, cmd, target, ctx.get("exempt_targets")))
                break            # одного срабатывания правила достаточно
    return matches


def _extra_rules():
    """Локальные правила сотрудника: только запрещающие, только добавляют."""
    out = []
    for rule in (config.extra_rules() or []):
        if rule.get("match", {}).get("kind") != "command":
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
    for rule, cmd, target, exempt_targets in matches:
        resolution = policy.resolve(rule, target=target, agent_id=agent_id,
                                    session_id=session_id,
                                    exempt_targets=exempt_targets)
        resolution["cmd"] = cmd
        resolution["target"] = target
        resolutions.append(resolution)
        effective = policy.LOG if resolution["suppressed"] else resolution["decision"]
        current = (policy.LOG if best and best["suppressed"]
                   else best["decision"] if best else None)
        if best is None or order[effective] > order[current]:
            best = resolution
    return best, resolutions


# Команды, выводящие данные в сеть. В «запятнанной» инъекцией сессии каждая
# такая команда с внешним адресом уходит в ask.
_EGRESS_ARGV0 = {"curl", "wget", "nc", "ncat", "socat", "scp", "sftp", "ssh",
                 "rsync", "ftp", "telnet", "http", "httpie"}
_EXTERNAL_RE = re.compile(r"https?://|ftp://|@[\w.-]+:|[\w.-]+\.[a-z]{2,}")


def _tainted_egress(data, command):
    """В сессии, помеченной инъекцией, команда отправки данных наружу → ask."""
    sid = data.get("session_id")
    if not sid:
        return False
    try:
        if not policy.state_get(sid, "injection_tainted"):
            return False
        cmds, _ = cmdparse.parse(command)
    except Exception:
        return False
    for cmd in cmds:
        if cmd.argv0 in _EGRESS_ARGV0:
            joined = " ".join(cmd.args)
            if _EXTERNAL_RE.search(joined) and "localhost" not in joined:
                return True
    return False


def _ask_tainted(data, command):
    audit.write({
        "hook": HOOK, "rule": "INJECTION_TAINTED_EGRESS", "class": "injection",
        "severity": "MEDIUM", "level": config.level(), "action": "asked",
        "target": None, "evidence": command[:512],
        "latency_ms": hookio.elapsed_ms(),
    }, data)
    hookio.ask("PreToolUse",
               "secure-dev: ранее в этой сессии в прочитанном содержимом найдены "
               "внедрённые инструкции, а эта команда отправляет данные наружу. "
               "Подтвердите, если отправка ожидаема.")


def _ask_unparsed(data, command, why):
    audit.write({
        "hook": HOOK, "rule": "PARSER_UNRESOLVED", "class": "internal",
        "severity": "MEDIUM", "level": config.level(), "action": "asked",
        "target": why, "evidence": command[:2048],
        "latency_ms": hookio.elapsed_ms(),
    }, data)
    if why == "command_too_long":
        hookio.ask("PreToolUse",
                   "secure-dev: команда слишком длинная для надёжной проверки. "
                   "Подтвердите, если она ожидаема, либо разбейте её на части.")
    hookio.ask("PreToolUse",
               "secure-dev: команда собирается динамически, статически "
               "проверить её невозможно. Подтвердите, если она ожидаема.")


@hookio.guard(hookio.FAIL_CLOSED, HOOK, default_event="PreToolUse")
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

    if len(command) > MAX_COMMAND_BYTES:
        _ask_unparsed(data, command, "command_too_long")

    if _tainted_egress(data, command):
        _ask_tainted(data, command)

    cmds, warnings = cmdparse.parse(command)
    # Предупреждения парсера из файлов скриптов не эскалируются: в любом
    # install.sh полно `$CMD "$@"`, и ask на каждый такой запуск — ложное
    # срабатывание. Правила по разобранным командам скрипта действуют в полную
    # силу, а всё динамическое в НАЗНАЧЕНИИ синхронизации ловит dest_dynamic.
    file_cmds, unresolved_scripts = script_commands(cmds, cwd)
    if unresolved_scripts:
        warnings = warnings + ["script_unresolved"]
    if "shell_stdin_unresolved" in warnings and any(
            c.shell_stdin and c.upstream and script_candidates(c, cwd, cmds)[0]
            for c in cmds):
        # `cat x.sh | bash`: файл прочитан и проверен как скрипт.
        warnings = [w for w in warnings if w != "shell_stdin_unresolved"]
    cmds = cmds + file_cmds
    # Тела heredoc, ушедшие в файл, — данные: правила по сырому тексту их не
    # видят. Запись shell-скрипта данными не считается; heredoc внутри
    # запускаемого файла скрипта подчиняется тем же условиям.
    scripts = cmdparse.heredoc_scripts(cmds)
    code = cmdparse.code_text(command, cmds, also_code=[h for h, _ in scripts])
    if len(code) > MAX_CODE_BYTES:
        warnings = warnings + ["command_too_long"]
    cmds = cmds + cmdparse.heredoc_script_commands(scripts)
    matches = collect_matches(code, cmds, cwd)
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
    # Смотрим на ДЕЙСТВУЮЩЕЕ решение: подавленное памятью сессии или снятое
    # исключением правило не должно заодно гасить эскалацию неразобранного.
    effective = (policy.LOG if best is None or best["suppressed"]
                 or best["exempt"] is not None else best["decision"])
    if unresolved and effective in (policy.LOG, policy.WARN):
        _ask_unparsed(data, command, unresolved[0])

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
