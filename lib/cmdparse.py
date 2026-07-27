#!/usr/bin/env python3
"""cmdparse.py — семантический разбор shell-команды (TS.md §7, ADR-002).

Regex-блэклист обходится тривиально: `rm -fr /`, `rm --recursive --force /`,
`RM=rm; $RM -rf /`, `bash -c 'rm -rf /'`, `echo cm0gLXJmIC8= | base64 -d | sh`.
Поэтому здесь строится дерево вызовов: разбираются списки, пайпы и подстановки,
раскрываются обёртки-интерпретаторы, флаги нормализуются до канонического вида.

Целевая платформа — bash в WSL (ADR-007). Разбор cmd.exe и PowerShell не
реализуется: это второй лексер, другая модель кавычек и удвоение корпуса
тестов при нулевом приросте ценности, если WSL доступен всем.

Контракт устойчивости: `parse()` НИКОГДА не бросает исключение. Любая
внутренняя ошибка превращается в предупреждение, а непустые предупреждения при
fail-closed эскалируются в `ask`. Иначе атакующий подбирает вход, роняющий
парсер, и получает обход (ADR-002).
"""

import os
import re
from dataclasses import dataclass, field

MAX_DEPTH = 6
MAX_COMMANDS = 256

DIRECT = "direct"
SUBSHELL = "subshell"
INTERPRETER = "interpreter"
PIPE = "pipe"

CONTROL_OPS = (";;", "&&", "||", ";", "|&", "|", "&", "\n")
REDIR_RE = re.compile(r"^(?:\d*(?:>>|>\||>&|>|<<<|<<|<&|<))$")

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php",
    "deno", "bun",
}
# Обёртки, которые сами по себе безобидны, но прячут за собой настоящую команду.
# sudo/doas/pkexec тоже раскрываются, но, в отличие от прочих, остаются в
# результате как отдельный Cmd — правило command-sudo обязано их увидеть.
WRAPPERS = {
    "env": {"value_flags": {"-u", "--unset", "-S", "--split-string"},
            "skip_assignments": True},
    "command": {"value_flags": set()},
    "builtin": {"value_flags": set()},
    "exec": {"value_flags": set()},
    "nohup": {"value_flags": set()},
    "setsid": {"value_flags": set()},
    "stdbuf": {"value_flags": {"-i", "-o", "-e"}},
    "nice": {"value_flags": {"-n"}},
    "ionice": {"value_flags": {"-c", "-n", "-p"}},
    "time": {"value_flags": {"-o", "-f"}},
    "timeout": {"value_flags": {"-s", "--signal", "-k"}, "skip_numeric": True},
    "xargs": {"value_flags": {"-n", "-P", "-I", "-d", "-a", "-E", "-s"}},
    "sudo": {"value_flags": {"-u", "-g", "-p", "-C", "-h", "-U", "-r", "-t"},
             "keep": True},
    "doas": {"value_flags": {"-u", "-C"}, "keep": True},
    "pkexec": {"value_flags": {"--user"}, "keep": True},
}

# Канонизация флагов (TS.md §7.3). Незнакомая команда — флаги не нормализуются,
# Cmd строится как есть, и правила по argv0 продолжают работать.
FLAG_ALIASES = {
    "rm": {"-r": "--recursive", "-R": "--recursive", "-f": "--force",
           "-i": "--interactive", "-d": "--dir", "-v": "--verbose"},
    "cp": {"-r": "--recursive", "-R": "--recursive", "-f": "--force",
           "-a": "--archive"},
    "mv": {"-f": "--force", "-n": "--no-clobber"},
    "git": {"-f": "--force", "-D": "--delete-force", "-d": "--delete",
            "-n": "--dry-run"},
    "chmod": {"-R": "--recursive", "-f": "--silent"},
    "chown": {"-R": "--recursive"},
    "find": {"-delete": "--delete", "-exec": "--exec", "-execdir": "--exec"},
    "tar": {"-x": "--extract", "-c": "--create", "-f": "--file"},
    "curl": {"-o": "--output", "-O": "--remote-name", "-s": "--silent",
             "-H": "--header", "-d": "--data", "-X": "--request"},
    "wget": {"-O": "--output-document", "-q": "--quiet"},
    "base64": {"-d": "--decode", "-D": "--decode"},
    "xxd": {"-r": "--revert"},
    "openssl": {"-d": "--decrypt"},
    "shred": {"-u": "--remove", "-z": "--zero"},
}

# Флаги, забирающие следующий аргумент: без этого значение флага попало бы в
# operands и, например, `git commit -m "/tmp/x"` выглядел бы как операция над
# путём вне рабочего каталога.
VALUE_FLAGS = {
    "git": {"-m", "-C", "-c", "--message", "--work-tree", "--git-dir"},
    "curl": {"-H", "-d", "-X", "-o", "-u", "--header", "--data", "--request",
             "--output", "--user"},
    "wget": {"-O", "--output-document", "--header"},
    "ssh": {"-i", "-p", "-o", "-l"},
    "tar": {"-f", "--file", "-C"},
    "grep": {"-e", "-f", "--include", "--exclude"},
    "sed": {"-e", "-f", "-i"},
    "awk": {"-v", "-f"},
    "docker": {"-e", "-v", "--name", "-p", "--env", "--volume"},
    "openssl": {"-in", "-out", "-k", "-K", "-iv"},
}

# Признаки исполнения команды из кода интерпретатора (TS.md §7.2).
INTERPRETER_EXEC_RE = re.compile(
    r"os\.system|os\.popen|os\.exec|subprocess|Popen|child_process|execSync|"
    r"execFileSync|spawnSync|\bexec\s*\(|\bsystem\s*\(|Runtime\.getRuntime|"
    r"IO\.popen|Kernel\.system|shell_exec|passthru|popen\s*\(",
    re.IGNORECASE)
STRING_LITERAL_RE = re.compile(r"'([^'\n]{2,400})'|\"([^\"\n]{2,400})\"")


@dataclass(frozen=True)
class Cmd:
    """Одна простая команда в дереве вызовов.

    `origin` отвечает на вопрос «как мы сюда попали»: direct — прямой вызов,
    subshell — подстановка или `bash -c`, interpreter — извлечено из кода
    python/node/perl, pipe — команда справа от пайпа. Правила опираются на это
    поле: `sh` с origin="pipe" подозрителен сам по себе.
    """
    argv0: str
    args: tuple = ()
    flags: frozenset = frozenset()
    operands: tuple = ()
    depth: int = 0
    origin: str = DIRECT
    raw: str = ""
    pipeline: int = 0
    position: int = 0
    upstream: tuple = ()
    downstream: tuple = ()
    redirects: tuple = ()
    assignments: tuple = ()
    var_argv0: bool = False


@dataclass
class _Word:
    text: str = ""
    subs: list = field(default_factory=list)     # тексты $( ) и `` внутри слова
    has_var: bool = False
    quoted: bool = False


# --- Лексер ----------------------------------------------------------------

def _tokenize(text):
    """Строка → список токенов: ('word', _Word) либо ('op', str).

    Кавычки, экранирование, подстановки и управляющие операторы разбираются
    здесь; всё остальное — уже работа со списком токенов.
    """
    tokens = []
    word = None
    i, n = 0, len(text)

    def flush():
        nonlocal word
        if word is not None:
            tokens.append(("word", word))
            word = None

    def start():
        nonlocal word
        if word is None:
            word = _Word()
        return word

    while i < n:
        ch = text[i]

        if ch in " \t\r":
            flush()
            i += 1
            continue

        if ch == "\n":
            flush()
            tokens.append(("op", "\n"))
            i += 1
            continue

        if ch == "\\":
            if i + 1 < n:
                nxt = text[i + 1]
                if nxt == "\n":
                    i += 2
                    continue
                w = start()
                w.text += nxt
                i += 2
            else:
                i += 1
            continue

        if ch == "'":
            j = text.find("'", i + 1)
            if j == -1:
                j = n
            w = start()
            w.text += text[i + 1:j]
            w.quoted = True
            i = j + 1
            continue

        if ch == '"':
            i, w = _scan_double(text, i, start())
            w.quoted = True
            continue

        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            inner, i = _scan_balanced(text, i + 2, "(", ")")
            start().subs.append(inner)
            continue

        if ch == "`":
            j = _find_unescaped(text, i + 1, "`")
            start().subs.append(text[i + 1:j])
            i = j + 1
            continue

        if ch == "$":
            i, _ = _scan_variable(text, i, start())
            continue

        matched_op = None
        for op in CONTROL_OPS:
            if text.startswith(op, i):
                matched_op = op
                break
        if matched_op:
            flush()
            tokens.append(("op", matched_op))
            i += len(matched_op)
            continue

        if ch in "()":
            flush()
            tokens.append(("op", ch))
            i += 1
            continue

        w = start()
        w.text += ch
        i += 1

    flush()
    return tokens


def _scan_double(text, i, word):
    """Двойные кавычки: внутри работают \\, $( ) и обратные кавычки."""
    i += 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            word.text += text[i + 1]
            i += 2
            continue
        if ch == '"':
            return i + 1, word
        if ch == "$" and i + 1 < n and text[i + 1] == "(":
            inner, i = _scan_balanced(text, i + 2, "(", ")")
            word.subs.append(inner)
            continue
        if ch == "`":
            j = _find_unescaped(text, i + 1, "`")
            word.subs.append(text[i + 1:j])
            i = j + 1
            continue
        if ch == "$":
            i, _ = _scan_variable(text, i, word)
            continue
        word.text += ch
        i += 1
    return i, word


def _scan_variable(text, i, word):
    """`$VAR` и `${VAR}` остаются в тексте слова как есть: подставить их
    статически невозможно, но увидеть переменную в позиции команды — нужно."""
    n = len(text)
    if i + 1 < n and text[i + 1] == "{":
        j = text.find("}", i + 2)
        if j == -1:
            j = n - 1
        word.text += text[i:j + 1]
        word.has_var = True
        return j + 1, word
    j = i + 1
    while j < n and (text[j].isalnum() or text[j] == "_"):
        j += 1
    if j == i + 1:                     # одиночный `$` — обычный символ
        word.text += "$"
        return i + 1, word
    word.text += text[i:j]
    word.has_var = True
    return j, word


def _scan_balanced(text, i, open_ch, close_ch):
    """Содержимое $( ) с учётом вложенности и кавычек."""
    depth, start, n = 1, i, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            j = text.find("'", i + 1)
            i = (j + 1) if j != -1 else n
            continue
        if ch == '"':
            j = _find_unescaped(text, i + 1, '"')
            i = j + 1
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return text[start:], n


def _find_unescaped(text, i, target):
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == target:
            return i
        i += 1
    return n


# --- Разбор ----------------------------------------------------------------

def parse(command):
    """(команды, предупреждения).

    Непустые предупреждения при fail-closed → эскалация в `ask` (TS.md §7.1).
    Исключений не бросает никогда: сбой парсера сам становится предупреждением.
    """
    if not isinstance(command, str) or not command.strip():
        return [], []
    state = {"warnings": []}
    try:
        cmds = _parse_text(command, 0, DIRECT, state)
    except RecursionError:
        return [], ["recursion_limit"]
    except Exception as exc:                     # инвариант: парсер не падает
        return [], ["parse_error:{}".format(type(exc).__name__)]
    return cmds, state["warnings"]


def _parse_text(text, depth, origin, state):
    if depth > MAX_DEPTH:
        state["warnings"].append("max_depth_exceeded")
        return []
    tokens = _tokenize(text)
    groups = _split_pipelines(tokens)

    out = []
    for pipeline_index, group in enumerate(groups):
        stage_cmds = []
        for position, stage in enumerate(group):
            stage_cmds.append(_build(stage, depth, origin, position,
                                     pipeline_index, state))
        argv0s = [built[0].argv0 if built else None for built in stage_cmds]
        for position, built in enumerate(stage_cmds):
            if not built:
                continue
            head, extra = built
            out.append(_with_pipeline(head, argv0s, position, len(group)))
            out.extend(extra)
            if len(out) > MAX_COMMANDS:
                state["warnings"].append("too_many_commands")
                return out
    return out


def _with_pipeline(cmd, argv0s, position, size):
    """Проставить соседей по пайпу и origin=pipe для не-первой стадии."""
    upstream = tuple(a for a in argv0s[:position] if a)
    downstream = tuple(a for a in argv0s[position + 1:] if a)
    origin = PIPE if (position > 0 and size > 1 and cmd.origin == DIRECT) else cmd.origin
    return _replace(cmd, upstream=upstream, downstream=downstream, origin=origin)


def _replace(cmd, **kw):
    data = {f: getattr(cmd, f) for f in cmd.__dataclass_fields__}
    data.update(kw)
    return Cmd(**data)


def _split_pipelines(tokens):
    """Токены → список пайплайнов, каждый — список стадий (списков слов)."""
    groups, pipeline, stage = [], [], []
    for kind, value in tokens:
        if kind == "word":
            stage.append(value)
            continue
        if value in ("|", "|&"):
            pipeline.append(stage)
            stage = []
            continue
        pipeline.append(stage)
        if any(pipeline):
            groups.append([s for s in pipeline if s])
        pipeline, stage = [], []
    pipeline.append(stage)
    if any(pipeline):
        groups.append([s for s in pipeline if s])
    return groups


def _build(words, depth, origin, position, pipeline_index, state):
    """Список слов одной стадии → (Cmd, [дополнительные Cmd])."""
    words, redirects = _strip_redirects(words)
    assignments, words = _strip_assignments(words)
    if not words:
        return None
    head, rest = words[0], words[1:]

    argv0, var_argv0, extra = _resolve_argv0(head, depth, origin, state)
    args = tuple(_render(w) for w in rest)
    raw = " ".join([argv0] + list(args))

    flags, operands = _split_flags(argv0, args)
    cmd = Cmd(argv0=argv0, args=args, flags=flags, operands=operands,
              depth=depth, origin=origin, raw=raw, pipeline=pipeline_index,
              position=position, redirects=tuple(redirects),
              assignments=tuple(assignments), var_argv0=var_argv0)

    # Подстановки внутри аргументов — отдельные команды глубже уровнем.
    for word in words:
        for sub in word.subs:
            extra.extend(_parse_text(sub, depth + 1, SUBSHELL, state))

    extra.extend(_expand(cmd, args, depth, state))
    return cmd, extra


def _strip_redirects(words):
    """Цели перенаправлений — не операнды команды."""
    out, redirects, skip = [], [], False
    for word in words:
        text = word.text
        if skip:
            redirects.append(text)
            skip = False
            continue
        if REDIR_RE.match(text) and not word.quoted:
            skip = True
            continue
        m = re.match(r"^(\d*(?:>>|>\||>&|>|<))(.+)$", text)
        if m and not word.quoted and not word.subs:
            redirects.append(m.group(2))
            continue
        out.append(word)
    return out, redirects


def _strip_assignments(words):
    """`FOO=1 git push` → префикс отброшен, argv0="git" (TS.md §7.2)."""
    assignments, i = [], 0
    while i < len(words):
        text = words[i].text
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", text) and not words[i].subs:
            assignments.append(text)
            i += 1
            continue
        break
    return assignments, words[i:]


def _render(word):
    """Текст аргумента для правил.

    Подстановка внутри операнда отмечается маркером `$()`: значение статически
    неизвестно, но сам факт «цель вычисляется на лету» — сигнал. Без маркера
    `rm -rf $(echo /)` дал бы команду вовсе без операндов и прошёл бы мимо
    правил по цели.
    """
    return word.text + "$()" * len(word.subs)


def _resolve_argv0(word, depth, origin, state):
    """Имя команды: basename, без пути и без экранирования.

    `\\sudo`, `/usr/bin/sudo` и `$(which sudo)` должны дать одинаковый argv0 —
    иначе обход правила command-sudo стоит одного символа.
    """
    extra = []
    text = word.text.strip()

    if not text and word.subs:
        # Команда целиком получена подстановкой. Единственный случай, который
        # разрешается статически, — `$(which X)` / `$(command -v X)`.
        inner = _parse_text(word.subs[0], depth + 1, SUBSHELL, state)
        resolved = None
        for cmd in inner:
            if cmd.argv0 in ("which", "type", "whereis") and cmd.operands:
                resolved = cmd.operands[0]
                break
            if cmd.argv0 == "command" and "-v" in cmd.args and cmd.operands:
                resolved = cmd.operands[0]
                break
        extra.extend(inner)
        if resolved:
            return _basename(resolved), False, extra
        state["warnings"].append("argv0_from_substitution")
        return "unknown", True, extra

    if word.has_var and text.startswith("$"):
        # Динамически собранные команды статически неразрешимы (TS.md §7.4).
        # Это документируется, а не «чинится»: предупреждение → ask.
        state["warnings"].append("argv0_is_variable")
        return _basename(text), True, extra

    return _basename(text), word.has_var, extra


def _basename(text):
    text = text.strip().lstrip("\\")
    if not text:
        return "unknown"
    return os.path.basename(text.rstrip("/")) or text


def _split_flags(argv0, args):
    """Флаги → канонические длинные имена, остальное → операнды."""
    aliases = FLAG_ALIASES.get(argv0, {})
    value_flags = VALUE_FLAGS.get(argv0, set())
    flags, operands = set(), []
    end_of_flags = False
    skip_next = False

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if end_of_flags:
            operands.append(arg)
            continue
        if arg == "--":
            end_of_flags = True
            continue
        if arg in aliases:
            flags.add(aliases[arg])
            continue
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            flags.add(aliases.get(name, name))
            if arg in value_flags:
                skip_next = True
            continue
        if arg.startswith("-") and len(arg) > 1 and not _looks_negative_number(arg):
            if arg in value_flags:
                flags.add(aliases.get(arg, arg))
                skip_next = True
                continue
            # Разгруппировка `-rf` → `-r` `-f`; неизвестные буквы сохраняются
            # как короткие флаги, чтобы правило по argv0 всё равно сработало.
            for letter in arg[1:]:
                short = "-" + letter
                flags.add(aliases.get(short, short))
            continue
        operands.append(arg)

    return frozenset(flags), tuple(operands)


def _looks_negative_number(arg):
    return bool(re.match(r"^-\d+$", arg))


def _expand(cmd, args, depth, state):
    """Раскрытие обёрток, шеллов и интерпретаторов."""
    out = []

    inner_argv = _unwrap(cmd.argv0, args)
    if inner_argv:
        out.extend(_parse_text(" ".join(_quote(a) for a in inner_argv),
                               depth, cmd.origin, state))

    if cmd.argv0 in SHELLS:
        code = _flag_value(args, ("-c",))
        if code:
            out.extend(_parse_text(code, depth + 1, SUBSHELL, state))

    if cmd.argv0 in INTERPRETERS:
        code = _flag_value(args, ("-c", "-e", "-E", "--eval", "--print"))
        if code and INTERPRETER_EXEC_RE.search(code):
            # Полный разбор чужого языка не задача плагина: фиксируем факт
            # исполнения команды из кода и пытаемся вытащить строковые литералы.
            state["warnings"].append("interpreter_exec")
            out.append(Cmd(argv0="unknown", args=(), flags=frozenset(),
                           operands=(), depth=depth + 1, origin=INTERPRETER,
                           raw=code[:200]))
            for literal in _literals(code):
                out.extend(_parse_text(literal, depth + 1, INTERPRETER, state))
    return out


def _unwrap(argv0, args):
    """`env sudo rm -rf /` → внутренняя команда `sudo rm -rf /`."""
    spec = WRAPPERS.get(argv0)
    if not spec:
        return None
    rest = list(args)
    skip_numeric = spec.get("skip_numeric", False)
    while rest:
        arg = rest[0]
        if spec.get("skip_assignments") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", arg):
            rest.pop(0)
            continue
        if arg in spec.get("value_flags", ()):
            rest = rest[2:]
            continue
        if arg.startswith("-") and len(arg) > 1:
            rest.pop(0)
            continue
        if skip_numeric and re.match(r"^\d+(?:\.\d+)?[smhd]?$", arg):
            rest.pop(0)
            skip_numeric = False
            continue
        break
    return rest or None


def _flag_value(args, names):
    for i, arg in enumerate(args):
        if arg in names and i + 1 < len(args):
            return args[i + 1]
        for name in names:
            if arg.startswith(name + "="):
                return arg[len(name) + 1:]
    return None


def _literals(code):
    for match in STRING_LITERAL_RE.finditer(code):
        value = match.group(1) or match.group(2) or ""
        if value.strip():
            yield value


def _quote(value):
    if not value or re.search(r"[\s\"'$`\\|&;<>()]", value):
        return "'" + value.replace("'", "'\\''") + "'"
    return value


# --- Помощники для правил --------------------------------------------------

def expand_operand(operand, cwd):
    """Абсолютный путь операнда с раскрытием `~`, `..` и симлинков."""
    if not operand:
        return operand
    value = os.path.expanduser(os.path.expandvars(operand))
    if not os.path.isabs(value):
        value = os.path.join(cwd or os.getcwd(), value)
    try:
        return os.path.realpath(value)
    except OSError:
        return os.path.normpath(value)


def outside_cwd(operand, cwd):
    """Операнд указывает за пределы рабочего каталога.

    Сравнение по realpath: `../../..` и симлинк наружу должны считаться
    выходом, иначе проверка обходится одной ссылкой.
    """
    if not operand or not cwd:
        return False
    try:
        root = os.path.realpath(cwd)
        target = expand_operand(operand, cwd)
    except OSError:
        return True                              # не смогли проверить → «вне»
    return not (target == root or target.startswith(root + os.sep))


def flatten(cmds):
    """Плоский список argv0 для быстрых проверок в тестах и отчётах."""
    return [c.argv0 for c in cmds]
