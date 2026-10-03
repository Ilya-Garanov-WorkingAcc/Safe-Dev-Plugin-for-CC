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
SCRIPT = "script"          # извлечено из файла shell-скрипта, который запускает команда

CONTROL_OPS = (";;", "&&", "||", ";", "|&", "|", "&", "\n")
# Операторы перенаправления, от длинных к коротким. `<<` (heredoc) разбирается
# отдельно; сюда он попадает, только если разделителя нет.
REDIR_OPS = ("<<<", ">>", ">|", ">&", "<&", "<>", ">", "<")

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox", "fish", "csh",
          "tcsh", "mksh", "yash"}
# Опции шелла, забирающие следующий аргумент: без этого `bash -o pipefail x.sh`
# выглядел бы как запуск скрипта `pipefail`.
SHELL_VALUE_FLAGS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}

# Текущий каталог после `cd` в цель, которую статически не определить.
CWD_UNKNOWN = "$()"
# Значение переменной, полученной из `$(mktemp …)`: свежий временный путь.
MKTEMP_PATH = "/tmp/.secure-dev-mktemp"
MKTEMP_RE = re.compile(
    r"^mktemp(?:\s+(?:-[dqu]+|--directory|--quiet|--dry-run|-t|-p\s+\S+"
    r"|--tmpdir(?:=\S+)?|--suffix=\S+|[\w./-]*X{3,}[\w./-]*))*\s*$")
# `$(dirname "$0")`, `$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)` — каталог
# самого скрипта.
SCRIPT_DIR_RE = re.compile(r"dirname[^)]*(?:\$0|\$\{0\}|BASH_SOURCE)")
VAR_REF_RE = re.compile(r"\$(?:[A-Za-z_@*#?!0-9-]|\{)")
SIMPLE_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
# Команды, меняющие переменные способом, который статически не отследить.
VAR_WRITERS = {"read", "mapfile", "readarray", "getopts", "unset", "let", "for",
               "select"}
VAR_DECLARATORS = {"export", "declare", "local", "readonly", "typeset"}
INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php",
    "deno", "bun",
}
# Обёртки, которые сами по себе безобидны, но прячут за собой настоящую команду.
# sudo/doas/pkexec тоже раскрываются, но, в отличие от прочих, остаются в
# результате как отдельный Cmd — правило command-sudo обязано их увидеть.
WRAPPERS = {
    "env": {"value_flags": {"-u", "--unset", "-S", "--split-string", "-C",
                            "--chdir"},
            "skip_assignments": True, "cluster_value": "uCS"},
    "command": {"value_flags": set()},
    "builtin": {"value_flags": set()},
    "exec": {"value_flags": {"-a"}},
    "coproc": {"value_flags": set()},
    "nohup": {"value_flags": set()},
    "setsid": {"value_flags": set()},
    "stdbuf": {"value_flags": {"-i", "-o", "-e"}},
    "nice": {"value_flags": {"-n"}},
    "ionice": {"value_flags": {"-c", "-n", "-p"}},
    "time": {"value_flags": {"-o", "-f"}},
    "timeout": {"value_flags": {"-s", "--signal", "-k"}, "skip_numeric": True},
    "xargs": {"value_flags": {"-n", "-P", "-I", "-d", "-a", "-E", "-s", "-L",
                              "--max-args", "--max-procs", "--delimiter",
                              "--arg-file", "--max-lines", "--eof"}},
    # Утилиты, которые сами ничего не делают, а запускают следующую за ними
    # команду. Аудит 03.10.2026 (P5): `chroot / rm -rf ~`, `flock x rm …`,
    # `systemd-run rm …`, `busybox rm …` проходили мимо правил.
    "busybox": {"value_flags": set()},
    "chroot": {"value_flags": {"--userspec", "--groups"}, "skip_positional": 1},
    "flock": {"value_flags": {"-w", "--timeout", "-E", "--conflict-exit-code"},
              "skip_positional": 1},
    "unshare": {"value_flags": {"-S", "-G", "--map-user", "--map-group", "-R",
                                "--root", "-w", "--wd"}},
    "nsenter": {"value_flags": {"-t", "--target", "-S", "-G", "-r", "-w"}},
    "setpriv": {"value_flags": {"--reuid", "--regid", "--groups", "--inh-caps",
                                "--ambient-caps", "--bounding-set"}},
    "strace": {"value_flags": {"-e", "-o", "-p", "-s", "-u", "-E", "-P"}},
    "ltrace": {"value_flags": {"-e", "-o", "-p", "-s", "-u"}},
    "taskset": {"value_flags": {"-p"}, "skip_positional": 1},
    "chrt": {"value_flags": {"-p"}, "skip_positional": 1},
    "systemd-run": {"value_flags": {
        "-u", "--unit", "-p", "--property", "--on-calendar", "--on-active",
        "--on-boot", "-E", "--setenv", "--working-directory", "--uid", "--gid",
        "-M", "--machine", "-H", "--host", "--slice", "--description"}},
    "runuser": {"value_flags": {"-u", "--user", "-g", "--group", "-G", "-l"}},
    "tsp": {"value_flags": {"-L", "-N"}},
    "parallel": {"value_flags": {"-j", "--jobs", "-a", "--arg-file", "-S",
                                 "--sshlogin", "--colsep", "-N", "-n"}},
    "fakeroot": {"value_flags": set()},
    "unbuffer": {"value_flags": set()},
    "torsocks": {"value_flags": set()},
    "proxychains": {"value_flags": {"-f"}},
    "proxychains4": {"value_flags": {"-f"}},
    "sudo": {"value_flags": {"-u", "-g", "-p", "-C", "-h", "-U", "-r", "-t"},
             "keep": True},
    "doas": {"value_flags": {"-u", "-C"}, "keep": True},
    "pkexec": {"value_flags": {"--user"}, "keep": True},
}

# Утилиты, исполняющие СТРОКУ с командой: значение флага — код шелла.
CODE_FLAG_WRAPPERS = {
    "script": ("-c", "--command"),
    "su": ("-c", "--command"),
    "runuser": ("-c", "--command"),
    "flock": ("-c", "--command"),
}
SSH_VALUE_FLAGS = set("-b -c -D -E -e -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w".split())
LOCAL_HOST_RE = re.compile(
    r"^(?:[^@]+@)?(?:localhost|127(?:\.\d+){3}|\[?::1\]?|0\.0\.0\.0)$")

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
    # rsync: `--del` — псевдоним --delete-during; остальные --delete-* уже длинные.
    "rsync": {"--del": "--delete-during"},
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
    # rsync: без этого `-e ssh` дал бы операнд `ssh`, а `--exclude .venv` —
    # операнд `.venv`, и назначение (последний операнд) определялось бы неверно.
    "rsync": {"-e", "--rsh", "-f", "--filter", "-T", "--temp-dir", "-B",
              "--block-size", "-M", "--remote-option", "--exclude", "--include",
              "--exclude-from", "--include-from", "--files-from", "--log-file",
              "--log-file-format", "--bwlimit", "--timeout", "--contimeout",
              "--port", "--address", "--sockopts", "--chmod", "--chown",
              "--link-dest", "--compare-dest", "--copy-dest", "--backup-dir",
              "--suffix", "--max-size", "--min-size", "--max-delete",
              "--max-alloc", "--out-format", "--info", "--debug", "--partial-dir",
              "--password-file", "--rsync-path", "--usermap", "--groupmap",
              "--checksum-choice", "--compress-choice", "--compress-level",
              "--skip-compress", "--modify-window", "--outbuf", "--iconv",
              "--block-size", "--stop-after", "--stop-at", "--write-batch",
              "--only-write-batch", "--read-batch", "--protocol"},
}

# Признаки исполнения команды из кода интерпретатора (TS.md §7.2).
INTERPRETER_EXEC_RE = re.compile(
    r"os\.system|os\.popen|os\.exec|subprocess|Popen|child_process|execSync|"
    r"execFileSync|spawnSync|\bexec\s*\(|\bsystem\s*\(|Runtime\.getRuntime|"
    r"IO\.popen|Kernel\.system|shell_exec|passthru|popen\s*\(",
    re.IGNORECASE)
STRING_LITERAL_RE = re.compile(r"'([^'\n]{2,400})'|\"([^\"\n]{2,400})\"")

# Heredoc: кому достаётся тело (см. _classify_heredoc).
HEREDOC_DATA = "data"          # текст, уходящий в файл: командами не является
HEREDOC_CODE = "code"          # читает шелл либо получатель не доказуем
HEREDOC_INTERP = "interp"      # код python/node/perl: проверка как у `-c`
# Тело — данные только у этих команд и только если их stdout перенаправлен в
# статически известный файл. Список намеренно короткий: у всего остального
# (`ssh host <<EOF`, `psql <<EOF`, `sudo tee`) тело разбирается как раньше.
HEREDOC_SINKS = {"cat", "tee"}
# Признаки shell-скрипта — общие для файла на диске и тела heredoc.
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh")
SCRIPT_SHEBANG_RE = re.compile(r"^#!\s*(?:/usr/bin/env\s+)?(?:\S*/)?(?:ba|z|k|da|a)?sh\b")
# Команды, способные исполнить только что записанный файл. Если такая есть в
# строке, тело heredoc, ушедшее в файл, проверяется как скрипт: по имени цели
# связь не установить (`bash *.sh`, `chmod +x run && ./run`, `mv run go`).
HEREDOC_EXECUTORS = SHELLS | {"source", ".", "eval", "exec", "xargs", "chmod"}
HEREDOC_DELIM_END = " \t\r\n;&|()<>"
STDOUT_REDIR_RE = re.compile(r"^(?:1|&)?(?:>>|>\||>)$")
SPECIAL_TARGET_RE = re.compile(r"^/(?:dev|proc)/")


@dataclass(frozen=True)
class Heredoc:
    """Тело heredoc и решение, чем оно является.

    `span` — границы тела в исходной команде (только для heredoc верхнего
    уровня): по ним code_text() вырезает данные из текста для regex-правил.
    `target` — файл, в который уходит тело-данные.
    """
    body: str = ""
    quoted: bool = False
    kind: str = HEREDOC_CODE
    target: str = ""
    span: tuple = None


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
    # Имя команды как написано (`./deploy/e2e-test.sh`, `/usr/bin/rm`): argv0
    # нормализован до basename, а хуку нужен путь, чтобы открыть файл скрипта.
    argv0_text: str = ""
    heredocs: tuple = ()
    here_strings: tuple = ()   # тексты `<<< '…'`
    stdin_file: str = ""       # цель `< файл`
    stdout_file: str = ""      # цель единственного статического `> файл`
    # Каталог, в который команду привёл `cd` раньше в той же строке (как
    # написано), CWD_UNKNOWN — если цель `cd` вычисляется; None — cd не было.
    cwd: str = None
    via_wrapper: bool = False  # внутренняя команда обёртки: наследует пайп
    shell_stdin: bool = False  # шелл без `-c` и без файла: код придёт из stdin


@dataclass
class _Word:
    text: str = ""
    subs: list = field(default_factory=list)     # тексты $( ) и `` внутри слова
    has_var: bool = False
    quoted: bool = False
    heredoc: dict = None       # слово-заглушка `<<DELIM`: тело заполняет лексер
    redir: bool = False        # слово — оператор перенаправления (`>`, `2>>`, `<<<`)
    glob: bool = False         # незакавыченные `*`, `?`, `[`: имя раскроет шелл
    brace: bool = False        # незакавыченное `{a,b}` или `{1..3}`
    lbrace: bool = False       # встречена незакавыченная `{` (служебное)


# --- Лексер ----------------------------------------------------------------

def _tokenize(text):
    """Строка → список токенов: ('word', _Word) либо ('op', str).

    Кавычки, экранирование, подстановки и управляющие операторы разбираются
    здесь; всё остальное — уже работа со списком токенов.

    Оператор перенаправления — отдельное слово с пометкой `redir`, где бы он
    ни стоял: `echo x>>~/.bashrc` и `echo x >"$HOME/.bashrc"` дают ту же
    тройку «команда, оператор, цель», что и запись через пробелы. До 2.2
    оператор распознавался только как отдельное незакавыченное слово, и обе
    формы проходили мимо правил по цели перенаправления.
    """
    tokens = []
    word = None
    i, n = 0, len(text)
    pending = []               # heredoc, чьё тело начнётся со следующей строки
    arith_until = 0            # внутри `(( ))` `<` и `>` — сравнение и сдвиг

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
            if pending:
                i = _read_heredoc_bodies(text, i, pending)
                pending = []
            continue

        if ch == "#" and word is None:
            # Комментарий до конца строки: шелл его не исполняет, и продолжение
            # строки (`\` в конце) внутри комментария не действует. Раньше текст
            # комментария разбирался как команда (ложные отказы на `# rm -rf /`),
            # а `# x\` + перевод строки склеивал комментарий со следующей
            # командой и прятал её.
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue

        if ch in "<>" and i >= arith_until:
            if i + 1 < n and text[i + 1] == "(":
                # Process substitution `<(...)`/`>(...)`: как и $( ), содержимое —
                # отдельная команда; итоговое слово помечается тем же маркером
                # `$()`, что и обычная подстановка (см. _render) — цель становится
                # динамической для правил вроде command-rm-dynamic-target.
                inner, i = _scan_balanced(text, i + 2, "(", ")")
                start().subs.append(inner)
                continue
            if text.startswith("<<", i) and not text.startswith("<<<", i):
                spec, j = _scan_heredoc_op(text, i)
                if spec is not None:
                    flush()
                    tokens.append(("word", _Word(text="<<", heredoc=spec)))
                    pending.append(spec)
                    i = j
                    continue
            prefix = ""
            if (word is not None and word.text.isdigit() and not word.quoted
                    and not word.subs and not word.has_var):
                prefix, word = word.text, None       # `2>file`: дескриптор
            else:
                flush()
            op = next(o for o in REDIR_OPS if text.startswith(o, i))
            tokens.append(("word", _Word(text=prefix + op, redir=True)))
            i += len(op)
            continue

        if ch == "&" and text.startswith("&>", i) and i >= arith_until:
            flush()
            op = "&>>" if text.startswith("&>>", i) else "&>"
            tokens.append(("word", _Word(text=op, redir=True)))
            i += len(op)
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

        if ch == "$" and i + 1 < n and text[i + 1] == "'":
            j, decoded = _scan_ansi_c(text, i + 2)
            w = start()
            w.text += decoded
            w.quoted = True
            i = j
            continue

        if ch == "$" and i + 1 < n and text[i + 1] == '"':
            i += 1                 # `$"…"` — перевод по локали, те же кавычки
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
            if ch == "(" and text.startswith("((", i):
                _, end = _scan_balanced(text, i + 1, "(", ")")
                arith_until = max(arith_until, end)
            flush()
            tokens.append(("op", ch))
            i += 1
            continue

        w = start()
        if ch in "*?[":
            w.glob = True
        elif ch == "{":
            w.lbrace = True
        elif w.lbrace and (ch == "," or (ch == "." and w.text.endswith("."))):
            w.brace = True
        w.text += ch
        i += 1

    flush()
    return tokens


def _scan_heredoc_op(text, i):
    """`<<DELIM`, `<<-DELIM`, `<<'DELIM'` → (описание, позиция после слова).

    Разделитель проходит снятие кавычек так же, как в bash: `<<'EOF'`,
    `<<"EOF"`, `<<\\EOF` и `<<E"O"F` закрываются строкой `EOF`. Любая кавычка
    делает тело литералом — без подстановок.
    """
    n = len(text)
    j = i + 2
    strip_tabs = j < n and text[j] == "-"
    if strip_tabs:
        j += 1
    while j < n and text[j] in " \t":
        j += 1
    delim, quoted, odd = "", False, False
    while j < n and text[j] not in HEREDOC_DELIM_END:
        ch = text[j]
        if ch == "'":
            end = text.find("'", j + 1)
            end = n if end == -1 else end
            delim += text[j + 1:end]
            quoted = True
            j = end + 1
        elif ch == '"':
            end = _find_unescaped(text, j + 1, '"')
            delim += text[j + 1:end].replace("\\", "")
            quoted = True
            j = end + 1
        elif ch == "\\" and j + 1 < n:
            delim += text[j + 1]
            quoted = True
            j += 2
        else:
            if ch in "$`":
                odd = True     # bash разбирает такой разделитель по-своему
            delim += ch
            j += 1
    if not delim or "\n" in delim:
        return None, i
    return {"delim": delim, "strip_tabs": strip_tabs, "quoted": quoted,
            "odd": odd, "body": "", "span": None, "terminated": True}, j


def _read_heredoc_bodies(text, i, pending):
    """Тела heredoc начинаются со строки после оператора и идут по порядку.

    Закрывает тело строка, РАВНАЯ разделителю (у `<<-` — после снятия ведущих
    табов): хвостовой пробел или отступ пробелами тело не закрывают, как и в
    bash. Не нашли — тело тянется до конца текста, а heredoc помечается
    незакрытым. Возвращает позицию после последнего закрывающего разделителя.
    """
    n = len(text)
    for spec in pending:
        start, pos, spec["terminated"] = i, i, False
        while pos < n:
            eol = text.find("\n", pos)
            eol = n if eol == -1 else eol
            line = text[pos:eol]
            if (line.lstrip("\t") if spec["strip_tabs"] else line) == spec["delim"]:
                spec["terminated"] = True
                break
            pos = min(eol + 1, n)
        spec["body"] = text[start:pos]
        spec["span"] = (start, pos)
        if not spec["terminated"]:
            return n
        eol = text.find("\n", pos)
        i = n if eol == -1 else eol + 1
    return i


def _heredoc_subs(body):
    """Подстановки в теле heredoc без кавычек: `$( )` и обратные кавычки там
    исполняются, остальное — текст."""
    subs, i, n = [], 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "\\":
            i += 2
        elif ch == "$" and body.startswith("$(", i):
            inner, i = _scan_balanced(body, i + 2, "(", ")")
            subs.append(inner)
        elif ch == "`":
            j = _find_unescaped(body, i + 1, "`")
            subs.append(body[i + 1:j])
            i = j + 1
        else:
            i += 1
    return subs


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
    статически невозможно, но увидеть переменную в позиции команды — нужно.

    Тело `${…}` берётся по парным скобкам, и подстановки внутри него
    (`${x:-$(cmd)}`, `${a[$(cmd)]}`) извлекаются: шелл их исполняет. Раньше
    тело бралось до первой `}` как текст, и команда внутри была невидима.
    Специальные параметры (`$@`, `$*`, `$1`, `$?` …) — тоже переменные:
    `set -- rm -rf ~; "$@"` иначе выглядел как команда с именем `$`.
    """
    n = len(text)
    if i + 1 < n and text[i + 1] == "{":
        inner, j = _scan_balanced(text, i + 2, "{", "}")
        word.text += text[i:j]
        word.has_var = True
        word.subs.extend(_heredoc_subs(inner))
        return j, word
    if i + 1 < n and text[i + 1] in "@*#?$!-0123456789":
        word.text += text[i:i + 2]
        word.has_var = True
        return i + 2, word
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


def _scan_ansi_c(text, i):
    """Содержимое ANSI-C кавычек `$'...'` — с раскрытием escape-последовательностей.

    `$'\\x2f'` должно дать тот же символ, что и `/`, иначе `rm -rf $'\\x2f'`
    обходит проверку корня одним экранированием (ADR-002).
    """
    n = len(text)
    j = i
    while j < n:
        if text[j] == "\\" and j + 1 < n:
            j += 2
            continue
        if text[j] == "'":
            break
        j += 1
    raw = text[i:j]
    try:
        decoded = raw.encode("utf-8", "surrogateescape").decode("unicode_escape")
    except Exception:
        decoded = raw
    return (j + 1 if j < n else n), decoded


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

def parse(command, script_dir=None):
    """(команды, предупреждения).

    `script_dir` — каталог файла, если разбирается содержимое скрипта:
    `cd "$(dirname "$0")"` тогда ведёт в известный каталог, а не в неизвестный.

    Непустые предупреждения при fail-closed → эскалация в `ask` (TS.md §7.1).
    Исключений не бросает никогда: сбой парсера сам становится предупреждением.
    """
    if not isinstance(command, str) or not command.strip():
        return [], []
    state = {"warnings": [], "aliases": {}, "top": command, "vars": {},
             "cd": None, "script_dir": script_dir,
             "functions": {m.group(1) or m.group(2)
                           for m in FUNC_NAME_RE.finditer(command)}}
    try:
        cmds = _parse_text(command, 0, DIRECT, state)
        # Определения функций ищутся по тексту без тел-данных: `f() { ... }`
        # в markdown, который пишется в файл, — не определение функции.
        cmds.extend(_expand_function_bodies(code_text(command, cmds), state))
    except RecursionError:
        return [], ["recursion_limit"]
    except Exception as exc:                     # инвариант: парсер не падает
        return [], ["parse_error:{}".format(type(exc).__name__)]
    return cmds, state["warnings"]


# `name () { body }` и `function name { body }` (TS.md §7.2). Тело разбирается
# по тексту команды целиком, а не по дереву вызовов: токенайзер трактует
# голые `(` `)` как разделители конструкций (ADR-002 §fork-bomb), и попытка
# провести определение функции через обычный `_build` даёт мусор. Само тело —
# опасная команда внутри — обязано попасть в результат независимо от того,
# вызывается ли функция дальше в той же строке: не вызванное определение не
# опаснее вызванного, если проверка вообще пропускает его мимо правил.
# `(?<![A-Za-z0-9_])` перед именем обязателен: без него поиск стартует с
# каждой позиции длинного слова и просматривает его до конца — квадратичное
# время, 20 КБ без пробелов разбирались дольше таймаута хука.
FUNC_DEF_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:function\s+[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))"
    r"\s*\{([^{}]*)\}",
    re.DOTALL)


FUNC_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))")


def _expand_function_bodies(command, state):
    out = []
    for match in FUNC_DEF_RE.finditer(command):
        body = match.group(1)
        if body.strip():
            out.extend(_parse_text(body, 1, SUBSHELL, state))
    return out


def _parse_text(text, depth, origin, state):
    if depth > MAX_DEPTH:
        state["warnings"].append("max_depth_exceeded")
        return []
    tokens = _tokenize(text)
    top = text is state.get("top")
    if not top:
        # Смещения тел осмысленны только относительно исходной команды.
        for kind, value in tokens:
            if kind == "word" and value.heredoc is not None:
                value.heredoc["span"] = None
    groups = _split_pipelines(tokens)

    saved_cd, cd_stack = state.get("cd"), []
    out = []
    try:
        for pipeline_index, (ops, group) in enumerate(groups):
            for op in ops:                    # подоболочка: cd внутри не вытекает
                if op == "(":
                    cd_stack.append(state.get("cd"))
                elif op == ")" and cd_stack:
                    state["cd"] = cd_stack.pop()
            stage_cmds = []
            for position, stage in enumerate(group):
                stage_cmds.append(_build(stage, depth, origin, position,
                                         pipeline_index, state))
            argv0s = [built[0].argv0 if built and built[0] else None
                      for built in stage_cmds]
            for position, built in enumerate(stage_cmds):
                if not built:
                    continue
                head, extra = built
                if head is not None:
                    head = _with_pipeline(head, argv0s, position, len(group))
                    out.append(head)
                    extra = [_inherit_pipeline(e, head) if e.via_wrapper else e
                             for e in extra]
                for cmd in ([head] if head is not None else []) + list(extra):
                    if cmd.shell_stdin and cmd.upstream and not cmd.stdin_file:
                        # `… | bash`: исполнится то, что выдаст левая часть.
                        state["warnings"].append("shell_stdin_unresolved")
                out.extend(extra)
                if len(out) > MAX_COMMANDS:
                    state["warnings"].append("too_many_commands")
                    return out
            if len(group) == 1 and stage_cmds[0] and stage_cmds[0][0] is not None:
                _track_cd(stage_cmds[0][0], state)
    finally:
        if not top:
            state["cd"] = saved_cd
    return out


def _with_pipeline(cmd, argv0s, position, size):
    """Проставить соседей по пайпу и origin=pipe для не-первой стадии."""
    upstream = tuple(a for a in argv0s[:position] if a)
    downstream = tuple(a for a in argv0s[position + 1:] if a)
    origin = PIPE if (position > 0 and size > 1 and cmd.origin == DIRECT) else cmd.origin
    return _replace(cmd, upstream=upstream, downstream=downstream, origin=origin)


def _inherit_pipeline(inner, wrapper):
    """Команда внутри обёртки стоит в пайпе там же, где сама обёртка.

    `curl … | env bash` раньше давал `bash` без соседей по пайпу: внутренняя
    команда разбиралась отдельной строкой, и правила по `piped_from_any`
    на неё не действовали.
    """
    origin = PIPE if (wrapper.origin == PIPE and inner.origin == DIRECT) else inner.origin
    return _replace(inner, upstream=wrapper.upstream, downstream=wrapper.downstream,
                    position=wrapper.position, pipeline=wrapper.pipeline,
                    origin=origin)


def _track_cd(cmd, state):
    """Запомнить, куда `cd` увёл последующие команды той же строки.

    Рабочий каталог хука — тот, из которого запущена вся команда; после
    `cd / && rm -rf *` относительные цели считаются уже от `/`.
    """
    if cmd.argv0 == "popd":
        state["cd"] = CWD_UNKNOWN
        return
    if cmd.argv0 not in ("cd", "pushd"):
        return
    target = cmd.operands[0] if cmd.operands else "~"
    previous = state.get("cd")
    hint = state.pop("cd_hint", None)
    if hint is not None and "$()" in target:
        state["cd"] = hint
    elif target == "-" or "$" in target or "`" in target or re.search(r"[*?\[]", target):
        state["cd"] = CWD_UNKNOWN
    elif target.startswith(("/", "~")):
        state["cd"] = target
    elif previous == CWD_UNKNOWN:
        state["cd"] = CWD_UNKNOWN
    else:
        state["cd"] = os.path.join(previous, target) if previous else target


def _replace(cmd, **kw):
    data = {f: getattr(cmd, f) for f in cmd.__dataclass_fields__}
    data.update(kw)
    return Cmd(**data)


def _split_pipelines(tokens):
    """Токены → список (операторы перед пайплайном, пайплайн).

    Пайплайн — список стадий (списков слов). Операторы нужны вызывающему
    ради скобок подоболочек: `cd` внутри `( … )` наружу не действует.
    """
    groups, pipeline, stage, ops = [], [], [], []

    def close():
        nonlocal pipeline, stage, ops
        pipeline.append(stage)
        if any(pipeline):
            groups.append((ops, [s for s in pipeline if s]))
            ops = []
        pipeline, stage = [], []

    for kind, value in tokens:
        if kind == "word":
            stage.append(value)
            continue
        if value in ("|", "|&"):
            pipeline.append(stage)
            stage = []
            continue
        close()
        ops.append(value)
    close()
    return groups


def _build(words, depth, origin, position, pipeline_index, state):
    """Список слов одной стадии → (Cmd, [дополнительные Cmd])."""
    red = _strip_redirects(words)
    assignments, words, assign_subs = _strip_assignments(red["words"], state)
    words = _strip_reserved_prefix(words)
    extra = []
    # Подстановки в целях перенаправлений и в присваиваниях исполняются так же,
    # как в аргументах: `echo x > $(cmd)`, `X=$(cmd)`.
    for sub in list(red["subs"]) + list(assign_subs):
        extra.extend(_parse_text(sub, depth + 1, SUBSHELL, state))

    if not words:
        if red["heredocs"]:
            # Heredoc без команды: получатель неизвестен — тело как код.
            _, here_extra = _heredocs(None, red["heredocs"], None, depth, origin, state)
            extra.extend(here_extra)
        if red["redirects"]:
            # Перенаправление без команды (`> file`, `( … ) >> file`): цель
            # должна остаться видимой правилам по перенаправлениям.
            cmd = Cmd(argv0=":", raw=": > " + " ".join(red["redirects"]),
                      depth=depth, origin=origin, pipeline=pipeline_index,
                      position=position, redirects=tuple(red["redirects"]),
                      assignments=tuple(assignments), argv0_text=":",
                      stdout_file=red["stdout_file"] or "",
                      stdin_file=red["stdin_file"] or "", cwd=state.get("cd"))
            return cmd, extra
        return (None, extra) if extra else None

    for word in words:
        _substitute_vars(word, state)
    if any(w.has_var and ("$IFS" in w.text or "${IFS" in w.text) for w in words):
        # `rm${IFS}-rf${IFS}~`: шелл разрежет слово на несколько аргументов.
        state["warnings"].append("ifs_split")

    head, rest = words[0], words[1:]
    argv0, var_argv0, more = _resolve_argv0(head, depth, origin, state)
    extra.extend(more)
    args = tuple(_render(w) for w in rest)

    # Алиас, определённый раньше в этой же команде: `alias r="rm -rf"; r /`
    # (TS.md §7.2). Раскрывается тем же способом, что и eval — подстановкой
    # значения и повторным разбором; глубина растёт, чтобы самоссылающийся
    # алиас (`alias r=r`) уткнулся в MAX_DEPTH, а не зациклился.
    aliases = state.setdefault("aliases", {})
    if argv0 in aliases and depth < MAX_DEPTH:
        expanded_line = aliases[argv0] + "".join(" " + _quote(a) for a in args)
        parsed = _parse_text(expanded_line, depth + 1, origin, state)
        # Алиас может оказаться шеллом (`alias c=bash; c <<EOF` или `<<<`): тело
        # и here-string — код.
        _, here_extra = _heredocs(None, red["heredocs"], None, depth, origin, state)
        if red["here_strings"] and parsed and _basename(parsed[0].argv0) in SHELLS:
            for text in red["here_strings"]:
                here_extra.extend(_parse_text(text, depth + 1, SUBSHELL, state))
        if not parsed:
            extra.extend(here_extra)
            return (None, extra) if extra else None
        new_head, new_extra = parsed[0], list(parsed[1:])
        return new_head, new_extra + extra + here_extra

    raw = " ".join([argv0] + list(args))

    flags, operands = _split_flags(argv0, args)
    cmd = Cmd(argv0=argv0, args=args, flags=flags, operands=operands,
              depth=depth, origin=origin, raw=raw, pipeline=pipeline_index,
              position=position, redirects=tuple(red["redirects"]),
              assignments=tuple(assignments), var_argv0=var_argv0,
              argv0_text=_render(head).strip().lstrip("\\"),
              here_strings=tuple(red["here_strings"]),
              stdin_file=red["stdin_file"] or "",
              stdout_file=red["stdout_file"] or "", cwd=state.get("cd"))

    if argv0 == "alias":
        for arg in args:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", arg)
            if m:
                aliases[m.group(1)] = m.group(2)
    _track_vars(cmd, state)
    if argv0 in ("cd", "pushd"):
        target_words = [w for w in rest if not w.text.startswith("-")]
        if (target_words and target_words[0].subs and not target_words[0].text.strip()
                and any(SCRIPT_DIR_RE.search(sub) for sub in target_words[0].subs)):
            state["cd_hint"] = state.get("script_dir") or "."

    # Подстановки внутри аргументов — отдельные команды глубже уровнем.
    for word in words:
        for sub in word.subs:
            extra.extend(_parse_text(sub, depth + 1, SUBSHELL, state))

    inner, shell_stdin = _expand(cmd, args, depth, state,
                                 has_heredoc=bool(red["heredocs"]))
    extra.extend(inner)
    if shell_stdin:
        cmd = _replace(cmd, shell_stdin=True)
    if red["heredocs"]:
        heredocs, here_extra = _heredocs(cmd, red["heredocs"], red["stdout_file"],
                                         depth, origin, state)
        cmd = _replace(cmd, heredocs=heredocs)
        extra.extend(here_extra)
    return cmd, extra


def _strip_redirects(words):
    """Цели перенаправлений — не операнды команды.

    Заодно выясняется, куда уходит stdout: `stdout_file` — цель единственного
    файлового редиректа stdout, если она известна статически; иначе None
    (нет редиректа, их несколько, есть дублирование дескрипторов `>&`, цель
    вычисляется или это /dev/stdout и подобное).
    """
    out, redirects, heredocs, here_strings, subs = [], [], [], [], []
    stdout_targets, stdout_static, stdin_file = [], True, None
    i = 0
    while i < len(words):
        word = words[i]
        if word.heredoc is not None:
            heredocs.append(word.heredoc)
            i += 1
            continue
        if not word.redir:
            out.append(word)
            i += 1
            continue
        op = word.text
        target = words[i + 1] if i + 1 < len(words) else None
        if target is None or target.redir or target.heredoc is not None:
            i += 1                           # оператор без цели
            continue
        i += 2
        redirects.append(_render(target))
        subs.extend(target.subs)
        if op.endswith("<<<"):
            here_strings.append(target.text)
        elif op in ("<", "0<"):
            stdin_file = _render(target)
        stdout_static &= _note_stdout(op, target.text, target, stdout_targets)
    stdout_file = None
    if stdout_static and len(stdout_targets) == 1:
        stdout_file = stdout_targets[0]
    return {"words": out, "redirects": redirects, "stdout_file": stdout_file,
            "heredocs": heredocs, "here_strings": here_strings,
            "stdin_file": stdin_file, "subs": subs}


def _note_stdout(op, target, word, targets):
    """Учесть редирект; False — stdout после него статически не определён."""
    if ">&" in op or "<&" in op:
        return False
    if not STDOUT_REDIR_RE.match(op):
        return True                          # stdin или чужой дескриптор
    targets.append(target)
    if word.subs or word.has_var or not target:
        return False
    return target == "/dev/null" or not SPECIAL_TARGET_RE.match(target)


def _classify_heredoc(cmd, spec, stdout_file, state):
    """Чем является тело heredoc для команды, которая его читает.

    Данные — только доказуемый случай: cat/tee пишет тело в статически
    известный файл, то есть ни в пайп, ни в подстановку оно не попадёт, чем
    бы ни была окружена команда. Всё остальное (`bash <<EOF`, `cat <<EOF |
    sh`, `sudo tee`, алиас, цель из переменной) — код, как и до появления
    разбора heredoc.
    """
    if cmd is None or not spec["terminated"] or spec["odd"]:
        return HEREDOC_CODE
    if cmd.argv0 in state.get("functions", ()):
        return HEREDOC_CODE
    if cmd.argv0 in INTERPRETERS and not cmd.var_argv0:
        return HEREDOC_INTERP
    if cmd.argv0 in HEREDOC_SINKS and not cmd.var_argv0 and stdout_file:
        return HEREDOC_DATA
    return HEREDOC_CODE


def _heredocs(cmd, specs, stdout_file, depth, origin, state):
    """(Heredoc-и команды, команды из их тел)."""
    heredocs, extra = [], []
    for spec in specs:
        kind = _classify_heredoc(cmd, spec, stdout_file, state)
        body = spec["body"]
        if not spec["terminated"] or spec["odd"]:
            # Незакрытый heredoc или разделитель с `$`: границы тела у bash
            # могут быть другими — и предупреждение, и разбор тела как кода.
            state["warnings"].append("heredoc_unresolved")
        if kind == HEREDOC_CODE:
            extra.extend(_parse_text(body, depth, origin, state))
        else:
            if kind == HEREDOC_INTERP:
                extra.extend(_interpreter_code(body, depth, state))
            if not spec["quoted"]:
                for sub in _heredoc_subs(body):
                    extra.extend(_parse_text(sub, depth + 1, SUBSHELL, state))
        heredocs.append(Heredoc(
            body=body, quoted=spec["quoted"], kind=kind, span=spec["span"],
            target=stdout_file if kind == HEREDOC_DATA else ""))
    return tuple(heredocs), extra


def _interpreter_code(code, depth, state):
    """Код python/node/perl: полный разбор чужого языка не задача плагина —
    фиксируется факт исполнения команды и вытаскиваются строковые литералы."""
    out = []
    if INTERPRETER_EXEC_RE.search(code):
        state["warnings"].append("interpreter_exec")
        out.append(Cmd(argv0="unknown", args=(), flags=frozenset(),
                       operands=(), depth=depth + 1, origin=INTERPRETER,
                       raw=code[:200]))
        for literal in _literals(code):
            out.extend(_parse_text(literal, depth + 1, INTERPRETER, state))
    return out


def code_text(command, cmds, also_code=()):
    """Текст команды без тел heredoc, которые кодом шелла не являются.

    Нужен правилам по сырому тексту: `history -c` в документе, который
    пишется в файл, — не очистка истории. `also_code` — heredoc-и, которые
    вызывающий всё же считает кодом (запись shell-скрипта).
    """
    spans = sorted({h.span for c in cmds for h in c.heredocs
                    if h.kind != HEREDOC_CODE and h.span and h not in also_code})
    out, pos = [], 0
    for start, end in spans:
        if start < pos:
            continue
        out.append(command[pos:start])
        pos = end
    out.append(command[pos:])
    return "".join(out)


def _strip_assignments(words, state=None):
    """`FOO=1 git push` → префикс отброшен, argv0="git" (TS.md §7.2).

    Возвращает (присваивания, остальные слова, подстановки из значений).
    Значения попадают в таблицу переменных (см. _set_var): `X=/; rm -rf $X`
    тогда разбирается как `rm -rf /`.
    """
    assignments, subs, i = [], [], 0
    while i < len(words):
        word = words[i]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", word.text, re.S)
        if not m or word.redir or word.heredoc is not None:
            break
        if state is not None:
            _substitute_vars(word, state)
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", word.text, re.S)
            name, plus, value = m.group(1), m.group(2), m.group(3)
            if plus or word.has_var:
                _set_var(state, name, None)
            elif word.subs:
                single = len(word.subs) == 1 and not value
                if single and MKTEMP_RE.match(word.subs[0].strip()):
                    _set_var(state, name, MKTEMP_PATH)
                elif single and SCRIPT_DIR_RE.search(word.subs[0]):
                    _set_var(state, name, state.get("script_dir") or ".")
                else:
                    _set_var(state, name, None)
            else:
                _set_var(state, name, value)
        assignments.append(word.text)
        subs.extend(word.subs)
        i += 1
    return assignments, words[i:], subs


def _set_var(state, name, value):
    """Запомнить значение переменной; None — значение статически неизвестно.

    Подставляется только переменная, присвоенная в строке ровно один раз:
    второе присваивание (ветка `if`, цикл) делает её неизвестной — иначе
    `X=/; [ c ] && X=build; rm -rf $X` разобрался бы как безопасный.
    """
    table = state.setdefault("vars", {})
    table[name] = None if name in table else value


def _substitute_vars(word, state):
    """Подставить в слово значения переменных, известные из этой же строки."""
    if not word.has_var or word.redir or word.heredoc is not None:
        return
    table = state.get("vars") or {}
    if not table or state.get("vars_frozen"):
        return

    def value_of(match):
        name = match.group(1) or match.group(2)
        value = table.get(name)
        return value if isinstance(value, str) else match.group(0)

    word.text = SIMPLE_VAR_RE.sub(value_of, word.text)
    word.has_var = bool(VAR_REF_RE.search(word.text))


def _track_vars(cmd, state):
    """Команды, после которых значение переменной статически неизвестно."""
    if cmd.argv0 in ("eval", "source", "."):
        state["vars_frozen"] = True          # присвоить могли что угодно
        return
    if cmd.argv0 in VAR_DECLARATORS:
        for arg in cmd.args:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", arg, re.S)
            if m:
                dynamic = bool(VAR_REF_RE.search(m.group(2))) or "$()" in m.group(2)
                _set_var(state, m.group(1), None if dynamic else m.group(2))
        return
    if cmd.argv0 in VAR_WRITERS or (cmd.argv0 == "printf" and "-v" in cmd.args):
        for arg in cmd.args:
            name = arg.split("=", 1)[0]
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                _set_var(state, name, None)
                state["vars"][name] = None


# Служебные слова shell, за которыми следует НОВАЯ команда, а не её аргумент
# (найдено охотой за обходами сверх P0-корпуса, 2026-08). Токенайзер режет
# только по `;`/`&&`/`||`/`|` — стадия `do rm -rf /` после `until false; do
# rm -rf /; done` парсится как команда с argv0="do", а `rm -rf /` тонет в её
# args. `if`/`while`/`until`/`for`/`case` сюда не входят: они вводят не
# команду, а условие/список, и без полного грамматического разбора шелла
# срезать их так же нельзя, не потеряв реальные операнды.
#
# С 2.2 срезаются и `{`, `!`, `if`, `while`, `until`, `coproc`, `function`:
# после них стоит обычная команда. `{ rm -rf ~; }`, `! rm -rf ~`,
# `if rm -rf ~; then …` давали argv0="{"/"!"/"if" и проходили мимо всех
# правил (аудит 03.10.2026, P1). `for`/`case`/`select` по-прежнему не
# срезаются: за ними идёт имя переменной или слово, а не команда.
RESERVED_PREFIX = {"do", "then", "else", "elif", "time", "{", "!", "if",
                   "while", "until", "coproc", "function"}
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _strip_reserved_prefix(words):
    def plain(word):
        return not word.quoted and not word.subs and not word.has_var

    while words and plain(words[0]) and words[0].text in RESERVED_PREFIX:
        keyword, words = words[0].text, words[1:]
        if keyword == "time":
            while words and plain(words[0]) and words[0].text == "-p":
                words = words[1:]
        elif keyword == "function" and words and plain(words[0]):
            words = words[1:]                        # имя функции
            if len(words) >= 2 and words[0].text == "(" and words[1].text == ")":
                words = words[2:]
        elif (keyword == "coproc" and len(words) >= 2 and plain(words[0])
              and _NAME_RE.match(words[0].text) and words[1].text == "{"):
            words = words[1:]                        # `coproc NAME { … }`
    return words


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

    Имя, которое шелл соберёт сам, статически неизвестно — предупреждение и
    `ask`. С 2.2 это любое слово-команда с переменной, подстановкой, глобом
    или фигурными скобками в ЛЮБОМ месте, а не только слово, начинающееся с
    `$`: `r${x}m`, `r$(echo m)`, `/bin/r?m`, `{rm,-rf,~}` проходили молча.
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

    if word.subs:
        state["warnings"].append("argv0_from_substitution")
        return _basename(text), True, extra

    if word.has_var:
        # Динамически собранные команды статически неразрешимы (TS.md §7.4).
        # Это документируется, а не «чинится»: предупреждение → ask.
        state["warnings"].append("argv0_is_variable")
        return _basename(text), True, extra

    if (word.glob or word.brace) and text not in ("[", "[[", "?", "{", "}"):
        state["warnings"].append("argv0_dynamic")
        return _basename(text), True, extra

    return _basename(text), False, extra


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


SOURCE_DYNAMIC_RE = re.compile(r"^/(dev/std(in|out)|dev/fd/|proc/self/fd/)")


def _expand(cmd, args, depth, state, has_heredoc=False):
    """Раскрытие обёрток, шеллов и интерпретаторов.

    Возвращает (команды, признак «шелл прочитает код из stdin»).
    """
    out = []
    argv0 = cmd.argv0

    def wrapped(line, level):
        return [_replace(c, via_wrapper=True) if c.depth == level else c
                for c in _parse_text(line, level, cmd.origin, state)]

    if argv0 == "xargs":
        # `-I{}` даёт цель, вычисляемую из потока: статически известен только
        # плейсхолдер, не значение (TS.md §7.2). Помечаем его тем же
        # маркером `$()`, что и обычная подстановка — правило
        # command-rm-dynamic-target реагирует одинаково на обе формы. Без
        # `-I` аргументы из потока дописываются в конец команды.
        inner_argv = _unwrap(argv0, args)
        repl = _xargs_replacement(args)
        if inner_argv:
            line = " ".join(_quote(a) for a in inner_argv)
            if repl:
                line = line.replace(repl, repl + "$()")
            else:
                line += " $()"
            out.extend(wrapped(line, depth))
        return out, False

    if argv0 in ("eval",):
        # `eval 'rm -rf /'` — строка-аргумент исполняется как код (TS.md §7.2,
        # обход из корпуса bypass_corpus). Склеиваем аргументы тем же способом,
        # каким это делает сам bash: пробелом.
        code = " ".join(args)
        if code.strip():
            out.extend(_parse_text(code, depth + 1, SUBSHELL, state))

    if argv0 in ("source", "."):
        # `source .venv/bin/activate` — обычное дело в любом Python-проекте;
        # эскалация по каждому такому вызову была бы ложным срабатыванием на
        # львиной доле легитимных команд. Опасен не source сам по себе, а
        # source из НЕИЗВЕСТНОГО источника: here-string (`<<<`), явный
        # /dev/stdin или /dev/fd, либо цель, вычисленная подстановкой
        # (маркер `$()` — см. _render).
        if cmd.here_strings:
            for code in cmd.here_strings:
                out.extend(_parse_text(code, depth + 1, SUBSHELL, state))
        elif not has_heredoc:
            target = args[0] if args else None
            if not target or "$()" in target or SOURCE_DYNAMIC_RE.match(target):
                state["warnings"].append("source_unresolved")

    if argv0 == "trap" and args and not args[0].startswith("-"):
        # `trap "rm -rf /" EXIT` — первый операнд обычно код, выполняемый по
        # сигналу (TS.md §7.2).
        out.extend(_parse_text(args[0], depth + 1, SUBSHELL, state))

    if argv0 == "find" and "--exec" in cmd.flags:
        exec_cmd = _find_exec_command(args)
        if exec_cmd:
            # `{}` — цель, которую find подставляет для каждого найденного
            # файла: статически известен только плейсхолдер (как `-I{}` у
            # xargs), не то, что реально будет удалено. Тот же маркер `$()`,
            # что и у обычной подстановки.
            line = " ".join(_quote(a) for a in exec_cmd)
            if "{}" in exec_cmd:
                line = line.replace("{}", "{}$()")
            out.extend(_parse_text(line, depth + 1, cmd.origin, state))

    # --- утилиты, исполняющие строку с командой ---------------------------
    if argv0 == "env":
        # `env -S 'rm -rf ~'`: значение — командная строка, а не имя файла.
        code = _flag_value(args, ("-S", "--split-string"))
        for arg in args:
            if arg.startswith("-S") and len(arg) > 2:
                code = arg[2:]
        if code:
            out.extend(_parse_text(code, depth + 1, SUBSHELL, state))
    if argv0 in CODE_FLAG_WRAPPERS:
        code = _flag_value(args, CODE_FLAG_WRAPPERS[argv0])
        if code:
            out.extend(_parse_text(code, depth + 1, SUBSHELL, state))
    if argv0 == "watch":
        rest = _unwrap("watch", args, {"value_flags": {"-n", "--interval", "-d"}})
        if rest:
            out.extend(_parse_text(" ".join(rest), depth + 1, SUBSHELL, state))
    if argv0 == "sg" and len(cmd.operands) >= 2:
        out.extend(_parse_text(cmd.operands[1], depth + 1, SUBSHELL, state))
    if argv0 == "ssh":
        host, remote = _ssh_remote(args)
        if host and remote and (LOCAL_HOST_RE.match(host) or "$" in host):
            # ssh на эту же машину — тот же шелл, только в обход проверки.
            out.extend(_parse_text(" ".join(remote), depth + 1, SUBSHELL, state))

    inner_argv = _unwrap(argv0, args)
    if inner_argv:
        out.extend(wrapped(" ".join(_quote(a) for a in inner_argv), depth))
        # Перенаправления обёртки действуют на внутреннюю команду:
        # `exec bash <<< 'код'`, `nohup sh < файл` — здесь шеллом оказывается
        # не argv0, а первый внутренний аргумент. Без этого here-string и
        # stdin обёрнутого шелла терялись при раскрытии.
        inner0 = _basename(inner_argv[0])
        if inner0 in SHELLS and _unwrap(inner0, inner_argv[1:]) is None:
            _code, has_c, script = shell_invocation(inner_argv[1:])
            if not has_c and not script:
                for text in cmd.here_strings:
                    out.extend(_parse_text(text, depth + 1, SUBSHELL, state))

    shell_stdin = False
    if argv0 in SHELLS and not (argv0 == "busybox" and inner_argv):
        code, has_c, script = shell_invocation(args)
        if code and code.strip() == "$()":
            code = None                  # код целиком придёт из подстановки/потока
        if code:
            out.extend(_parse_text(code, depth + 1, SUBSHELL, state))
        elif has_c:
            # `-c` присутствует, но значение статически недоступно — обычно
            # потому, что оно приходит от xargs/пайпа
            # (`... | xargs -d '\n' sh -c`). Пропускать нельзя (TS.md §7.1).
            state["warnings"].append("shell_c_unresolved")
        elif script:
            if "$()" in script:
                # `bash <(curl …)`: скрипт — вывод подстановки.
                state["warnings"].append("shell_c_unresolved")
        elif cmd.here_strings:
            for text in cmd.here_strings:        # `bash <<< 'код'`
                out.extend(_parse_text(text, depth + 1, SUBSHELL, state))
        elif not has_heredoc:
            shell_stdin = True
            if cmd.stdin_file and ("$" in cmd.stdin_file or "`" in cmd.stdin_file):
                state["warnings"].append("shell_stdin_unresolved")

    if argv0 in INTERPRETERS:
        code = _flag_value(args, ("-c", "-e", "-E", "--eval", "--print"))
        if code:
            out.extend(_interpreter_code(code, depth, state))
    return out, shell_stdin


def shell_invocation(args):
    """Разбор аргументов шелла: (код из `-c` | None, был ли `-c`, файл скрипта | None).

    Между `-c` и кодом могут стоять другие опции и `--`: `bash -c -- 'код'`,
    `bash -x -c 'код'`, `bash -o pipefail -c 'код'`. Раньше кодом считался
    аргумент сразу после `-c`, то есть `--`.
    """
    has_c, stdin_mode, i = False, False, 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            break
        if arg in SHELL_VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("--"):
            i += 1
            continue
        if arg[:1] in "-+" and len(arg) > 1:
            if arg[0] == "-" and "c" in arg[1:]:
                has_c = True
            if arg[0] == "-" and "s" in arg[1:]:
                stdin_mode = True
            i += 1
            continue
        break
    rest = args[i:]
    if has_c:
        return (rest[0] if rest else None), True, None
    if stdin_mode:
        return None, False, None
    return None, False, (rest[0] if rest else None)


def _ssh_remote(args):
    """(хост, слова удалённой команды) из аргументов ssh."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in SSH_VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("-") and len(arg) > 1:
            i += 1
            continue
        return arg, list(args[i + 1:])
    return None, []


def _xargs_replacement(args):
    """Плейсхолдер xargs: `-I R`, `-IR`, `-i` (он же `{}`), `--replace[=R]`."""
    for i, arg in enumerate(args):
        if arg == "-I" and i + 1 < len(args):
            return args[i + 1]
        if arg.startswith("-I") and len(arg) > 2:
            return arg[2:]
        if arg in ("-i", "--replace"):
            return "{}"
        if arg.startswith("-i") and len(arg) > 2:
            return arg[2:]
        if arg.startswith("--replace="):
            return arg[len("--replace="):] or "{}"
    return None


def _find_exec_command(args):
    """Команда внутри `find ... -exec CMD {} ;` (TS.md §7.2)."""
    for i, arg in enumerate(args):
        if arg in ("-exec", "-execdir"):
            parts = []
            for later in args[i + 1:]:
                if later in (";", "+"):
                    break
                parts.append(later)
            return parts or None
    return None


def _unwrap(argv0, args, spec=None):
    """`env sudo rm -rf /` → внутренняя команда `sudo rm -rf /`."""
    spec = spec or WRAPPERS.get(argv0)
    if not spec:
        return None
    rest = list(args)
    skip_numeric = spec.get("skip_numeric", False)
    cluster = spec.get("cluster_value")
    while rest:
        arg = rest[0]
        if spec.get("skip_assignments") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", arg):
            rest.pop(0)
            continue
        if arg == "--":
            rest.pop(0)
            break
        if arg in spec.get("value_flags", ()):
            rest = rest[2:]
            continue
        if cluster and re.match(r"^-[A-Za-z]*[" + cluster + r"]$", arg):
            rest = rest[2:]                      # `env -iu NAME cmd`
            continue
        if arg.startswith("-") and len(arg) > 1:
            rest.pop(0)
            continue
        if skip_numeric and re.match(r"^(?:\d+(?:\.\d*)?|\.\d+)[smhd]?$", arg):
            rest.pop(0)
            skip_numeric = False
            continue
        break
    rest = rest[spec.get("skip_positional", 0):]
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
    """Аргумент для повторного разбора строки.

    Слово с `$` или обратной кавычкой берётся в ДВОЙНЫЕ кавычки: в одинарных
    переменная превратилась бы в литерал, и `x=rm; env $x -rf ~` после
    раскрытия обёртки терял признак «имя команды из переменной».
    """
    if not value:
        return "''"
    if "$" in value or "`" in value:
        if re.search(r"[\s\"'\\|&;<>()]", value):
            return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return value
    if re.search(r"[\s\"'\\|&;<>()#]", value):
        return "'" + value.replace("'", "'\\''") + "'"
    return value


def heredoc_scripts(cmds):
    """Heredoc-и, записывающие shell-скрипт: [(Heredoc, имя файла)].

    Тело, уходящее через cat/tee в файл, считается данными. Исключение —
    запись скрипта: расширение или shebang как у shell-скрипта либо в той же
    строке есть команда, способная файл исполнить (шелл, source, chmod,
    запуск по пути). Тогда тело проверяется правилами, как файл скрипта.
    """
    executor = any(c.argv0 in HEREDOC_EXECUTORS or "/" in c.argv0_text
                   for c in cmds)
    found = []
    for cmd in cmds:
        if cmd.argv0 in ("echo", "printf") and cmd.stdout_file:
            # `printf '…' > run; bash run`: тот же приём, что и с heredoc, —
            # файл пишется строкой и исполняется той же командой.
            body = "\n".join(cmd.args).replace("\\n", "\n")
            script = cmd.stdout_file.endswith(SCRIPT_SUFFIXES)
            if executor or script or SCRIPT_SHEBANG_RE.match(body):
                found.append((Heredoc(body=body, kind=HEREDOC_DATA,
                                      target=cmd.stdout_file), cmd.stdout_file))
        for here in cmd.heredocs:
            if here.kind != HEREDOC_DATA:
                continue
            # У tee файл — операнд, а stdout обычно уходит в /dev/null.
            targets = [here.target] + list(cmd.operands)
            script = next((t for t in targets if t.endswith(SCRIPT_SUFFIXES)), None)
            if (executor or script
                    or SCRIPT_SHEBANG_RE.match(here.body.split("\n", 1)[0])):
                found.append((here, script or next(
                    (t for t in targets if t != "/dev/null"), here.target)))
    return found


def heredoc_script_commands(scripts):
    """Команды из тел heredoc, записывающих скрипт.

    Как и у файлов скриптов, предупреждения парсера не эскалируются: `$CC -o
    app main.c` в записываемом build.sh — обычное дело.
    """
    extra = []
    for here, target in scripts:
        inner, _warnings = parse(here.body)
        for c in inner:
            extra.append(_replace(c, origin=SCRIPT, depth=c.depth + 1,
                                  raw="heredoc → {}: {}".format(target, c.raw)))
    return extra


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


def effective_cwd(cmd, cwd):
    """Рабочий каталог команды с учётом `cd` раньше в той же строке.

    None — каталог статически неизвестен (`cd "$X"`): относительные цели такой
    команды нельзя считать «внутри проекта».
    """
    if cmd.cwd is None:
        return cwd
    if CWD_UNKNOWN in cmd.cwd or "$" in cmd.cwd:
        return None
    return expand_operand(cmd.cwd, cwd)


def is_mktemp_path(operand):
    """Операнд — путь, полученный из `$(mktemp …)` этой же строки."""
    return ((operand == MKTEMP_PATH or operand.startswith(MKTEMP_PATH + "/"))
            and ".." not in operand.split("/"))


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
