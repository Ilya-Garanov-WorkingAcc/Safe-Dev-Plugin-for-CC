#!/usr/bin/env python3
"""
hook_test_runner.py — мета-хук: запускает батарею тестов хука после каждого
его изменения (Write/Edit/MultiEdit). Регистрируется на PostToolUse.

Соглашение об именах (см. skill `hook-development`):
  • Хук-скрипт:   <.../.claude/hooks>/<name>.<ext>        ext ∈ {py, sh, js, mjs}
  • Батарея:      тот же каталог, <name>.tests.<ext>       ИЛИ <dir>/tests/<name>.tests.<ext>
  • Контракт:     батарея завершается кодом 0 = все тесты прошли; ≠0 = провал.

Поведение:
  • Отредактирован не-хук файл            → тихий выход 0 (быстрый no-op).
  • Хук изменён, батарея НЕ найдена        → systemMessage-напоминание, выход 0.
  • Батарея найдена, все тесты прошли      → короткий systemMessage «✓», выход 0.
  • Батарея найдена, есть провал           → отчёт в stderr, выход 2
                                             (PostToolUse отдаёт stderr модели как фидбэк).

Отказоустойчивость: любая ВНУТРЕННЯЯ ошибка самого раннера → выход 0 (fail-open),
чтобы не ломать сессию. Проваленные тесты хука — это НЕ внутренняя ошибка, они
осознанно дают выход 2.
"""

import sys
import os
import re
import json
import subprocess

# См. secret_redactor.py: на консолях с не-UTF8 кодировкой по умолчанию
# (cp1251/cp1252/cp437 и т.п. — типично для Windows) stdout кодирует строго
# (errors="strict") и падает с UnicodeEncodeError на кириллице/эмодзи в наших
# сообщениях, а fail-open в main() тихо проглатывает исключение — JSON-решение
# и даже сам факт «батарея не найдена»/«тесты пройдены» пропадают без следа.
for _stream in (sys.stdin, sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}
# ext -> команда запуска
RUNNERS = {
    ".py": ["python3"],
    ".sh": ["bash"],
    ".js": ["node"],
    ".mjs": ["node"],
}
HOOKS_MARKER = os.sep + ".claude" + os.sep + "hooks" + os.sep
TEST_RE = re.compile(r"\.tests?\.[^.]+$")     # foo.tests.py / foo.test.sh
TIMEOUT_S = 120


def is_under_hooks_dir(path):
    return HOOKS_MARKER in (os.path.normpath(path) + os.sep)


def is_test_file(path):
    return bool(TEST_RE.search(os.path.basename(path)))


def discover_tests(hook_path):
    """Вернуть список существующих батарей для данного хук-скрипта."""
    d = os.path.dirname(hook_path)
    stem = re.sub(r"\.[^.]+$", "", os.path.basename(hook_path))
    found = []
    for ext in RUNNERS:
        for cand in (os.path.join(d, stem + ".tests" + ext),
                     os.path.join(d, "tests", stem + ".tests" + ext)):
            if os.path.isfile(cand) and cand not in found:
                found.append(cand)
    return found


def run_battery(test_path):
    """Запустить одну батарею. Вернуть (ok, summary)."""
    ext = os.path.splitext(test_path)[1]
    cmd = RUNNERS.get(ext, ["python3"]) + [test_path]
    try:
        # encoding= (не text=True) фиксирует UTF-8 для декодирования вывода
        # батареи независимо от локали процесса/консоли.
        p = subprocess.run(cmd, capture_output=True, encoding="utf-8",
                            errors="replace", timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT после {}s: {}".format(TIMEOUT_S, test_path)
    except Exception as e:                       # интерпретатор не найден и т.п.
        return None, "не удалось запустить {}: {}".format(test_path, e)
    tail = (p.stdout + p.stderr).strip().splitlines()[-25:]
    return p.returncode == 0, "\n".join(tail)


def emit_stdout(obj):
    # ensure_ascii=True: вторая, независимая линия защиты — см. secret_redactor.py.
    sys.stdout.write(json.dumps(obj, ensure_ascii=True))


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        return 0
    data = json.loads(raw)
    if data.get("hook_event_name") != "PostToolUse":
        return 0
    if data.get("tool_name") not in WRITE_TOOLS:
        return 0
    fp = (data.get("tool_input") or {}).get("file_path")
    if not isinstance(fp, str) or not fp:
        return 0
    if not is_under_hooks_dir(fp):
        return 0

    # Что тестировать: сам тест-файл или батарею хука.
    if is_test_file(fp):
        batteries = [fp] if os.path.isfile(fp) else []
        subject = fp
    else:
        ext = os.path.splitext(fp)[1]
        if ext not in RUNNERS:                   # не исполняемый хук-скрипт
            return 0
        batteries = discover_tests(fp)
        subject = fp

    name = os.path.basename(subject)

    if not batteries:
        emit_stdout({
            "systemMessage": (
                "⚠️  Хук {} изменён, но батарея тестов не найдена. "
                "Создай {}.tests.py рядом (скилл hook-development) — "
                "изменения хуков должны проверяться тестами."
            ).format(name, re.sub(r"\.[^.]+$", "", name)),
            "suppressOutput": True,
        })
        return 0

    results = [(b, *run_battery(b)) for b in batteries]
    failed = [(b, s) for b, ok, s in results if ok is False]
    errored = [(b, s) for b, ok, s in results if ok is None]

    if failed:
        lines = ["❌ Батарея тестов хука не прошла после изменения {}:".format(name)]
        for b, s in failed:
            lines.append("  ── {} ──\n{}".format(os.path.basename(b), s))
        lines.append("Исправь хук так, чтобы все тесты снова проходили.")
        sys.stderr.write("\n".join(lines) + "\n")
        return 2

    if errored:                                  # тесты не удалось запустить — не блокируем
        emit_stdout({
            "systemMessage": "⚠️  Батарею {} не удалось запустить: {}".format(
                name, "; ".join(s for _, s in errored)),
            "suppressOutput": True,
        })
        return 0

    passed = len(results)
    emit_stdout({
        "systemMessage": "✅ Хук {}: батарея тестов пройдена ({} набор(ов)).".format(
            name, passed),
        "suppressOutput": True,
    })
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        # fail-open: внутренний сбой раннера не должен ломать сессию
        sys.exit(0)
