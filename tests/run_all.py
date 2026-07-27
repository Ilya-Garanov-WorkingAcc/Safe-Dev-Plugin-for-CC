#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_all.py — прогон всех тест-батарей плагина.

Требование TS.md §16: модулей без тест-батареи быть не должно. Этот раннер
проверяет и то, и другое: что батареи проходят и что для каждого хука и модуля
ядра батарея вообще существует.

    python3 tests/run_all.py [--quiet]
"""

import argparse
import glob
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Модули ядра, покрытые общей батареей tests/test_core.py.
CORE_COVERED = {"hookio", "config", "policy", "audit", "export", "ruleset",
                "redact", "__init__"}
# cmdparse покрыт отдельной батареей, trust — батареей config_trust.
CORE_EXTRA = {"cmdparse": "tests/test_cmdparse.py",
              "trust": "hooks/config_trust.tests.py"}


def batteries():
    found = sorted(glob.glob(os.path.join(ROOT, "hooks", "*.tests.py")))
    found += [os.path.join(ROOT, "tests", "test_core.py"),
              os.path.join(ROOT, "tests", "test_cmdparse.py")]
    return found


def check_coverage():
    """Каждый хук обязан иметь батарею; каждый модуль ядра — быть покрытым."""
    problems = []
    for path in sorted(glob.glob(os.path.join(ROOT, "hooks", "*.py"))):
        name = os.path.basename(path)
        if name.endswith(".tests.py"):
            continue
        stem = name[:-3]
        if not os.path.isfile(os.path.join(ROOT, "hooks", stem + ".tests.py")):
            problems.append("хук без батареи: hooks/{}".format(name))

    for path in sorted(glob.glob(os.path.join(ROOT, "lib", "*.py"))):
        stem = os.path.basename(path)[:-3]
        if stem in CORE_COVERED or stem in CORE_EXTRA:
            continue
        problems.append("модуль ядра без покрытия: lib/{}.py".format(stem))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Прогон всех батарей secure-dev")
    parser.add_argument("--quiet", action="store_true",
                        help="показывать только итог по каждой батарее")
    args = parser.parse_args(argv)

    print("secure-dev — прогон тест-батарей")
    print("=" * 60)

    coverage = check_coverage()
    for problem in coverage:
        print("  !! {}".format(problem))
    if not coverage:
        print("  Покрытие: у каждого хука и модуля ядра есть батарея.")
    print()

    results = []
    for battery in batteries():
        name = os.path.relpath(battery, ROOT)
        started = time.time()
        proc = subprocess.run([sys.executable, battery], capture_output=True,
                              encoding="utf-8", errors="replace")
        elapsed = time.time() - started
        ok = proc.returncode == 0
        results.append((name, ok, elapsed))

        print("[{}] {:44} {:5.1f}s".format("OK " if ok else "FAIL", name, elapsed))
        if not ok or not args.quiet:
            tail = [line for line in (proc.stdout or "").splitlines()
                    if "FAIL" in line or line.startswith("SUMMARY")]
            for line in tail[-12:]:
                print("        {}".format(line))
            if (proc.stderr or "").strip():
                print("        stderr: {}".format(proc.stderr.strip()[:300]))

    failed = [name for name, ok, _ in results if not ok]
    print("=" * 60)
    print("Батарей: {}, провалов: {}, общее время: {:.1f}s".format(
        len(results), len(failed), sum(t for _, _, t in results)))
    if failed:
        print("Провалились: {}".format(", ".join(failed)))
    if coverage:
        print("Проблемы покрытия: {}".format(len(coverage)))
    return 1 if (failed or coverage) else 0


if __name__ == "__main__":
    sys.exit(main())
