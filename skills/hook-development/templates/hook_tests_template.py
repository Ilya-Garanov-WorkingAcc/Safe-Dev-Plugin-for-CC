#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
<name>.tests.py — батарея для <name>.py.
Контракт: печатает PASS/FAIL, exit 0 если все прошли, иначе exit 1.
Запускается авто-раннером после каждого изменения <name>.py, а также вручную:
    python3 <name>.tests.py
"""
import json
import os
import sys
import subprocess
import importlib.util

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "<name>.py")

# Импорт чистых функций хука для юнит-проверок (без побочных эффектов main()).
spec = importlib.util.spec_from_file_location("hook", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)

FAILS = []
def check(name, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL':6}] {name:34} {detail}")
    if not ok:
        FAILS.append(name)

def run_event(payload):
    """Полный прогон хука через subprocess со stdin-JSON."""
    p = subprocess.run(["python3", HOOK], input=json.dumps(payload),
                       capture_output=True, text=True)
    out = p.stdout.strip()
    try:
        return (json.loads(out) if out else {}), p.returncode
    except json.JSONDecodeError:
        return {"__raw__": out}, p.returncode


# --- 1. Позитивы: то, что хук ДОЛЖЕН обрабатывать ----------------------------
# check("detects X", ...)

# --- 2. Истинные негативы: безобидный вход не трогается -----------------------
# check("ignores benign Y", ...)

# --- 3. Ложные срабатывания на РЕАЛЬНЫХ данных (главное!) ---------------------
# Прогони хук на кусках настоящего кода/конфига/.env, которые он увидит в бою.
# check("real code left intact", ...)

# --- 4. Форма вывода: структурный и строковый вход ---------------------------
# res,_ = run_event({"hook_event_name":"PostToolUse","tool_name":"Bash",
#                    "tool_response":{"stdout":"...","stderr":""}})
# check("dict output preserved", isinstance(res.get(...), dict))

# --- 5. Решения и коды выхода на границах -------------------------------------
# res,_ = run_event({"hook_event_name":"PreToolUse", ...})
# check("decision correct", res.get("hookSpecificOutput",{}).get("permissionDecision")=="ask")

# --- 6. Отказоустойчивость ----------------------------------------------------
p = subprocess.run(["python3", HOOK], input="",       capture_output=True, text=True); check("empty stdin -> rc0", p.returncode == 0)
p = subprocess.run(["python3", HOOK], input="{bad",   capture_output=True, text=True); check("malformed json -> rc0", p.returncode == 0)
_, rc = run_event({"hook_event_name": "SessionStart"});                                check("unknown event -> rc0", rc == 0)

print("\nSUMMARY:", "ALL PASSED" if not FAILS else f"FAILED({len(FAILS)}) {FAILS}")
sys.exit(1 if FAILS else 0)
