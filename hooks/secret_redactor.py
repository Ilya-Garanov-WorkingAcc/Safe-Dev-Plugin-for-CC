#!/usr/bin/env python3
"""
secret_redactor.py — единый хук Claude Code для анонимизации секретов.

Регистрируется на два события (одним и тем же файлом, ветвление по
hook_event_name из stdin):

  • PreToolUse  — ДО выполнения инструмента (контроль исходящих каналов).
  • PostToolUse — ПОСЛЕ выполнения (очистка вывода до попадания в контекст модели).

Поведение (согласовано с пользователем):
  • Исходящие каналы (Bash / WebFetch / WebSearch / MCP) с секретом в аргументах
        → permissionDecision: "ask"  (спрашиваем пользователя; команду НЕ портим,
          чтобы не ломать легальные аутентифицированные вызовы).
  • Write / Edit / MultiEdit с секретом в содержимом
        → только systemMessage-предупреждение + запись в аудит; контент НЕ меняем.
  • Любой вывод инструмента (PostToolUse) с секретом
        → заменяем секрет на [REDACTED:TYPE] через updatedToolOutput
          (модель видит плейсхолдер вместо реального значения).

Аудит: ~/.claude/safe-development-audit.log — секреты пишутся только в
МАСКИРОВАННОМ виде (первые 4 и последние 2 символа), сам секрет в лог не попадает.
Путь лога ФИКСИРОВАН вне каталога плагина: при установке через плагин файлы
хука лежат в кэше плагина (~/.claude/plugins/cache/.../), который переписывается
и чистится при каждом обновлении — лог рядом с __file__ был бы потерян.

Отказоустойчивость: любая внутренняя ошибка → тихий выход 0 (fail-open),
чтобы хук никогда не блокировал работу Claude Code.
"""

import sys
import os
import re
import json
import datetime

AUDIT_LOG = os.path.expanduser(os.path.join("~", ".claude", "safe-development-audit.log"))

# --- Классификация инструментов ---------------------------------------------
EGRESS_TOOLS = {"Bash", "WebFetch", "WebSearch"}   # + любой инструмент mcp__*
WRITE_TOOLS = {"Write", "Edit", "MultiEdit"}

# Какие поля аргументов сканировать у "обычных" исходящих инструментов.
EGRESS_FIELDS = {
    "Bash": ["command"],
    "WebFetch": ["url", "prompt"],
    "WebSearch": ["query"],
}
WRITE_FIELDS = ["content", "new_string"]           # + MultiEdit.edits[].new_string

PLACEHOLDER = "[REDACTED:{}]"

# --- Правила детекции секретов ----------------------------------------------
# Кортеж: (имя_типа, regex, группа_для_замены)
#   группа 0  → заменить всё совпадение (сам секрет = всё совпадение);
#   группа >0 → заменить только эту группу (напр. только пароль внутри URL,
#               оставив имя переменной/схему видимыми модели).
_RAW_RULES = [
    # Приватные ключи (многострочный блок) — проверяем первым.
    ("PRIVATE_KEY",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
     r"[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
     0),
    ("AWS_ACCESS_KEY_ID",
     r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", 0),
    ("GITHUB_TOKEN",
     r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0),
    ("GITHUB_PAT",
     r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", 0),
    ("STRIPE_KEY",
     r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0),
    ("OPENAI_ANTHROPIC_KEY",
     r"\bsk-(?:ant-)?(?:proj-)?[A-Za-z0-9_-]{20,}\b", 0),
    ("SLACK_TOKEN",
     r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", 0),
    ("SLACK_WEBHOOK",
     r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+", 0),
    ("GOOGLE_API_KEY",
     r"\bAIza[0-9A-Za-z_-]{35}\b", 0),
    ("GOOGLE_OAUTH_TOKEN",
     r"\bya29\.[0-9A-Za-z_-]{20,}", 0),
    ("NPM_TOKEN",
     r"\bnpm_[A-Za-z0-9]{36}\b", 0),
    ("JWT",
     r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b", 0),
    # Bearer <token> — заменяем только сам токен (группа 1).
    ("BEARER_TOKEN",
     r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 1),
    # proto://user:PASSWORD@host — заменяем только пароль (группа 1).
    ("URL_CREDENTIALS",
     r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:([^\s:@/]{6,})@", 1),
    # ИМЯ_С_SECRET/TOKEN/PASSWORD/... = значение — заменяем значение (группа 2).
    ("ENV_SECRET",
     r"\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|"
     r"ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*)\s*[=:]\s*"
     r"[\"']?([A-Za-z0-9_\-+/=~]{6,})", 2),
]
RULES = [(name, re.compile(pat), grp) for name, pat, grp in _RAW_RULES]


def mask(secret):
    """Маскированное превью для аудита: сам секрет наружу не отдаём."""
    secret = secret.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "…" + secret[-2:]


def redact(text):
    """Чистит одну строку. Возвращает (new_text, findings=[(type, masked), ...])."""
    findings = []

    for name, rx, grp in RULES:
        def _sub(m, _name=name, _grp=grp):
            val = m.group(_grp)
            if val is None:
                return m.group(0)
            if "REDACTED" in val:            # значение уже вычищено ранее — пропускаем
                return m.group(0)
            findings.append((_name, mask(val)))
            ph = PLACEHOLDER.format(_name)
            if _grp == 0:
                return ph
            full = m.group(0)
            start = m.start(_grp) - m.start(0)
            end = m.end(_grp) - m.start(0)
            return full[:start] + ph + full[end:]

        text = rx.sub(_sub, text)

    return text, findings


def redact_any(obj):
    """Рекурсивно чистит строки в произвольной JSON-структуре.
    Возвращает (new_obj, findings)."""
    findings = []
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        out = []
        for item in obj:
            new_item, f = redact_any(item)
            out.append(new_item)
            findings.extend(f)
        return out, findings
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            new_value, f = redact_any(value)
            out[key] = new_value
            findings.extend(f)
        return out, findings
    return obj, findings


def audit(event, tool, action, findings, session_id, extra=""):
    """Запись факта срабатывания в аудит-лог (без реальных секретов)."""
    try:
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        types = ",".join(sorted({t for t, _ in findings})) or "-"
        previews = "; ".join("{}:{}".format(t, p) for t, p in findings)
        line = ("{ts}\t{ev}\t{tool}\t{act}\tsession={sid}\ttypes={types}"
                "\tcount={cnt}\t{prev}\t{extra}\n").format(
                    ts=ts, ev=event, tool=tool, act=action, sid=session_id,
                    types=types, cnt=len(findings), prev=previews, extra=extra)
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
        try:
            os.chmod(AUDIT_LOG, 0o600)
        except OSError:
            pass
    except Exception:
        pass


def emit(obj):
    """Отдать JSON-решение хука и выйти (код 0 => JSON парсится Claude Code)."""
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.exit(0)


def handle_pre(data, tool, sid):
    tool_input = data.get("tool_input") or {}
    is_mcp = tool.startswith("mcp__")

    # 1) Запись в файл — только предупреждаем, содержимое не трогаем.
    if tool in WRITE_TOOLS:
        chunks = []
        for field in WRITE_FIELDS:
            value = tool_input.get(field)
            if isinstance(value, str):
                chunks.append(value)
        for edit in (tool_input.get("edits") or []):        # MultiEdit
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                chunks.append(edit["new_string"])
        _, findings = redact("\n".join(chunks))
        if findings:
            audit("PreToolUse", tool, "WARN_WRITE", findings, sid)
            types = ", ".join(sorted({t for t, _ in findings}))
            emit({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                },
                "systemMessage": (
                    "⚠️  Секрет(ы) в записываемом файле: {}. "
                    "Запись разрешена как есть — проверь перед коммитом."
                ).format(types),
            })
        sys.exit(0)

    # 2) Исходящие каналы — спрашиваем пользователя (не портим команду).
    if tool in EGRESS_TOOLS or is_mcp:
        if is_mcp:
            _, findings = redact_any(tool_input)
        else:
            chunks = []
            for field in EGRESS_FIELDS.get(tool, []):
                value = tool_input.get(field)
                if isinstance(value, str):
                    chunks.append(value)
            _, findings = redact("\n".join(chunks))
        if findings:
            audit("PreToolUse", tool, "ASK_EGRESS", findings, sid)
            types = ", ".join(sorted({t for t, _ in findings}))
            emit({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": (
                        "\U0001f512 Обнаружены секреты ({}) в исходящем вызове {}. "
                        "Возможна утечка данных. Подтверди, только если действительно "
                        "намерен отправить эти данные."
                    ).format(types, tool),
                }
            })
        sys.exit(0)

    sys.exit(0)


def handle_post(data, tool, sid):
    resp = data.get("tool_response")
    if resp is None:
        sys.exit(0)
    new_resp, findings = redact_any(resp)
    if findings:
        audit("PostToolUse", tool, "REDACT_OUTPUT", findings, sid)
        types = ", ".join(sorted({t for t, _ in findings}))
        emit({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": new_resp,
                "additionalContext": (
                    "[security] В выводе {} были вычищены секреты ({}); "
                    "модель видит плейсхолдеры вместо реальных значений."
                ).format(tool, types),
            },
            "systemMessage": (
                "\U0001f512 Из вывода {} удалено секретов: {} ({})."
            ).format(tool, len(findings), types),
        })
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)
    data = json.loads(raw)
    event = data.get("hook_event_name", "")
    tool = data.get("tool_name", "")
    sid = data.get("session_id", "?")
    if event == "PreToolUse":
        handle_pre(data, tool, sid)
    elif event == "PostToolUse":
        handle_post(data, tool, sid)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:                 # fail-open: не ломаем работу Claude Code
        try:
            audit("ERROR", "-", "EXCEPTION", [], "?", extra=repr(e)[:200])
        except Exception:
            pass
        sys.exit(0)
