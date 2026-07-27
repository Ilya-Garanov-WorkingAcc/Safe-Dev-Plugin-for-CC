#!/usr/bin/env python3
"""redact.py — детекция и маскирование секретов (v1.x → на общее ядро).

Инвариант TS.md §1.4: реальное значение секрета не покидает процесс. Наружу
уходит либо `[REDACTED:TYPE]`, либо `mask()` — первые 4 и последние 2 символа.

Поведение идентично v1.x: правила те же и в том же порядке, только теперь
приезжают из rules/secrets.json (ADR-005). Тест-батарея v1.x гоняется на этом
коде без правок — это и есть доказательство отсутствия регрессии (PLAN.md 0.10).
"""

from lib import ruleset

PLACEHOLDER = "[REDACTED:{}]"


def rules():
    return ruleset.load("secrets")


def mask(secret):
    """Маскированное превью для аудита: сам секрет наружу не отдаём."""
    secret = secret.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "…" + secret[-2:]


def redact(text):
    """Чистит одну строку. Возвращает (new_text, findings=[(type, masked), ...])."""
    if not isinstance(text, str) or not text:
        return text, []
    findings = []

    for rule in rules():
        match = rule["match"]
        if match["kind"] != "regex":
            continue
        rx = match["_rx"]
        grp = match.get("group", 0)
        name = rule.get("secret_type") or rule["id"]

        def _sub(m, _name=name, _grp=grp):
            val = m.group(_grp)
            if val is None:
                return m.group(0)
            if "REDACTED" in val:        # значение уже вычищено ранее — пропускаем
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
            new_item, found = redact_any(item)
            out.append(new_item)
            findings.extend(found)
        return out, findings
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            new_value, found = redact_any(value)
            out[key] = new_value
            findings.extend(found)
        return out, findings
    return obj, findings


def types_of(findings):
    return sorted({t for t, _ in findings})


def masked_records(findings):
    """Формат поля `masked` записи аудита (TS.md §6.1)."""
    seen, out = set(), []
    for kind, preview in findings:
        key = (kind, preview)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": kind, "preview": preview})
    return out


def rule_for_type(secret_type):
    for rule in rules():
        if rule.get("secret_type") == secret_type:
            return rule
    return None


def worst_severity(findings):
    severities = []
    for kind, _ in findings:
        rule = rule_for_type(kind)
        if rule:
            severities.append(rule["severity"])
    return ruleset.worst(severities) or "MEDIUM"
