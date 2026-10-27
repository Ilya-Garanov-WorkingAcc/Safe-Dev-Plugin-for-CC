#!/usr/bin/env python3
"""redact.py — детекция и маскирование секретов (v1.x → на общее ядро).

Инвариант TS.md §1.4: реальное значение секрета не покидает процесс. Наружу
уходит либо `[REDACTED:TYPE]`, либо `mask()` — первые 4 и последние 2 символа.

Поведение идентично v1.x: правила те же и в том же порядке, только теперь
приезжают из rules/secrets.json (ADR-005). Тест-батарея v1.x гоняется на этом
коде без правок — это и есть доказательство отсутствия регрессии (PLAN.md 0.10).
"""

import re

from lib import ruleset

PLACEHOLDER = "[REDACTED:{}]"

# Значения, которые не являются секретом, даже если ключ назван «...secret»:
# типы, литералы, шаблоны-плейсхолдеры, схемы авторизации. Иначе `token:
# string`, `Authorization: Bearer <token>`, `password = None` давали ложное
# срабатывание и портили код, который читает модель (аудит 03.10.2026, C8).
#
# Границы ужесточены после ревью 27.10.2026: прежние ветки «путь/число/URL/
# код» пропускали настоящие секреты (`PASSWORD=/a/b`, `SECRET=config.Abc123`,
# числовые PIN, токен в query URL). Теперь каждая ветка описывает ровно ту
# форму, которой настоящий ключ/токен/пароль не бывает; сомнение трактуется в
# пользу редактирования (инвариант TS.md §1.4 — лучше лишняя маска, чем утечка).
# Сегменты-идентификаторы проверяются с учётом регистра через (?-i:…), иначе
# внешний re.I стёр бы различие «нормальный идентификатор / случайный токен».
_KEYWORD_VALUE_RE = re.compile(
    r"^(?:string|str|int|integer|bool|boolean|true|false|null|none|nil|required|"
    r"optional|number|object|array|any|void|undefined|empty|bearer|basic|digest|"
    r"token|secret|password|placeholder|example|"
    r"redacted|x{3,}|"
    # Короткое число/константа (порт, таймаут, флаг). Длинные цифровые значения
    # НЕ в whitelist: числовой пароль/PIN выглядит так же.
    r"[+-]?\d{1,3}(?:\.\d{1,3})?|"
    # Путь только под известным системным корнем и из безопасных символов.
    # Одноимённый секрет (`/Zk3q9…`, `/p@ss!`) и относительные `./x`, `~x` сюда
    # не попадают и редактятся.
    r"/(?:home|usr|var|etc|opt|tmp|srv|bin|sbin|lib|lib64|mnt|media|dev|proc|"
    r"sys|root|boot|run|Users|private|data)(?:/[\w.\- ]*)*|"
    # URL без учётных данных и без query/fragment: в query/`#` прячут токен.
    r"[a-z][a-z0-9+.\-]*://[^@\s?#]*|"
    # Плейсхолдер: `your` + ТОЛЬКО слова-заполнители (your-secret-key-here,
    # your-api-key). Настоящий ключ yourSuperSecretKey99 имеет случайный хвост,
    # не состоящий из этих слов, и редактируется.
    r"your(?:[-_]?(?:token|key|secret|password|api|credential|value|name|pass|"
    r"placeholder|here|example|sample|dummy|changeme|goes|real))+|" +
    # Ссылка на код: self.x, request.META, config.database_url. Каждый сегмент —
    # нормальный идентификатор (всё строчное ИЛИ всё ПРОПИСНОЕ): случайный токен
    # config.Abc123xyzQ и app.9fK2 (цифра сразу после точки) не проходят.
    r"(?:self|cls|this|req|request|res|response|os|sys|io|process|config|"
    r"settings|ctx|context|window|document|globals|locals|params|conf|app)"
    r"(?:\.(?-i:[a-z_][a-z0-9_]*|[A-Z_][A-Z0-9_]*))+(?:\(\)|\[[^\]]*\])?|"
    r"os\.environ[\w.()\[\]\"']*|process\.env[\w.()\[\]\"']*|"
    r"<[^>]*>|\$\{?[\w.]+\}?|"
    r"env\.(?-i:[a-z_][a-z0-9_]*|[A-Z_][A-Z0-9_]*)|\[redacted:[^\]]*\])$", re.I)


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
            if _name == "ENV_SECRET" and _KEYWORD_VALUE_RE.match(val.strip()):
                return m.group(0)            # тип/литерал/плейсхолдер, не секрет
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
