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

# Значение, которое ЦЕЛИКОМ состоит из наших плейсхолдеров, не переобрабатываем
# (иначе получили бы вложенные [REDACTED:[REDACTED:…]]). Проверка точная: прежняя
# `"REDACTED" in val` срабатывала по подстроке и открывала проход — настоящий
# секрет, приклеенный к плейсхолдеру (`REDACTEDhunter2`, `[x]realsecret`),
# пропускался целиком (ревью 28.10.2026, F5). Теперь хвост-секрет редактируется.
_ONLY_PLACEHOLDER_RE = re.compile(r"^(?:\[REDACTED:[^\]]*\])+$")

# Значения, которые не являются секретом, даже если ключ назван «...secret»:
# типы, литералы, шаблоны-плейсхолдеры, схемы авторизации. Иначе `token:
# string`, `Authorization: Bearer <token>`, `password = None` давали ложное
# срабатывание и портили код, который читает модель (аудит 03.10.2026, C8).
#
# Границы ужесточены после ревью 27.10.2026, затем РАДИКАЛЬНО сужены после
# независимого ревью 28.10.2026 (вариант A). Прежние shape-ветки «путь / URL /
# $-ссылка / код-референс / os.environ / env» пропускали НАСТОЯЩИЙ секрет нужной
# формы: `PASSWORD=/home/hunter2x`, `=config.hunter2`, `=$Pa55w0rd`,
# `=https://x.com/hunter2`. Структурно отличить такой низкоэнтропийный секрет от
# легитимного кода/пути НЕЛЬЗЯ (те же слова, та же длина), а вето `_looks_secret`
# ловит только высокую энтропию. Поэтому по инварианту TS.md §1.4 «сомнение →
# редактировать» все shape-ветки удалены: whitelist пропускает ТОЛЬКО имена
# типов/литералы и явные плейсхолдеры (`<...>`, `your-...-here`, `[redacted:...]`,
# короткое число). Цена — осознанная over-redaction код-референсов и путей под
# секретным ключом; это вывод, который читает агент, на выполнение команд не
# влияет. Слабые литералы-значения token/secret/password убраны: это топ слабых
# паролей, а не только имена типов.
_KEYWORD_VALUE_RE = re.compile(
    r"^(?:string|str|int|integer|bool|boolean|true|false|null|none|nil|required|"
    r"optional|number|object|array|any|void|undefined|empty|bearer|basic|digest|"
    r"placeholder|example|"
    r"redacted|x{3,}|"
    # Короткое число/константа (порт, таймаут, флаг). Длинные цифровые значения
    # НЕ в whitelist: числовой пароль/PIN выглядит так же.
    r"[+-]?\d{1,3}(?:\.\d{1,3})?|"
    # Плейсхолдер: `your` + ТОЛЬКО слова-заполнители (your-secret-key-here,
    # your-api-key). Настоящий ключ yourSuperSecretKey99 имеет случайный хвост,
    # не состоящий из этих слов, и редактируется.
    r"your(?:[-_]?(?:token|key|secret|password|api|credential|value|name|pass|"
    r"placeholder|here|example|sample|dummy|changeme|goes|real))+|"
    # Явные плейсхолдеры `<...>` и наш собственный `[redacted:...]`. Высоко-
    # энтропийное содержимое `<...>` добивает вето _looks_secret ниже.
    r"<[^>]*>|\[redacted:[^\]]*\])$", re.I)


_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]+")


def _looks_secret(value):
    """Значение содержит токен, похожий на СЕКРЕТ (высокая энтропия)?

    Вето поверх whitelist (ревью 28.10.2026): ветки «путь» и «ссылка на код»
    пропускали `config.A1B2C3…`, `/var/Zk3q9…` — настоящий секрет нужной формы.
    Легитимные идентификаторы/пути такого токена не содержат: `database_url`,
    `SECRET_KEY`, `/home/user` разбиваются `_`/`.`/`/` на короткие сегменты.
    Сомнение трактуется в пользу редактирования (инвариант TS.md §1.4).
    """
    for run in _ALNUM_RUN_RE.findall(value):
        if len(run) >= 16:
            return True                          # длинный alnum-блоб
        if len(run) >= 10 and sum(c.isdigit() for c in run) >= 2:
            return True                          # смесь букв и цифр подлиннее
        if len(run) >= 11 and run.isupper():
            return True                          # длинная ПРОПИСНАЯ без разделителя
    return False


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
            if _ONLY_PLACEHOLDER_RE.match(val):   # уже наш плейсхолдер целиком
                return m.group(0)
            if (_name == "ENV_SECRET" and _KEYWORD_VALUE_RE.match(val.strip())
                    and not _looks_secret(val)):
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
