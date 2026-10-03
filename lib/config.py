#!/usr/bin/env python3
"""config.py — двухуровневая конфигурация (TS.md §3, ADR-008).

Одного редактируемого файла недостаточно: конфиг, который правит сотрудник, —
это политика, которую правит сотрудник.

    policy.json  (репозиторий плагина)  ──┐
                                          ├─► merge() ─► эффективная политика
    ~/.claude/secure-dev.local.json     ──┘

Инвариант: локальный файл может только УЖЕСТОЧИТЬ. Попытка смягчить
игнорируется молча для пользователя и громко для аудита
(LOCAL_OVERRIDE_REJECTED). Иначе разграничение уровней ничего не значит.

Отклонение от TS.md §3.3, зафиксированное осознанно: эталонный хеш политики
хранится в policy.lock.json рядом с policy.json, а не внутри plugin.json.
Причина — `claude plugin validate` проверяет манифест по своей схеме, и лишнее
поле в нём стоило бы совместимости с будущими версиями Claude Code. Отдельный
файл лочится тем же релизным скриптом (tools/seal_policy.py) и даёт ровно тот
же эффект: расхождение видно в heartbeat как policy_tampered.
"""

import datetime
import hashlib
import json
import os

from lib import hookio

LEVELS = ("audit", "warn", "strict")

LOCAL_PATH = os.path.expanduser(os.path.join("~", ".claude", "secure-dev.local.json"))

# Что сотруднику разрешено трогать у себя (TS.md §3.2).
LOCAL_ALLOWED = ("level", "rule_levels", "extra_rules", "ui")
LOCAL_UI_ALLOWED = ("banner", "verbosity")
# Что запрещено явно — попытка правки пишется в аудит, а не игнорируется тихо.
LOCAL_FORBIDDEN = ("audit", "exemptions", "exclusions", "protected_branches",
                   "llm", "session_memory", "policy_version", "schema_version")

_CACHE = None
_PROBLEMS = []
_POLICY_READ_FAILED = False
_SEAL_CACHE = None

DEFAULTS = {
    "schema_version": 1,
    "policy_version": "unknown",
    "level": "audit",
    "rule_levels": {},
    "protected_branches": ["main", "master"],
    "exclusions": [],
    "exemptions": [],
    "session_memory": {"enabled": True, "ttl_hours": 24},
    "llm": {"enabled": False, "model": "haiku", "max_calls_per_session": 20},
    "audit": {"retention_days": 30,
              "export": {"type": "none", "path": None, "url": None, "token_env": None}},
    "ui": {"banner": True, "verbosity": "normal"},
}


# --- Пути ------------------------------------------------------------------

def policy_path():
    return os.path.join(hookio.plugin_root(), "policy.json")


def lock_path():
    return os.path.join(hookio.plugin_root(), "policy.lock.json")


# --- Строгость -------------------------------------------------------------

def strictness(level_name):
    try:
        return LEVELS.index(level_name)
    except ValueError:
        return 0


def harder(a, b):
    """Более строгий из двух уровней."""
    return a if strictness(a) >= strictness(b) else b


# --- Загрузка --------------------------------------------------------------

def load():
    """Эффективная политика. Кешируется на время жизни процесса."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    policy = _read_policy()
    local, found = _read_local(policy)
    _CACHE = _merge(policy, local)
    _PROBLEMS.extend(found)
    for rule_id, target in found:
        _report(rule_id, target)
    return _CACHE


def reset_cache():
    """Только для тестов и CLI: политика перечитывается между сценариями."""
    global _CACHE, _SEAL_CACHE, _POLICY_READ_FAILED
    _CACHE = None
    _SEAL_CACHE = None
    _POLICY_READ_FAILED = False
    del _PROBLEMS[:]


def _read_policy():
    global _POLICY_READ_FAILED
    merged = json.loads(json.dumps(DEFAULTS))       # глубокая копия дефолтов
    data = {}
    try:
        with open(policy_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        # policy.json нечитаем или испорчен. Молча падать на дефолтный audit
        # нельзя: это обход через порчу политики (аудит 03.10.2026, L4).
        # Помечаем отказ — level() поднимет пол до strict.
        _POLICY_READ_FAILED = True
        data = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if key.startswith("$"):
                continue
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key].update(value)
            else:
                merged[key] = value
    return merged


def _read_local(policy):
    """Разбор личного файла. Возвращает (принятые значения, проблемы)."""
    found = []
    try:
        with open(LOCAL_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return {}, found
    except Exception:
        return {}, [("LOCAL_FILE_INVALID", LOCAL_PATH)]
    if not isinstance(raw, dict):
        return {}, [("LOCAL_FILE_INVALID", LOCAL_PATH)]

    accepted = {}
    for key, value in raw.items():
        if key in LOCAL_FORBIDDEN:
            found.append(("LOCAL_OVERRIDE_REJECTED", key))
            continue
        if key not in LOCAL_ALLOWED:
            found.append(("LOCAL_OVERRIDE_UNKNOWN", key))
            continue

        if key == "level":
            if value not in LEVELS:
                found.append(("LOCAL_OVERRIDE_UNKNOWN", "level=" + str(value)))
            elif strictness(value) > strictness(policy.get("level", "audit")):
                accepted["level"] = value
            else:
                found.append(("LOCAL_OVERRIDE_REJECTED", "level=" + str(value)))

        elif key == "rule_levels":
            if not isinstance(value, dict):
                found.append(("LOCAL_OVERRIDE_UNKNOWN", "rule_levels"))
                continue
            keep = {}
            for rule_key, rule_level in value.items():
                if rule_level not in LEVELS:
                    found.append(("LOCAL_OVERRIDE_UNKNOWN",
                                  "rule_levels." + str(rule_key)))
                    continue
                current = policy.get("rule_levels", {}).get(
                    rule_key, policy.get("level", "audit"))
                if strictness(rule_level) > strictness(current):
                    keep[rule_key] = rule_level
                else:
                    found.append(("LOCAL_OVERRIDE_REJECTED",
                                  "rule_levels." + str(rule_key)))
            if keep:
                accepted["rule_levels"] = keep

        elif key == "extra_rules":
            keep = [r for r in (value if isinstance(value, list) else [])
                    if _is_denying_rule(r)]
            dropped = (len(value) if isinstance(value, list) else 0) - len(keep)
            if dropped > 0:
                found.append(("LOCAL_OVERRIDE_UNKNOWN", "extra_rules"))
            if keep:
                accepted["extra_rules"] = keep

        elif key == "ui":
            if not isinstance(value, dict):
                found.append(("LOCAL_OVERRIDE_UNKNOWN", "ui"))
                continue
            keep = {k: v for k, v in value.items() if k in LOCAL_UI_ALLOWED}
            for k in value:
                if k not in LOCAL_UI_ALLOWED:
                    found.append(("LOCAL_OVERRIDE_UNKNOWN", "ui." + str(k)))
            if keep:
                accepted["ui"] = keep

    return accepted, found


def _is_denying_rule(rule):
    """Локальные правила могут только запрещать: у них обязана быть severity и
    полный набор обучающих полей, как у любого правила (TS.md §5.1)."""
    if not isinstance(rule, dict):
        return False
    required = ("id", "class", "severity", "match", "message", "remediation", "reference")
    if any(f not in rule for f in required):
        return False
    # Только kind=command. Регулярное выражение из файла, который может
    # записать агент, — это способ повесить хук на каждой Bash-команде
    # (`(a+)+$`) и получить пропуск по таймауту. В `args_regex_any` и
    # `dest_regex_any` та же опасность, поэтому в локальных правилах запрещены
    # и они.
    match = rule.get("match")
    if not isinstance(match, dict) or match.get("kind") != "command":
        return False
    if any(key.endswith("regex_any") for key in match):
        return False
    return rule["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def _merge(policy, local):
    cfg = json.loads(json.dumps(policy))
    cfg["_local_floor"] = None
    if "level" in local:
        # Локальный `level` — не замена дефолта, а ПОЛ строгости: иначе
        # ужесточение глобального уровня не действовало бы на классы,
        # перечисленные в rule_levels, и инвариант «только ужесточать»
        # обходился бы одним лишним ключом в policy.json.
        cfg["_local_floor"] = local["level"]
    if "rule_levels" in local:
        cfg["rule_levels"] = dict(cfg.get("rule_levels", {}))
        cfg["rule_levels"].update(local["rule_levels"])
    if "extra_rules" in local:
        cfg["extra_rules"] = local["extra_rules"]
    if "ui" in local:
        cfg["ui"] = dict(cfg.get("ui", {}))
        cfg["ui"].update(local["ui"])
    return cfg


def _report(rule_id, target):
    try:
        from lib import audit
        audit.write({
            "kind": "event", "hook": "config", "rule": rule_id,
            "class": "internal", "severity": "LOW", "action": "logged",
            "target": str(target),
        }, {})
    except Exception:
        pass


def problems():
    load()
    return list(_PROBLEMS)


# --- Резолв уровня ---------------------------------------------------------

def effective_level(rule_id, rule_class=None):
    """Уровень для конкретного правила.

    Точность важнее общности: id правила выигрывает у класса, класс — у
    глобального дефолта. Поверх всего применяется локальный пол строгости.
    """
    cfg = load()
    levels = cfg.get("rule_levels") or {}
    if rule_id in levels:
        resolved = levels[rule_id]
    elif rule_class and rule_class in levels:
        resolved = levels[rule_class]
    else:
        resolved = cfg.get("level", "audit")
    floor = cfg.get("_local_floor")
    if floor:
        resolved = harder(resolved, floor)
    return harder(resolved, integrity_floor())


def integrity_floor():
    """Пол строгости, навязанный целостностью: strict при нечитаемой политике,
    подмене печати policy.json или кода плагина. Иначе «audit»."""
    # policy.json нечитаем или его печать не совпала — политику определить
    if _POLICY_READ_FAILED:
        return "strict"
    if seal_status() == "tampered":
        return "strict"
    return "audit"


def level():
    cfg = load()
    return harder(harder(cfg.get("level", "audit"), cfg.get("_local_floor") or "audit"),
                  integrity_floor())


def ui():
    return load().get("ui") or {}


def audit_cfg():
    return load().get("audit") or {}


def llm_cfg():
    return load().get("llm") or {}


def session_memory_cfg():
    return load().get("session_memory") or {}


def protected_branches():
    return load().get("protected_branches") or []


def extra_rules():
    return load().get("extra_rules") or []


def policy_version():
    return load().get("policy_version", "unknown")


# --- Исключения ------------------------------------------------------------

def is_excluded(path, cwd=None):
    """Тестовые файлы и фикстуры — вне проверок содержимого.

    В secure-claude-code это была переменная окружения; здесь — конфиг: список
    исключений относится к политике, а не к запуску.

    Паттерны `exclusions` (`**/tests/**`, `**/fixtures/**` и т.п.) описывают
    расположение ВНУТРИ репозитория. Claude Code передаёт `tool_input.file_path`
    абсолютным путём — без приведения к пути относительно `cwd` совпадение
    ловится по случайным родительским каталогам ВНЕ репозитория: у кого угодно,
    чей домашний каталог или путь до проекта содержит сегмент `test`
    (`~/test/…`, `/tmp/test-42/…`, CI-раннеры вида `/test/workdir` — обычное
    дело), `**/test/**` молча выключает проверку контента для всего проекта.
    Найдено боевым прогоном через реальный `claude` CLI: injection_scanner
    ни разу не сработал на файле в каталоге `.../projects/test/...`, хотя вне
    хука `scan()` на тот же текст находил инъекцию с уверенностью high —
    юнит-тесты этого не поймали, потому что сами не запускаются из пути,
    содержащего `test` выше корня репозитория.
    """
    if not path:
        return False
    from lib import ruleset
    rel = path
    if cwd and os.path.isabs(path):
        try:
            candidate = os.path.relpath(path, cwd)
        except ValueError:
            candidate = None
        if candidate is None or candidate.startswith(".."):
            return False   # путь вне репозитория — не тестовая фикстура проекта
        rel = candidate
    return ruleset.any_glob(load().get("exclusions") or [], rel)


def exemption_for(rule_id, target, targets=None):
    """Действующее исключение для пары (правило, цель) либо None.

    Просроченное исключение не применяется и пишет EXEMPTION_EXPIRED — это не
    позволяет исключению «зависнуть» навсегда (TS.md §4.4).

    `targets` — все цели команды в раскрытом виде: исключение с `target_glob`
    действует, только если ему удовлетворяет каждая; пустой список — цели есть,
    но исключению не подлежат. None — вызывающий цели не раскрывал и передаёт
    одну `target` (прежнее поведение).
    """
    from lib import ruleset
    today = datetime.date.today()
    checked = (list(targets) if targets is not None
               else ([target] if target else []))
    for item in load().get("exemptions") or []:
        if item.get("rule") != rule_id:
            continue
        glob = item.get("target_glob")
        if glob and (not checked or not all(
                isinstance(t, str) and ruleset.glob_match(glob, t) for t in checked)):
            continue
        expires = item.get("expires")
        try:
            expired = datetime.datetime.strptime(expires, "%Y-%m-%d").date() < today
        except Exception:
            expired = True
        if expired:
            _report("EXEMPTION_EXPIRED", rule_id)
            continue
        return item
    return None


# --- Целостность политики --------------------------------------------------

def policy_sha256():
    """sha256 фактического policy.json — идёт в heartbeat."""
    try:
        with open(policy_path(), "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except Exception:
        return None


def code_sha256():
    """sha256 манифеста файлов плагина — тот же расчёт, что в seal_policy."""
    import glob as _glob
    entries = []
    root = hookio.plugin_root()
    for pat in ("lib/*.py", "hooks/*.py", "rules/*.json", "policy.json",
                "policy.schema.json", "bin/secure-dev", "hooks/hooks.json"):
        for path in sorted(_glob.glob(os.path.join(root, pat))):
            if path.endswith(".tests.py"):
                continue
            try:
                with open(path, "rb") as fh:
                    entries.append("{}:{}".format(
                        os.path.relpath(path, root),
                        hashlib.sha256(fh.read()).hexdigest()))
            except OSError:
                continue
    return hashlib.sha256("\n".join(sorted(entries)).encode("utf-8")).hexdigest()


def seal_status():
    """Кэшируется на процесс: хеш манифеста на каждый effective_level() выбил бы
    бюджет PreToolUse."""
    global _SEAL_CACHE
    if _SEAL_CACHE is None:
        _SEAL_CACHE = _seal_status()
    return _SEAL_CACHE
def _seal_status():
    """'ok' | 'tampered' | 'code_tampered' | 'unsealed'.

    'unsealed' — рабочая копия из git без релизного лока; это не подмена, но и
    не подтверждённая политика. 'code_tampered' — изменён любой файл плагина
    (lib/hooks/rules), а не только policy.json (аудит 03.10.2026, L4).
    """
    expected = expected_code = None
    try:
        with open(lock_path(), "r", encoding="utf-8") as fh:
            locked = json.load(fh)
            expected = locked.get("policy_sha256")
            expected_code = locked.get("code_sha256")
    except Exception:
        expected = None
    if not expected:
        return "unsealed"
    if expected != policy_sha256():
        return "tampered"
    if expected_code and expected_code != code_sha256():
        return "code_tampered"
    return "ok"


def is_tampered():
    return seal_status() in ("tampered", "code_tampered")


# --- Рекомендуемый шаблон настроек -----------------------------------------

def template_path():
    return os.path.join(hookio.plugin_root(), "deploy", "settings.template.json")


def user_settings_path():
    return os.path.expanduser(os.path.join("~", ".claude", "settings.json"))


def settings_template_applied():
    """Применён ли рекомендуемый ~/.claude/settings.json (СЛОЙ 0).

    Проверяется не побайтовое совпадение, а вложенность: сотрудник вправе
    добавить свои правила, но не вправе потерять правила шаблона. Иначе
    флаг в heartbeat становился бы ложно-отрицательным у каждого, кто дописал
    себе одну строку.
    """
    template = _read_json(template_path())
    user = _read_json(user_settings_path())
    if not template or not user:
        return False
    want = set((template.get("permissions") or {}).get("deny") or [])
    have = set((user.get("permissions") or {}).get("deny") or [])
    if not want.issubset(have):
        return False
    return user.get("enableAllProjectMcpServers") is False


def missing_template_rules():
    """Чего именно не хватает в личных настройках — для `secure-dev doctor`."""
    template = _read_json(template_path())
    user = _read_json(user_settings_path())
    if not template:
        return ["шаблон deploy/settings.template.json не найден"]
    if not user:
        return ["~/.claude/settings.json отсутствует"]
    want = (template.get("permissions") or {}).get("deny") or []
    have = set((user.get("permissions") or {}).get("deny") or [])
    missing = [rule for rule in want if rule not in have]
    if user.get("enableAllProjectMcpServers") is not False:
        missing.append("enableAllProjectMcpServers: false")
    return missing


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


# --- Валидация (для `secure-dev doctor`) -----------------------------------

def validate(policy=None):
    """Проверка политики без внешних зависимостей: jsonschema на машинах
    сотрудников нет и не будет (TS.md §1.1). Возвращает список проблем."""
    cfg = policy if policy is not None else _read_policy()
    issues = []
    if cfg.get("schema_version") != 1:
        issues.append("schema_version должен быть 1")
    if cfg.get("level") not in LEVELS:
        issues.append("level должен быть audit|warn|strict")
    for key, value in (cfg.get("rule_levels") or {}).items():
        if value not in LEVELS:
            issues.append("rule_levels.{}: недопустимый уровень {}".format(key, value))
    export = ((cfg.get("audit") or {}).get("export") or {})
    if export.get("type") not in ("none", "file", "http"):
        issues.append("audit.export.type должен быть none|file|http")
    if export.get("type") == "file" and not export.get("path"):
        issues.append("audit.export.type=file требует audit.export.path")
    if export.get("type") == "http" and not export.get("url"):
        issues.append("audit.export.type=http требует audit.export.url")
    if export.get("type") == "http" and export.get("url") \
            and not str(export.get("url")).startswith("https://"):
        issues.append("audit.export.url должен быть https://")
    for item in (cfg.get("exemptions") or []):
        for field in ("rule", "reason", "expires", "approved_by"):
            if not item.get(field):
                issues.append("exemptions[{}]: отсутствует {}".format(
                    item.get("rule", "?"), field))
        try:
            datetime.datetime.strptime(item.get("expires", ""), "%Y-%m-%d")
        except Exception:
            issues.append("exemptions[{}]: expires должен быть YYYY-MM-DD".format(
                item.get("rule", "?")))
    return issues
