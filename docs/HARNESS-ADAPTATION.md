# Адаптация secure-dev под Codex, pi и omp: анализ (26.10.2026)

Объект: secure-dev 3.0.1, коммит 7776fb4. Это анализ кода и документации харнесов. Ничего не проверялось запуском харнесов.

Исходники, использованные при исследовании, лежат в scratchpad сессии:

- `codexsrc/codex` — openai/codex@b881730;
- `pkg/package` — npm-тарбол pi 1.4.0.

## Итог

- **Codex 0.164.0** перенял формат хуков Claude Code: те же поля, `Bash`, `mcp__*`, `CLAUDE_PLUGIN_ROOT`, фолбэк на `.claude-plugin/plugin.json`. Поэтому нынешний плагин, скорее всего, установится в Codex без изменений. Но работать будет опасно:
  - `ask` из PreToolUse Codex считает ошибкой хука и пропускает вызов;
  - таймаут или падение хука тоже ведут к пропуску;
  - замены вывода нет;
  - ConfigChange и PostToolUseFailure нет.
  
  До выхода адаптера ставить плагин в Codex нельзя: он даст ложное чувство защиты.
- **pi 1.4.0** (`@earendil-works/pi-coding-agent`, репозиторий earendil-works/pi). Расширения на TS:
  - `tool_call` → `{block}`, ошибка обработчика блокирует вызов;
  - `tool_result` меняет `content`;
  - `ctx.ui.confirm` даёт ask;
  - событие `project_trust` срабатывает до загрузки проектных расширений;
  - MCP встроен.
  
  Песочницы нет, плагин — единственный барьер.
- **omp** — oh-my-pi 18.13.0 (can1357/oh-my-pi), расходящийся форк pi на Bun.
  - Есть `additionalContext`; ошибка или таймаут обработчика (30 с) блокирует вызов.
  - `.omp/extensions` и `.omp/hooks` грузятся **без trust**, то есть возможен запуск кода из клонированного репозитория.
  - Инструмент `eval` (Python/Bun) идёт мимо bash-парсера.
  - То, что omp — это oh-my-pi, нужно подтвердить.

## 1. Зависимости от Claude Code в коде

### Транспорт

- `hooks/hooks.json` — exec-форма `command` + `args`, `${CLAUDE_PLUGIN_ROOT}`, `timeout`, `statusMessage`, `async`.
- События: SessionStart, ConfigChange, PreToolUse, PostToolUse, PostToolUseFailure, SubagentStart, SessionEnd.
- Какой хук на каком инструменте срабатывает, решает Claude Code по матчерам; код этого не знает.
- Сторож `lib/hookio.py:300-432` (бюджеты в `:48-49`) построен на факте Claude Code: хук, убитый по таймауту, действие не блокирует.
- Хуки одного события работают параллельно. secret_redactor и injection_scanner координируются через состояние `secrets:<tool_use_id>` (`secret_redactor.py:150-157`, `injection_scanner.py:116-126`).

### Входное событие

`lib/hookio.py:175-214`, `lib/audit.py:198-232`.

| Поле | Где используется |
|---|---|
| `hook_event_name`, `tool_name`, `tool_input`, `tool_response` | все хуки |
| `error` / `tool_error` / `stderr` | `injection_scanner.py:71` |
| `tool_use_id` | координация хуков |
| `session_id`, `agent_id` | память сессии и taint (`policy.py:51-161`, `command_guard.py:396`) |
| `cwd` | весь контроль «вне cwd» |
| `source` | `config_trust.py:155`, `session_guard.py:42` |
| `claude_code_version` | аудит |

### Ответ

`lib/hookio.py:219-285`.

- `deny` / `ask` → `hookSpecificOutput.permissionDecision`.
- `warn` → `systemMessage`.
- `context` → `additionalContext`.
- `updated_output` → `updatedToolOutput`.
- `block_config` → `decision:"block"`.
- **На `ask` держится fail-closed** (`_fail`, `hookio.py:344-350`): сбой или таймаут превращаются в вопрос человеку.

### Инструменты

| Инструмент | Поля |
|---|---|
| Bash | `command` |
| Read / NotebookRead | `file_path` |
| Glob / Grep | `pattern` / `glob` / `path` |
| Write / Edit / MultiEdit | `file_path`, `content`, `new_string`, `edits` |
| NotebookEdit | `notebook_path` |
| WebFetch / WebSearch | `url`, `query` |
| `mcp__*` | эвристика по полям и имени (`path_guard.py:36,60-79`) |

Имена инструментов зашиты:

- в матчерах `hooks.json`;
- в таблицах хуков (`path_guard.py:29-79`, `secret_redactor.py:34-42`);
- в полях `tools` / `write_tools` всех 9 правил `rules/paths.json` (сравнение в `lib/ruleset.py:327-349`).

### Окружение и пути

- `CLAUDE_PLUGIN_DATA` (`hookio.py:70-110`), фолбэк `~/.claude/secure-dev/`.
- `~/.claude/secure-dev.local.json` (`config.py:32`).
- Проверка Слоя 0 в `~/.claude/settings.json` (`config.py:471-512`).
- `CLAUDECODE` (`bin/secure-dev:68`).
- Версия плагина из `.claude-plugin/plugin.json` (`audit.py:69`).
- Slash-команды `commands/*.md`, skills, обёртка `claude()` в `deploy/bashrc-snippet.sh`.

### Данные, специфичные для Claude Code

- `lib/trust.py:26-49,228-257` — артефакты `.claude/*`, `.mcp.json`, `CLAUDE*.md`; разбирается только JSON.
- `rules/config.json` `hot_keys` — ключи settings.json Claude Code.
- `rules/paths.json`: `path-self-protection` и `path-claude-credentials`.
- `rules/commands.json`: `command-plugin-disable`, `command-claude-bypass`.
- `rules/injection.json`: упоминания `claude` и `.claude/.credentials`.

### Возможности, без которых логика деградирует

| Возможность | Что теряется без неё |
|---|---|
| PreToolUse deny | основная защита |
| PreToolUse ask | fail-closed вырождается в выбор между allow и deny |
| updatedToolOutput | модель видит секреты |
| additionalContext (Post и PostFailure) | модель не получает предупреждения |
| SessionStart (контекст, баннер) | нет видимости, heartbeat и отчёта trust |
| ConfigChange block | нет блокировки горячей правки конфигурации |
| SubagentStart / `agent_id` | агенты не различаются в аудите |
| matcher `mcp__.*` | MCP идёт мимо контроля |
| `permissions.deny` (Слой 0) | нет декларативного запрета чтения секретов |

## 2. Ядро и адаптер

**Переносятся как есть:**

- `lib/cmdparse.py`, `redact.py`, `injection.py`, `export.py`;
- `ruleset.py` — кроме имён инструментов в данных;
- `policy.py` — ключ памяти нужно абстрагировать в «контекст вызова».

**Смешаны:**

- `lib/hookio.py` (сильнее всего):
  - ядро: `atomic_write`, `append_line`, `ensure_dir`, `_run_with_deadline`;
  - адаптер Claude Code: `read`, ответы, `_fail`, `BUDGETS`, `data_dir`.
- `lib/config.py:32,471-512`.
- `lib/trust.py`: списки артефактов и парсинг конфигов.
- `lib/audit.py:63-109,198-232`.
- Каждый `main()` в `hooks/*.py` смешивает три шага: разбор события, логику и ответ. Логику нужно вынести в общий движок:
  - `command_guard.py:442-541`;
  - `path_guard.py:146-200` (`_candidate_paths` и `_tool_class` — это маппинг Claude Code);
  - `secret_redactor.py:81-231`;
  - `injection_scanner.py:58-135`.

## 3. Харнесы

### Codex 0.164.0 (23.10.2026)

Источники:

- документация: learn.chatgpt.com/docs/hooks, /docs/sandboxing, /docs/agent-configuration/rules;
- исходники github.com/openai/codex: `codex-rs/hooks/src/engine/*`, `hooks/src/events/pre_tool_use.rs`, `hooks/schema/generated/*`, `core/src/tools/registry.rs`.

**Хуки.**

- Статус stable с 0.124, хуки в плагинах — с 0.128, доверие к хукам по хешу — с 0.129, хуки для всех инструментов — с 0.135.
- Где лежат: `~/.codex/hooks.json` или `[hooks]` в `config.toml`; проектные — только в доверенном проекте; managed — `/etc/codex/requirements.toml`; в плагине — `hooks/hooks.json`. Слои суммируются.
- Команда запускается через `$SHELL -lc`. Поддерживается ли exec-форма `args`, не подтверждено.
- Переменные окружения: `PLUGIN_ROOT`, `CLAUDE_PLUGIN_ROOT`, `PLUGIN_DATA`, `CLAUDE_PLUGIN_DATA`.
- События: PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, UserPromptSubmit, SubagentStart/Stop, Stop, Interrupt, SessionStart, SessionEnd. **ConfigChange, PostToolUseFailure, FileChanged и CwdChanged нет.**
- Вход: те же поля, что у Claude Code, плюс `turn_id` и `model`.

**Выход.**

- PreToolUse: `deny`, `allow` + `updatedInput`, `additionalContext`, `systemMessage`.
- **`ask` — ошибка хука, вызов проходит** (`pre_tool_use.rs:577` `unsupported_permission_decision_fails_open`).
- **Таймаут, падение или кривой JSON — тоже проход.**
- PostToolUse: `decision:block` + `reason` (модель видит только `reason`), `additionalContext`. `updatedToolOutput` нет.
- Ограничения PostToolUse:
  - не вызывается на неуспешных вызовах;
  - не вызывается на промежуточных порциях `exec_command`/`write_stdin`;
  - в UI и логах остаётся исходный вывод.
- Таймаут по умолчанию 600 с; у SessionEnd — не больше 3 с.

**Доверие к хукам.** Неуправляемый хук не запустится, пока его не одобрят через `/hooks`. Хеш считается от объявления хука, а не от скрипта; для плагинов — от всего бандла.

**Инструменты.**

- `exec_command` приходит как `Bash` с `command`-строкой; `cwd` — уже разрешённый каталог команды.
- `apply_patch` приходит как `{"command": "<патч>"}`, его ловят матчеры Edit/Write. Маркеры: `*** Add/Update/Delete File:`, `*** Move to:`.
- MCP — `mcp__<server>__<tool>`; есть `spawn_agent` (алиас Agent).
- Отдельного read-инструмента нет.
- Не покрыты хуками: хостовый `web_search` и `write_stdin`.

**Безопасность.**

- `sandbox_mode` = read-only | workspace-write | danger-full-access (на Linux — bubblewrap + seccomp). В workspace-write каталоги `.git`, `.agents`, `.codex` только на чтение.
- `approval_policy`: on-request, never, granular.
- execpolicy — `~/.codex/rules/*.rules` (Starlark, `prefix_rule(..., decision=allow|prompt|forbidden)`).
- `shell_environment_policy` по умолчанию пропускает переменные с KEY/SECRET/TOKEN в окружение shell.
- Проектный `.codex/*` грузится только при `trust_level="trusted"`. Доверенный репозиторий при этом может ослабить песочницу.

### pi 1.4.0 (21.10.2026)

Источник: npm `@earendil-works/pi-coding-agent` — `docs/extensions.md`, `security.md`, `mcp.md`, `dist/core/extensions/types.d.ts`.

**Расширения** — TS-модули из `~/.pi/agent/extensions/`, `.pi/extensions/` (после project trust), из settings, `pi -e` и `pi install`.

- **`tool_call`** `{toolCallId, toolName, input}` → `{block, reason}`. Ошибка обработчика блокирует вызов. Встроенного таймаута нет.
- **`tool_result`** → `{content, details, structuredContent, isError}`. Работает и на ошибках. При правке `content` нужно заменить и `structuredContent`.
- **ask:** `ctx.ui.confirm`. В режимах print/json возвращает false, значит block.
- Другие события: `project_trust`, `session_start`, `session_shutdown`, `before_agent_start`, `context`.

**Инструменты.**

- По умолчанию включены `bash {command}`, `read {path}`, `edit {path, edits}`, `write {path, content}`. Есть также `grep`, `find`, `ls`, `powershell`.
- MCP встроен с 0.99, имена `mcp__*`.
- В `codemode` вложенные вызовы проходят хуки (с `parentToolCallId`).

**Безопасность.**

- Песочницы и подтверждений нет.
- Project trust срабатывает, если в проекте есть `.pi/*` или `.agents/skills`. **`AGENTS.md` и `CLAUDE.md` грузятся вне trust.**
- Настройки — `~/.pi/agent/{settings.json, auth.json, mcp.json, trust.json, extensions/}`.

### omp (oh-my-pi) 18.13.0 (26.10.2026)

Источник: github.com/can1357/oh-my-pi, `docs/*`.

- Форк pi, последняя синхронизация — 22.03.2026. Рантайм Bun. Расширения pi работают через шим, полной совместимости документация не обещает.
- `tool_call` → `{block, reason, input, additionalContext}`; ошибка или таймаут (30 с) = block.
- `tool_result` → `{content, details, isError, additionalContext}`.
- Есть `ctx.ui.confirm`, события `before_subagent_spawn` и `tool_approval_*`. **События `project_trust` нет.**
- **`.omp/extensions` грузятся автоматически, без trust.** Ограничения — `--no-extensions` и `--trusted-extension`.
- omp читает правила, skills и MCP из `.claude`, `.cursor`, `.codex`.
- Около 31 инструмента: `task`, `eval` (Python/Bun), `ast_edit`, `browser` и др. Схемы аргументов не сверены.
- Встроено: approval mode (по умолчанию `yolo`), `tools.restrictedFolders`, `bash.patterns`, обфускация секретов (по умолчанию выключена).

## 4. Соответствие функций

Обозначения: Н — нативно, А — через адаптер, Ч — частично или с деградацией, ✗ — невозможно.

| Функция | Codex | pi | omp |
|---|---|---|---|
| deny опасных shell-команд | Н | А | А |
| ask | ✗/Ч (fail-open) | Н/А (`confirm`, без UI → block) | Н/А |
| fail-closed при сбое | Ч (сторож должен успеть) | Н/А | Н |
| path_guard на чтение | Н (через Bash) | А | А |
| path_guard на запись | А (разбор `apply_patch`) | А | А |
| секреты в исходящих вызовах | Ч | А | А |
| редакция вывода | Ч (`block` + `reason`, дыры) | Н | Н |
| предупреждения об инъекциях в контекст | Н | А | Н |
| инъекции в ошибках | ✗ | Н | Н |
| trust репозитория на старте | Ч/Н | Н (`project_trust`) | ✗/Ч (только обёртка `omp()`) |
| блок изменения конфига в сессии | ✗ (path_guard + read-only `.codex`) | Ч | Ч |
| баннер и heartbeat | Н | А | А |
| субагенты | Н | Ч | А |
| MCP | Н | Н | Н |
| защита от отключения (managed) | Н (`requirements.toml`) | ✗ | ✗ |
| новый канал исполнения кода | — | codemode (виден) | `eval` (мимо парсера) |

## 5. Предлагаемая архитектура

```
secure_dev/                 бывший lib/, только stdlib
  cmdparse, redact, injection, ruleset, policy, audit, export, config, trust
  patchparse.py             НОВОЕ: разбор Codex apply_patch → [(op, path, text)]
  model.py                  НОВОЕ: ToolCall, Verdict(allow|warn|ask|deny), OutputVerdict
  engine.py                 НОВОЕ: check_shell / check_paths / check_egress / scan_output / session_start
  deadline.py               сторож без знания событий
  profiles/{claude,codex,pi,omp}.json
                            имена инструментов → kind, артефакты trust, hot_keys,
                            глобы самозащиты, путь данных, деградация ask
adapters/
  claude/                   hooks.json + тонкие обёртки, поведение 3.0.1 без изменений
  codex/                    .codex-plugin/plugin.json + hooks.json, entrypoint --harness codex
  pi/                       secure-dev.ts: tool_call/tool_result/project_trust → Python
  omp/                      порт pi-шима под Bun
```

**Транспорт для pi и omp.** Начать с процесса на вызов: TS-шим запускает `python3 -m secure_dev.cli hook --harness pi` и передаёт JSON в stdin. Это добавляет 60–80 мс. Демон — позже, если понадобится. Портировать ядро на TS не стоит: это двойное сопровождение парсера (1751 строка) и 17 батарей.

**Словарь инструментов.** Дешевле всего оставить имена Claude Code (`Bash`/`Read`/`Write`/`Edit`) каноническими: Codex сам отдаёт shell как `Bash`. Адаптеры маппят свои имена:

- pi: `read`/`grep`/`find`/`ls` → Read; `write`/`edit` → Write/Edit;
- Codex: `apply_patch` → Write или Edit по каждому файлу патча.

**Деградация решений.**

| Verdict | Claude Code | Codex | pi / omp |
|---|---|---|---|
| deny | `permissionDecision: deny` | `permissionDecision: deny` | `{block, reason}` |
| ask | `ask` | настраиваемо: deny с инструкцией; для статических префиксов — `.rules prompt` | `ctx.ui.confirm`, без UI → block |
| warn | `systemMessage` | `systemMessage` | `ui.notify` |
| context | `additionalContext` | `additionalContext` | pi: текст в `content`; omp: `additionalContext` |
| redact | `updatedToolOutput` | `decision: block` + вычищенный `reason` | `content` + `structuredContent` + `details` |
| сбой | ask | **deny** | block |

**Изменения по файлам** (кратко):

- `lib/hookio.py` разделить на fsutil, deadline и адаптер Claude Code; `data_dir` брать из профиля.
- Логику `hooks/*.py` вынести в `engine.py`.
- `cmdparse.py`: `apply_patch` с heredoc — писатель; `codex`, `pi`, `omp` — argv0 для правил обхода.
- `ruleset.py:327-349`: сопоставлять по kind, а не по имени инструмента.
- `trust.py`: артефакты из профиля:
  - Codex: `.codex/{config.toml,hooks.json,rules/}`, `.agents/skills/`, `.codex-plugin/`;
  - pi: `.pi/*`;
  - omp: `.omp/**`.

  Плюс разбор TOML (`tomllib`, Python ≥ 3.11) и простой разбор YAML.
- `rules/config.json`: `hot_keys` по харнесам.
- `rules/paths.json`: самозащита и учётные данные для `~/.codex`, `~/.pi/agent`, `~/.omp/agent`, включая журналы сессий.
- `rules/commands.json`: аналоги `claude-bypass` и `plugin-disable` для каждого харнеса (флаги сверить).
- `rules/injection.json`: обобщить на все харнесы.
- `audit.py`: поля `harness` и `harness_version`; нейтральный файл `VERSION`.
- `config.py`: `LOCAL_PATH` и проверка Слоя 0 по профилю; адаптеры включить в печать `code_sha256`.
- `bin/secure-dev:68`: признак «запущено агентом» не только по `CLAUDECODE` — отсутствие TTY плюс цепочка родителей в `/proc`.
- `deploy/`: обёртки `codex()`, `pi()`, `omp()` с предварительным `secure-dev scan`; установщики для каждого харнеса.
- `tests/`: трансляторы фикстур для каждого харнеса, контрактные тесты формата, `bypass_corpus` через все адаптеры.

## 6. Риски

1. Codex с нынешним плагином «как есть» молча пропускает все ask.
2. Codex fail-open: падение Python до сторожа — пропуск. Основным барьером сделать песочницу `workspace-write` через `requirements.toml`, CRITICAL-префиксы продублировать в `.rules forbidden`.
3. Редакция в Codex дырявая: промежуточные порции, неуспешные вызовы, UI, логи, `~/.codex/sessions`.
4. omp: код из `.omp/extensions` исполняется без trust; `eval` идёт мимо парсера.
5. В pi и omp нет песочницы и managed-слоя: самозащита критична.
6. Дрейф форматов: нужны минимальные версии и контрактные тесты.
7. Python ≥ 3.11 для `tomllib`: на Ubuntu 22.04 стоит 3.10.
8. Ложные срабатывания injection_scanner на чужой документации — а именно с ней работают при портировании (см. `docs/TEST-2026-10-26.md`, FP-6).

## 7. Открытые вопросы

1. Приоритет харнесов.
2. Чем заменять ask в Codex: deny с инструкцией, allow с предупреждением или `.rules prompt`?
3. Один каталог данных, trust и журнал на все харнесы (с полем `harness`) или раздельные?
4. Остаётся ли ограничение «только WSL2/Ubuntu»?
5. Возможна ли managed-установка Codex (`/etc/codex/requirements.toml`)?
6. omp — точно oh-my-pi? Допустимо ли требовать обёртку `omp()` и `--no-extensions`?
7. Словарь инструментов: имена Claude Code или нейтральные ops?
8. Python ≥ 3.11 на целевых машинах или свой мини-парсер TOML?
9. Правило «только stdlib» — для TS-шима тоже? Как распространять шим?
10. Политика для `eval` (omp) и codemode (pi): ask, deny или статический скан?
