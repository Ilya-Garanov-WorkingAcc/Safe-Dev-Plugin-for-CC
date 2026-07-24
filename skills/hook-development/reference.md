# Справочник: события, ввод/вывод и матчеры хуков Claude Code

Официальные источники:
- https://code.claude.com/docs/en/hooks.md (полная спецификация)
- https://code.claude.com/docs/en/hooks-guide.md (гайд и примеры)

## События (когда срабатывают)

**Per-tool:** `PreToolUse` (до инструмента, может блокировать), `PostToolUse`
(после успеха), `PostToolUseFailure` (после ошибки инструмента),
`PermissionRequest`, `PermissionDenied`, `PostToolBatch` (после батча
параллельных вызовов).

**Per-turn:** `UserPromptSubmit` (до обработки промпта, может блокировать),
`UserPromptExpansion`, `Stop` (Claude закончил ответ), `StopFailure`.

**Per-session:** `SessionStart` (матчер: `startup|resume|clear|compact|fork`),
`SessionEnd`, `Setup`.

**Файлы/конфиг:** `FileChanged` (матчер — литеральные имена файлов, не regex),
`ConfigChange` (`user_settings|project_settings|local_settings|policy_settings|skills`),
`CwdChanged`.

**Асинхронные/фоновые:** `Notification` (`permission_prompt|idle_prompt|auth_success|
elicitation_*|agent_needs_input|agent_completed`), `PreCompact`/`PostCompact`
(`manual|auto`), `MessageDisplay`.

**Subagent/task/worktree:** `SubagentStart`, `SubagentStop`, `TaskCreated`,
`TaskCompleted`, `WorktreeCreate`, `WorktreeRemove`.

**Контекст:** `InstructionsLoaded`, `Elicitation`, `ElicitationResult`,
`TeammateIdle`.

## Вход (stdin, JSON)

Общие поля: `session_id`, `cwd`, `hook_event_name`, `permission_mode`,
`transcript_path`, `prompt_id`.

Событийные (примеры):
- `PreToolUse`/`PostToolUse`: `tool_name`, `tool_input` (аргументы инструмента),
  `tool_response` (только Post*).
- `UserPromptSubmit`: `prompt`.
- `SessionStart`: `source`.
- `FileChanged`/`ConfigChange`: `file_path`.
- `Stop`: `stop_hook_active` (флаг защиты от циклов).

Читай защитно: `data.get(...)`, проверяй типы.

## Выход

### Код выхода
| Код | Смысл |
|-----|-------|
| 0 | Успех. stdout-JSON применяется. Для `UserPromptSubmit`/`SessionStart` голый stdout инжектится в контекст. |
| 2 | Блокирующая ошибка. stderr → модели как фидбэк. Блокирует: PreToolUse, PostToolUse, PostToolUseFailure, UserPromptSubmit, UserPromptExpansion, Stop, PostToolBatch. Для остальных — просто показывает stderr и продолжает. |
| прочее | Неблокирующая ошибка. Первая строка stderr → пользователю как `<hook> hook error`. |

### stdout-JSON (общие поля)
- `continue` (bool) — продолжать ли выполнение.
- `suppressOutput` (bool) — не показывать вывод в транскрипте.
- `systemMessage` (str) — сообщение в контекст.
- `hookSpecificOutput` (obj) — событийные поля (ниже).

### hookSpecificOutput по событиям
- **PreToolUse:** `permissionDecision` ∈ `allow|deny|ask` (+ `defer` только в
  неинтерактивном режиме), `permissionDecisionReason` (str), `updatedInput`
  (модифицированные аргументы инструмента). Пропуск поля/JSON → обычный поток
  разрешений.
  - `allow` — пропустить интерактивный запрос (deny-правила всё равно действуют).
  - `deny` — заблокировать, причина уходит модели.
  - `ask` — показать обычный диалог разрешения.
- **PostToolUse:** `updatedToolOutput` (объект ИЛИ строка — отдавай тем же типом,
  что пришёл), `additionalContext` (str), `decision:"block"` + `reason`.
- **UserPromptSubmit:** `additionalContext`, `blockUserPrompt` (bool),
  `sessionTitle`.
- **PermissionRequest:** `decision:{behavior:"allow|ask|deny", updatedPermissions:[...]}`.
- **prompt/agent-хуки:** `{ "ok": true|false, "reason": "..." }`.

## Матчеры (settings.json)

Набор из букв, цифр, `_ - , | ` и пробелов трактуется как точный список; прочие
символы → JS-regex.
- `"Bash"` — только Bash. `"Edit|Write"` / `"Edit, Write"` — несколько.
- `"^Notebook"` — по префиксу (regex). `"mcp__.*"` — любые MCP-инструменты.
- `""` — все.
- Для не-tool событий матчер фильтрует событийное поле (источник сессии, имя
  файла, тип нотификации) — см. список событий выше.

## Типы обработчиков (поле `type`)
- `command` — внешняя программа (shell-форма или exec-форма с `args`). Таймаут
  10 мин (30с для UserPromptSubmit).
- `http` — POST на URL тем же JSON; ответ тем же форматом.
- `mcp_tool` — вызов инструмента MCP-сервера.
- `prompt` — одноходовый LLM-вызов, вывод `{ok, reason}` (по умолчанию Haiku).
- `agent` — многоходовый субагент (экспериментально), вывод `{ok, reason}`.

Опции: `timeout` (сек), `if` (фильтр по правилу разрешений, `"Bash(git *)"`),
`statusMessage`, `once`.

## Отладка
- `claude --debug` / `claude --debug-file /tmp/claude.log` — полная трассировка:
  какие хуки сматчились, коды выхода, stdout/stderr, порядок параллельного
  выполнения.
- `/debug` в сессии.

## Кодировка консоли (не-UTF8 Windows)

Python выбирает кодировку `sys.stdin`/`stdout`/`stderr` по локали процесса —
даже когда поток на самом деле pipe в Claude Code, а не видимый терминал. На
Windows-консолях с cp1251/cp1252/cp437 (кириллица, Западная Европа, DOS —
типичные некириллические кодировки) это не UTF-8.

Асимметрия по потокам (проверено эмпирически): `sys.stdout` по умолчанию
кодирует с `errors="strict"` — первый непредставимый символ (эмодзи, ─, ❌ и
т.п.) кидает `UnicodeEncodeError`. `sys.stderr`, напротив, в CPython всегда
использует `errors="backslashreplace"` — не падает, но текст превращается в
нечитаемое `\uXXXX`-экранирование вместо символа. Кириллица сама по себе не
проблема в cp1251 (это кириллическая кодировка), проблема — именно эмодзи и
спецсимволы, которых нет ни в одной однобайтовой Windows-кодировке.

Хуки в этом плагине отдают JSON-решение через `stdout` — именно тот канал,
который падает молча (fail-open проглатывает исключение), а не деградирует
до нечитаемого текста. Итог: на затронутых машинах хук просто перестаёт
отвечать, и для `secret_redactor` в PostToolUse это значит, что
`updatedToolOutput` с уже замаскированным секретом не долетает — модель
видит исходный, немаскированный секрет.

**Как воспроизвести на Linux/macOS без реальной Windows-машины:**
```bash
PYTHONIOENCODING=cp1251 python3 hooks/secret_redactor.py < payload.json
```
`PYTHONIOENCODING` переключает кодировку всех трёх потоков (включая `stdin` —
входящий JSON от Claude Code тоже рискует быть неверно декодирован, если
содержит не-ASCII, например кириллические пути).

**Фикс** (см. чек-лист, п.7): `reconfigure(encoding="utf-8", errors="replace")`
на всех трёх потоках до первой операции — устраняет проблему в источнике.
`json.dumps(obj, ensure_ascii=True)` — независимая вторая линия защиты: даже
если `reconfigure` почему-то не сработал, сам JSON-текст состоит только из
ASCII (`\uXXXX`-escape), кодируется в любой кодировке, и Claude Code корректно
разэкранирует его при разборе. Если хук порождает дочерний процесс (например,
`hook_test_runner.py` запускает батарею через `subprocess.run`) — передавай
`encoding="utf-8", errors="replace"` явно, а не `text=True`: иначе вывод
дочернего процесса декодируется по локали ОС и может упасть тем же образом.
