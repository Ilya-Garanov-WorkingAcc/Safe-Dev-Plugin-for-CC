#!/usr/bin/env bash
# install.sh — установка сопровождающих артефактов secure-dev (PLAN.md 5.4).
#
# Сам плагин ставится через marketplace Claude Code; этот скрипт готовит то,
# что живёт вне плагина: CLI в ~/.local/bin, рекомендуемые настройки (СЛОЙ 0,
# работает даже при отключённом плагине) и pre-flight-обёртку для claude.
#
# Идемпотентен: повторный запуск ничего не ломает. Существующий
# ~/.claude/settings.json не перезаписывается вслепую — создаётся резервная
# копия, а ключи шаблона доливаются к существующим.

set -euo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_DIR="${HOME}/.claude"
BIN_DIR="${HOME}/.local/bin"
SETTINGS="${CLAUDE_DIR}/settings.json"
TEMPLATE="${PLUGIN_ROOT}/deploy/settings.template.json"
SNIPPET="${PLUGIN_ROOT}/deploy/bashrc-snippet.sh"
MARKER="# --- secure-dev: pre-flight перед запуском Claude Code"

say() { printf '  %s\n' "$1"; }

echo "Установка secure-dev из ${PLUGIN_ROOT}"
echo "============================================"

# --- 0. Платформа ----------------------------------------------------------
if ! grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  say "ВНИМАНИЕ: система не определяется как WSL."
  say "Политика отдела требует WSL2/Ubuntu (ADR-007). Установка продолжится,"
  say "но часть контролей на этой платформе не гарантирована."
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 не найден в PATH — плагин работать не будет." >&2
  exit 2
fi

# --- 1. CLI ----------------------------------------------------------------
mkdir -p "${BIN_DIR}"
chmod +x "${PLUGIN_ROOT}/bin/secure-dev"
ln -sf "${PLUGIN_ROOT}/bin/secure-dev" "${BIN_DIR}/secure-dev"
say "CLI: ${BIN_DIR}/secure-dev → ${PLUGIN_ROOT}/bin/secure-dev"

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) say "ДОБАВЬТЕ В PATH: export PATH=\"\${HOME}/.local/bin:\${PATH}\"" ;;
esac

# --- 2. Рекомендуемые настройки -------------------------------------------
mkdir -p "${CLAUDE_DIR}"
if [ -f "${SETTINGS}" ]; then
  BACKUP="${SETTINGS}.bak-$(date +%Y%m%d-%H%M%S)"
  cp "${SETTINGS}" "${BACKUP}"
  say "Резервная копия настроек: ${BACKUP}"
  python3 - "${SETTINGS}" "${TEMPLATE}" <<'PY'
import json, sys

settings_path, template_path = sys.argv[1], sys.argv[2]
with open(settings_path, encoding="utf-8") as fh:
    try:
        settings = json.load(fh)
    except ValueError:
        print("  Существующий settings.json нечитаем — оставлен как есть.")
        raise SystemExit(1)
with open(template_path, encoding="utf-8") as fh:
    template = json.load(fh)

# Правила ДОЛИВАЮТСЯ: у сотрудника могут быть свои запреты, и терять их нельзя.
permissions = settings.setdefault("permissions", {})
for section in ("deny", "ask"):
    have = permissions.setdefault(section, [])
    for rule in template.get("permissions", {}).get(section, []):
        if rule not in have:
            have.append(rule)

settings["enableAllProjectMcpServers"] = False
env = settings.setdefault("env", {})
for key, value in template.get("env", {}).items():
    env.setdefault(key, value)

with open(settings_path, "w", encoding="utf-8") as fh:
    json.dump(settings, fh, ensure_ascii=False, indent=2)
    fh.write("\n")
print("  Настройки обновлены: правила шаблона добавлены к существующим.")
PY
else
  cp "${TEMPLATE}" "${SETTINGS}"
  say "Настройки установлены: ${SETTINGS}"
fi

# --- 3. Pre-flight-обёртка -------------------------------------------------
if grep -qF "${MARKER}" "${HOME}/.bashrc" 2>/dev/null; then
  say "Обёртка claude уже добавлена в ~/.bashrc"
else
  printf '\n' >> "${HOME}/.bashrc"
  cat "${SNIPPET}" >> "${HOME}/.bashrc"
  say "Обёртка claude добавлена в ~/.bashrc (примените: source ~/.bashrc)"
fi

# --- 4. Что дальше ---------------------------------------------------------
cat <<EOF

Осталось установить сам плагин в Claude Code:

  /plugin marketplace add ${PLUGIN_ROOT}
  /plugin install secure-dev@secure-dev-marketplace

Проверка после установки:

  secure-dev doctor
  secure-dev scan .

Ожидаемо на первой же сессии: сама установка дописывает enabledPlugins
в .claude/settings.json проекта, а это горячий ключ (TS.md §10.2) —
config_trust корректно пометит его как неподтверждённый (уровень warn,
не блокирует). Это не ошибка и не повод для тревоги: подтвердите
осознанно командой /secure-dev:trust.

Что делает плагин и что попадает в журнал — docs/ROLLOUT.md.
EOF
