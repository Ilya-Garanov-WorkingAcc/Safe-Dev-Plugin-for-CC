# --- secure-dev: pre-flight перед запуском Claude Code ---------------------
# Добавляется в ~/.bashrc установщиком deploy/install.sh.
#
# Единственный контроль, работающий ДО первого хука репозитория: хуки из
# .claude/settings.json клонированного репозитория стартуют параллельно с
# хуками плагина, а не после них (ARCHITECTURE.md §4.3).
#
# Обходится вызовом `command claude` напрямую — это принято. Функция закрывает
# неумышленный сценарий, который и является основным.

claude() {
  if [ -d .claude ] || [ -f .mcp.json ]; then
    if command -v secure-dev >/dev/null 2>&1; then
      command secure-dev scan . || {
        printf 'secure-dev: обнаружена непроверенная конфигурация репозитория. '
        printf 'Продолжить? [y/N] '
        read -r answer
        case "$answer" in
          y|Y|д|Д) ;;
          *) return 1 ;;
        esac
      }
    fi
  fi
  command claude "$@"
}
# --- конец secure-dev ------------------------------------------------------
