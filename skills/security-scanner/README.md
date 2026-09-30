# security-scanner

Скилл для Claude Code: аудит безопасности кода и решений перед сдачей/деплоем. Два слоя независимых экспертов (SAST/SCA/DAST-анализаторы и 6 зон требований), пруфы из реальных сканеров (Semgrep, Trivy, gitleaks, ZAP…), результат — план устранения `SECURITY_FIX_PLAN.md`, а не статистика.

- `SKILL.md` — протокол и формат отчёта.
- `references/default_checklist.md` — базовый чек-лист (по открытым источникам). Свои требования подключаются по `references/requirements_guide.md`.
- `scripts/csrf_template_lint.py` — линтер CSRF по HTML/Jinja/htmx-шаблонам (`python scripts/csrf_template_lint.py <корень>`; код 1 при находках).

Установка: скопировать каталог в `~/.claude/skills/security-scanner/`.

## Сторонние материалы
Все сторонние части — MIT, см. `THIRD_PARTY.md`. Лицензия проекта — MIT, см. `LICENSE`.
