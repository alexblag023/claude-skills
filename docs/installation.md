# Установка и обновление скиллов

Claude Code читает скиллы из двух мест:
- **глобально** — `~/.claude/skills/<имя>/` (Windows: `%USERPROFILE%\.claude\skills\<имя>\`);
- **в проекте** — `<проект>/.claude/skills/<имя>/` (можно коммитить вместе с кодом).

После добавления перезапустите сессию Claude Code.

## Клонировать
```bash
git clone https://github.com/alexblag023/claude-skills.git
```
Репозиторий приватный: нужен доступ коллаборатора и авторизация (`gh auth login` или токен).

## Скопировать скилл
```bash
# Linux / macOS / Git Bash
cp -r claude-skills/skills/security-scanner ~/.claude/skills/
```
```powershell
# Windows PowerShell
Copy-Item -Recurse claude-skills\skills\security-scanner $env:USERPROFILE\.claude\skills\
```

## Обновить
```bash
git -C claude-skills pull
cp -r claude-skills/skills/security-scanner/. ~/.claude/skills/security-scanner/
```

## Симлинк (чтобы обновления подхватывались сразу)
```bash
ln -s "$(pwd)/claude-skills/skills/security-scanner" ~/.claude/skills/security-scanner
```
```powershell
# Windows (нужны права администратора или режим разработчика)
New-Item -ItemType SymbolicLink -Path $env:USERPROFILE\.claude\skills\security-scanner -Target (Resolve-Path claude-skills\skills\security-scanner)
```

## Проверка
В сессии Claude Code скилл виден в списке доступных; скрипты скилла запускаются напрямую, например:
```bash
python ~/.claude/skills/security-scanner/scripts/csrf_template_lint.py <корень-проекта>
```
