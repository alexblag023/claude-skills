#!/usr/bin/env python3
"""Проверка скиллов репозитория: формат SKILL.md, отсутствие секретов и запрещённых слов.

Запуск: python scripts/validate_skills.py [каталог-скиллов ...]   (по умолчанию skills/ и templates/)
Код возврата: 0 — чисто, 1 — есть нарушения (гейт CI).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME_RE = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')
MAX_DESCRIPTION = 1024
TEXT_EXTS = {'.md', '.py', '.sh', '.txt', '.yml', '.yaml', '.json', '.toml', '.html', '.ps1', '.cfg', ''}
SKIP_DIRS = {'.git', '__pycache__', 'node_modules'}

# Типовые форматы секретов (узкие шаблоны, чтобы не ловить «ghp_...» в документации)
SECRET_PATTERNS = {
    'GitHub token': re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b'),
    'AWS access key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    'Private key block': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'Slack token': re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    'Anthropic/OpenAI key': re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{32,}\b'),
}


def rel(p: Path) -> Path:
    try:
        return p.relative_to(ROOT)
    except ValueError:  # каталог вне репозитория (локальная проверка чужого пути)
        return p


def load_denylist() -> list[re.Pattern]:
    path = ROOT / 'scripts' / 'denylist.txt'
    words = []
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                words.append(re.compile(re.escape(line), re.I))
    return words


def parse_frontmatter(text: str) -> dict[str, str] | None:
    m = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n', text, re.S)
    if not m:
        return None
    fm: dict[str, str] = {}
    for line in m.group(1).splitlines():
        kv = re.match(r'^([A-Za-z_-]+):\s*(.*)$', line)
        if kv:
            fm[kv.group(1)] = kv.group(2).strip().strip('"\'')
    return fm


def check_skill(skill_dir: Path, errors: list[str]) -> None:
    md = skill_dir / 'SKILL.md'
    if not md.exists():
        errors.append(f'{rel(skill_dir)}: нет SKILL.md')
        return
    fm = parse_frontmatter(md.read_text(encoding='utf-8'))
    where = rel(md)
    if fm is None:
        errors.append(f'{where}: нет frontmatter (--- … ---)')
        return
    name, desc = fm.get('name', ''), fm.get('description', '')
    if not name:
        errors.append(f'{where}: нет поля name')
    elif not NAME_RE.match(name):
        errors.append(f'{where}: name «{name}» не в kebab-case')
    elif skill_dir.parent.name == 'skills' and name != skill_dir.name:
        errors.append(f'{where}: name «{name}» не совпадает с именем каталога «{skill_dir.name}»')
    if not desc:
        errors.append(f'{where}: нет поля description')
    elif len(desc) > MAX_DESCRIPTION:
        errors.append(f'{where}: description длиннее {MAX_DESCRIPTION} символов ({len(desc)})')


def scan_content(base: Path, denylist: list[re.Pattern], errors: list[str]) -> None:
    for p in base.rglob('*'):
        if not p.is_file() or SKIP_DIRS & set(p.parts) or p.suffix.lower() not in TEXT_EXTS:
            continue
        try:
            text = p.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue
        where = rel(p)
        for label, rx in SECRET_PATTERNS.items():
            if rx.search(text):
                errors.append(f'{where}: похоже на секрет ({label})')
        for rx in denylist:
            if rx.search(text):
                errors.append(f'{where}: запрещённое слово из denylist «{rx.pattern}»')


def main() -> int:
    bases = [Path(a).resolve() for a in sys.argv[1:]] or [ROOT / 'skills', ROOT / 'templates']
    errors: list[str] = []
    denylist = load_denylist()
    for base in bases:
        if not base.exists():
            continue
        skill_dirs = [d for d in sorted(base.iterdir()) if d.is_dir()]
        for d in skill_dirs:
            check_skill(d, errors)
        scan_content(base, denylist, errors)
    for e in errors:
        print(e)
    print(f'validate_skills: {len(errors)} нарушений')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')  # Windows-консоль по умолчанию не UTF-8
    sys.exit(main())
