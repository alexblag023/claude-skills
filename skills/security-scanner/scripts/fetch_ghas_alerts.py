#!/usr/bin/env python3
"""Выгрузка алертов GitHub code scanning (GHAS/CodeQL) через `gh api` в JSON для ingest_external_report.py.

Использование: python fetch_ghas_alerts.py <owner>/<repo> [--state open|dismissed|fixed] [--out alerts.json]
Требуется `gh` с авторизацией и права security_events/repo. Токен скрипт не читает и не печатает —
авторизацию целиком ведёт `gh`. Только чтение: GET /repos/{owner}/{repo}/code-scanning/alerts (пагинация --paginate).
Код возврата: 0 — выгрузка записана (возможно пустая), 2 — ошибка (нет доступа/анализа/gh).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')


def main(argv: list[str]) -> int:
    if not argv or not REPO_RE.match(argv[0]):
        print(__doc__)
        return 2
    repo = argv[0]
    state = argv[argv.index('--state') + 1] if '--state' in argv else 'open'
    out = argv[argv.index('--out') + 1] if '--out' in argv else 'ghas_alerts.json'
    if state not in {'open', 'dismissed', 'fixed', 'closed'}:
        print('--state: open|dismissed|fixed|closed')
        return 2
    cmd = ['gh', 'api', '--paginate', '--slurp', f'repos/{repo}/code-scanning/alerts?state={state}&per_page=100']
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f'ОШИБКА запуска gh: {e}')
        return 2
    if p.returncode != 0:
        # типичные причины: code scanning не включён/нет анализа (404), нет прав (403), нет авторизации
        print(f'ОШИБКА gh api ({p.returncode}): {(p.stderr or p.stdout).strip()[:300]}')
        return 2
    pages = json.loads(p.stdout or '[]')           # --slurp: список страниц
    alerts = [a for page in pages for a in (page if isinstance(page, list) else [])]
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, ensure_ascii=False)
    print(f'Записано алертов: {len(alerts)} -> {out}')
    return 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main(sys.argv[1:]))
