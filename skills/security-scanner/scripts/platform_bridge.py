#!/usr/bin/env python3
"""Мост скилла к платформе-сканеру (необязателен: скилл работает и без неё).

Использование:
  python platform_bridge.py scan <путь-как-его-видит-платформа> [--name N] [--engines a,b] [--url URL] [--out report.json]
  python platform_bridge.py findings <scan-id> [--min-severity High] [--url URL]

Токен — ТОЛЬКО из переменной SCANNER_TOKEN или файла (--token-file); в аргументах/выводе/логах не появляется.
Адрес по умолчанию http://127.0.0.1:8000 (платформа слушает только localhost). Только stdlib.
Вывод: компактная сводка в Markdown (критичность, класс, файл:строка, путь устранения). Код возврата:
0 — скан завершён полностью, 1 — partial/failed (результат неполный — «чисто» утверждать нельзя), 2 — ошибка.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SEV = ['Critical', 'High', 'Medium', 'Low', 'Info']


def call(base: str, token: str, method: str, path: str, body: dict | None = None) -> dict | list:
    req = urllib.request.Request(base.rstrip('/') + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f'платформа ответила {e.code}: {e.read().decode(errors="replace")[:300]}')
    except urllib.error.URLError as e:
        raise SystemExit(f'платформа недоступна ({base}): {e.reason}. Запуск: python scripts/up.py в каталоге scanner-platform')


def get_token(a) -> str:
    tok = Path(a.token_file).read_text().strip() if a.token_file else os.environ.get('SCANNER_TOKEN', '')
    if not tok:
        raise SystemExit('нет токена: задайте SCANNER_TOKEN или --token-file (токен — в .env платформы)')
    return tok


def summary(base: str, tok: str, scan: dict, min_sev: str) -> str:
    rows = [f for f in call(base, tok, 'GET', f"/api/scans/{scan['id']}/findings")
            if f['status'] != 'rejected' and SEV.index(f['severity']) <= SEV.index(min_sev)]
    rows.sort(key=lambda f: (SEV.index(f['severity']), f['path'], f['line']))
    out = [f"# Скан №{scan['number']}: {scan['status']}, рейтинг {scan['rating']}, {scan['counts']}", '']
    for f in rows:
        d = call(base, tok, 'GET', f"/api/projects/{scan['project_id']}/findings/{f['fingerprint']}")
        fix = (d.get('remediation') or {}).get('fix') or []
        out.append(f"- **{f['severity']}** {f['class']} `{f['path']}:{f['line']}` ({', '.join(f['tools'])}) — {fix[0] if fix else 'см. карточку'}")
    return '\n'.join(out)


def main(argv=None) -> int:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', default=os.environ.get('SCANNER_URL', 'http://127.0.0.1:8000'))
    ap.add_argument('--token-file')
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('scan')
    s.add_argument('path')
    s.add_argument('--name')
    s.add_argument('--engines')
    s.add_argument('--min-severity', default='Medium', choices=SEV)
    s.add_argument('--out')
    f = sub.add_parser('findings')
    f.add_argument('scan_id')
    f.add_argument('--min-severity', default='Medium', choices=SEV)
    a = ap.parse_args(argv)
    tok = get_token(a)

    if a.cmd == 'findings':
        scan = call(a.url, tok, 'GET', f'/api/scans/{a.scan_id}')
    else:
        proj = call(a.url, tok, 'POST', '/api/projects', {'name': a.name or Path(a.path).name or 'project',
                                                          'source_type': 'local', 'source': a.path})
        body = {'engines': a.engines.split(',')} if a.engines else {}
        scan = call(a.url, tok, 'POST', f"/api/projects/{proj['id']}/scans", body)
        while scan['status'] in ('queued', 'running'):
            time.sleep(5)
            scan = call(a.url, tok, 'GET', f"/api/scans/{scan['id']}")
        if a.out:
            Path(a.out).write_text(json.dumps(call(a.url, tok, 'GET', f"/api/scans/{scan['id']}/findings")), encoding='utf-8')
    print(summary(a.url, tok, scan, a.min_severity))
    return 0 if scan['status'] == 'completed' else 1


if __name__ == '__main__':
    sys.exit(main())
