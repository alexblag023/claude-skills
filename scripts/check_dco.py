#!/usr/bin/env python3
"""Проверка подписи DCO (Signed-off-by) у коммитов pull request.

Использование: python scripts/check_dco.py <base-sha> <head-sha>
Проверяются коммиты диапазона base..head (без merge-коммитов). Условие: в сообщении есть строка
`Signed-off-by: Имя <email>`, где email совпадает с email автора коммита (регистр не важен).
Коммиты ботов (автор с суффиксом [bot]) не проверяются.
Код возврата: 0 — все подписаны, 1 — есть неподписанные.
"""
from __future__ import annotations

import re
import subprocess
import sys

SIGNOFF_RE = re.compile(r'^Signed-off-by:\s+(.+?)\s+<([^<>\s]+)>\s*$', re.M)
SEP_REC, SEP_FLD = '\x1e', '\x1f'


def commits(base: str, head: str) -> list[dict]:
    fmt = SEP_FLD.join(['%H', '%an', '%ae', '%B']) + SEP_REC
    out = subprocess.run(
        ['git', 'log', '--no-merges', f'--format={fmt}', f'{base}..{head}'],
        check=True, capture_output=True, text=True, encoding='utf-8').stdout
    res = []
    for rec in filter(None, (r.strip('\n') for r in out.split(SEP_REC))):
        sha, name, email, body = rec.split(SEP_FLD, 3)
        res.append({'sha': sha, 'name': name, 'email': email, 'body': body})
    return res


def problem(c: dict) -> str | None:
    if c['name'].endswith('[bot]'):
        return None
    signoffs = SIGNOFF_RE.findall(c['body'])
    if not signoffs:
        return 'нет строки Signed-off-by (подпишите: git commit -s)'
    if c['email'].lower() not in {e.lower() for _, e in signoffs}:
        return f'Signed-off-by не совпадает с email автора <{c["email"]}>'
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    bad = []
    items = commits(sys.argv[1], sys.argv[2])
    for c in items:
        p = problem(c)
        if p:
            bad.append(f'{c["sha"][:7]} ({c["name"]}): {p}')
    for b in bad:
        print(b)
    print(f'check_dco: проверено {len(items)} коммитов, нарушений {len(bad)}')
    if bad:
        print('\nИсправление: git rebase --signoff <base> && git push --force-with-lease')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main())
