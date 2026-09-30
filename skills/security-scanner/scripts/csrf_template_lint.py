#!/usr/bin/env python3
"""Статический линтер CSRF по HTML/Jinja-шаблонам (эмуляция внешнего паттерн-SAST).

Зачем: серверный гвард (Origin/Sec-Fetch-Site middleware) реально защищает, но
паттерн-SAST его НЕ видит — он ищет в шаблоне `<form method=post>` без токена и
ставит High (CWE-352). Этот линтер воспроизводит эту проверку, чтобы найти такие
формы ДО внешней экспертизы.

Правило: каждая `<form method=post|put|patch|delete>` и каждый элемент с
hx-post/put/patch/delete/hx-boost должны иметь anti-CSRF токен ВНУТРИ формы
(hidden-input с именем csrf*/_token/authenticity_token/xsrf* или Jinja-вызов
csrf_token/csrf_input) либо hx-headers/hx-vals с csrf на элементе/предке
(типично <body hx-headers='{"X-CSRF-Token": "{{ csrf_token }}"}'>).

Использование: python csrf_template_lint.py <корень> [--json]
Код возврата: 0 — чисто, 1 — есть находки (гейт CI/pre-commit).
"""
from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

EXTS = {'.html', '.htm', '.jinja', '.jinja2', '.j2', '.tmpl', '.mako', '.ejs', '.hbs', '.twig'}
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '.build-venv', 'site-packages', 'dist', 'build', '__pycache__'}
TOKEN_RE = re.compile(r'csrf|xsrf|_token|authenticity_token', re.I)
UNSAFE = {'post', 'put', 'patch', 'delete'}
HX_UNSAFE = {'hx-post', 'hx-put', 'hx-patch', 'hx-delete'}


class Lint(HTMLParser):
    def __init__(self, path: Path):
        super().__init__(convert_charrefs=True)
        self.path = path
        self.findings: list[dict] = []
        self.forms: list[dict] = []      # стек открытых форм
        self.ctx_token: list[bool] = []  # стек: есть ли токен в hx-headers/hx-vals предков

    def _add(self, line: int, what: str) -> None:
        self.findings.append({'file': str(self.path), 'line': line, 'issue': what})

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}
        line = self.getpos()[0]
        inherited = any(self.ctx_token)
        own = bool(TOKEN_RE.search(a.get('hx-headers', '') + a.get('hx-vals', '')))
        if tag not in {'input', 'meta', 'br', 'img', 'hr', 'link'}:
            self.ctx_token.append(own)
        if tag == 'form':
            self.forms.append({'line': line, 'unsafe': a.get('method', 'get').lower() in UNSAFE
                               or any(k in a for k in HX_UNSAFE),
                               'token': inherited or own})
        elif tag == 'input' and self.forms:
            if a.get('type', '').lower() == 'hidden' and TOKEN_RE.search(a.get('name', '') + a.get('value', '')):
                self.forms[-1]['token'] = True
        # Шаблонный токен может стоять текстом ({{ csrf_input }}) — ловим в handle_data.
        if tag != 'form' and any(k in a for k in HX_UNSAFE) and not self.forms and not (inherited or own):
            self._add(line, f'<{tag}> с hx-post/put/patch/delete вне формы без CSRF-токена (hx-headers/hx-vals)')

    def handle_endtag(self, tag):
        if tag not in {'input', 'meta', 'br', 'img', 'hr', 'link'} and self.ctx_token:
            self.ctx_token.pop()
        if tag == 'form' and self.forms:
            f = self.forms.pop()
            if f['unsafe'] and not f['token']:
                self._add(f['line'], 'state-changing <form> без anti-CSRF токена (CWE-352)')

    def handle_data(self, data):
        if self.forms and re.search(r'csrf_(token|input)|csrf\(|xsrf', data, re.I):
            self.forms[-1]['token'] = True


def scan(root: Path) -> list[dict]:
    out: list[dict] = []
    files = [root] if root.is_file() else (p for p in root.rglob('*') if p.suffix.lower() in EXTS
                                          and not SKIP_DIRS & set(p.parts))
    for p in files:
        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        lint = Lint(p)
        lint.feed(text)
        out += lint.findings
    return out


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')  # Windows-консоль по умолчанию не UTF-8
    target = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    res = scan(target)
    if '--json' in sys.argv:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        for f in res:
            print(f"{f['file']}:{f['line']}: {f['issue']}")
        print(f'CSRF-template-lint: {len(res)} находок')
    sys.exit(1 if res else 0)
