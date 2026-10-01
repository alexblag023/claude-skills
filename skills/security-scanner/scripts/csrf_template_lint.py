#!/usr/bin/env python3
"""Статический линтер CSRF по шаблонам и JS (эмуляция внешнего паттерн-SAST).

Зачем: серверный гвард (Origin/Sec-Fetch-Site middleware) реально защищает, но
паттерн-SAST его НЕ видит — он ищет в шаблоне `<form method=post>` без токена и
ставит High (CWE-352). Этот линтер воспроизводит эту проверку, чтобы найти такие
формы ДО внешней экспертизы.

Правила:
1. Каждая `<form method=post|put|patch|delete>` и каждый элемент с hx-post/put/patch/delete
   должны иметь anti-CSRF токен ВНУТРИ формы (hidden-input csrf*/_token/authenticity_token/xsrf*
   либо хелпер фреймворка: {% csrf_token %}, form.hidden_tag(), @csrf, csrf_field(), AntiForgery…)
   либо hx-headers/hx-vals с csrf на элементе/предке (<body hx-headers='{"X-CSRF-Token": "…"}'>).
2. JS-файл с fetch/axios/$.post/XHR, изменяющим состояние, должен где-то упоминать csrf/xsrf-токен
   (эвристика на уровне файла: проверьте общий wrapper/заголовок).

Покрытие: html/jinja/twig/ejs/hbs/blade/erb/php/cshtml, jsx/tsx/vue/svelte; JS: js/mjs/ts.
Не покрывает: формы, собираемые динамически строками в JS; токен, подставляемый серверным
middleware без следа в разметке (это и есть то, что внешний SAST не видит).

Использование: python csrf_template_lint.py <корень|файл> [--json]
Код возврата: 0 — чисто, 1 — есть находки (гейт CI/pre-commit).
"""
from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

TEMPLATE_EXTS = {'.html', '.htm', '.jinja', '.jinja2', '.j2', '.tmpl', '.mako', '.ejs', '.hbs', '.twig',
                 '.jsx', '.tsx', '.vue', '.svelte', '.php', '.erb', '.cshtml', '.razor', '.blade'}
JS_EXTS = {'.js', '.mjs', '.ts', '.jsx', '.tsx', '.vue', '.svelte'}
EXTS = TEMPLATE_EXTS | JS_EXTS
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '.build-venv', 'site-packages', 'dist', 'build',
             '__pycache__'}

TOKEN_RE = re.compile(r'csrf|xsrf|_token|authenticity_token', re.I)
# Хелперы фреймворков, вставляющие токен: Django, Flask-WTF, Laravel, Rails, ASP.NET, Spring
HELPER_RE = re.compile(
    r'csrf_(?:token|input|field)|csrf\(|xsrf|hidden_tag\(|form\.csrf|@csrf|AntiForgery|_csrf|authenticity_token',
    re.I)
JS_UNSAFE_RE = re.compile(
    r"fetch\([^)]*method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]"
    r"|axios\.(?:post|put|patch|delete)\("
    r"|\$\.(?:post|ajax)\("
    r"|XMLHttpRequest",
    re.I | re.S)
UNSAFE = {'post', 'put', 'patch', 'delete'}
HX_UNSAFE = {'hx-post', 'hx-put', 'hx-patch', 'hx-delete'}
VOID = {'input', 'meta', 'br', 'img', 'hr', 'link'}


class Lint(HTMLParser):
    def __init__(self, path: Path, global_token: bool = False):
        super().__init__(convert_charrefs=True)
        self.path = path
        # Layout проекта задаёт токен в hx-headers на <body>/<html>; partial-шаблоны (без своего <body>)
        # рендерятся внутрь него и токен наследуют.
        self.global_token = global_token
        self.findings: list[dict] = []
        self.forms: list[dict] = []      # стек открытых форм
        self.ctx_token: list[bool] = []  # стек: есть ли токен в hx-headers/hx-vals предков

    def _add(self, line: int, what: str) -> None:
        self.findings.append({'file': str(self.path), 'line': line, 'issue': what})

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or '') for k, v in attrs}
        line = self.getpos()[0]
        inherited = any(self.ctx_token) or self.global_token
        own = bool(TOKEN_RE.search(a.get('hx-headers', '') + a.get('hx-vals', '')))
        if tag not in VOID:
            self.ctx_token.append(own)
        if tag == 'form':
            unsafe = a.get('method', 'get').lower() in UNSAFE or any(k in a for k in HX_UNSAFE)
            self.forms.append({'line': line, 'unsafe': unsafe, 'token': inherited or own})
        elif tag == 'input' and self.forms:
            if a.get('type', '').lower() == 'hidden' and TOKEN_RE.search(a.get('name', '') + a.get('value', '')):
                self.forms[-1]['token'] = True
        if tag != 'form' and any(k in a for k in HX_UNSAFE) and not self.forms and not (inherited or own):
            self._add(line, f'<{tag}> с hx-post/put/patch/delete вне формы без CSRF-токена (hx-headers/hx-vals)')

    def handle_endtag(self, tag):
        if tag not in VOID and self.ctx_token:
            self.ctx_token.pop()
        if tag == 'form' and self.forms:
            self._finish_form(self.forms.pop(), closed=True)

    def handle_data(self, data):
        # серверный хелпер токена ({% csrf_token %}, {{ form.hidden_tag() }}, @csrf…) стоит текстом
        if self.forms and HELPER_RE.search(data):
            self.forms[-1]['token'] = True

    def _finish_form(self, f: dict, closed: bool) -> None:
        if f['unsafe'] and not f['token']:
            suffix = '' if closed else ' (форма не закрыта до конца файла)'
            self._add(f['line'], 'state-changing <form> без anti-CSRF токена (CWE-352)' + suffix)

    def close(self):
        super().close()
        # html.parser не шлёт end-событие для незакрытых форм — проверяем остаток стека сами
        while self.forms:
            self._finish_form(self.forms.pop(), closed=False)


LAYOUT_TOKEN_RE = re.compile(
    # значение атрибута в одинарных кавычках содержит двойные (JSON): ищем токен до закрывающей кавычки того же вида
    r"""<(?:body|html)\b[^>]*hx-(?:headers|vals)\s*=\s*(['"])(?:(?!\1).)*?(?:csrf|xsrf|_token)""", re.I | re.S)
HAS_ROOT_RE = re.compile(r'<(?:body|html)\b', re.I)


def scan_js(path: Path, text: str) -> list[dict]:
    """Эвристика уровня файла: небезопасный запрос есть, упоминания csrf/xsrf-токена нет."""
    m = JS_UNSAFE_RE.search(text)
    if m and not TOKEN_RE.search(text):
        line = text.count('\n', 0, m.start()) + 1
        return [{'file': str(path), 'line': line,
                 'issue': 'JS-запрос с изменением состояния, в файле нет CSRF-токена '
                          '(эвристика: проверьте общий wrapper/заголовок)'}]
    return []


def scan(root: Path) -> list[dict]:
    out: list[dict] = []
    files = [root] if root.is_file() else (p for p in root.rglob('*')
                                          if p.suffix.lower() in EXTS and not SKIP_DIRS & set(p.parts))
    files = [p for p in files if not p.name.lower().endswith('.min.js')]  # вендорные бандлы не анализируем
    texts: dict[Path, str] = {}
    for p in files:
        try:
            texts[p] = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
    layout_token = any(p.suffix.lower() in TEMPLATE_EXTS and LAYOUT_TOKEN_RE.search(t) for p, t in texts.items())
    for p, text in texts.items():
        ext = p.suffix.lower()
        if ext in TEMPLATE_EXTS:
            lint = Lint(p, global_token=layout_token and not HAS_ROOT_RE.search(text))
            lint.feed(text)
            lint.close()
            out += lint.findings
        if ext in JS_EXTS:
            out += scan_js(p, text)
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
