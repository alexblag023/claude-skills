#!/usr/bin/env python3
"""Тест моста к платформе против локального HTTP-сервера, имитирующего её API (без Docker и сети).

Проверяет: Bearer-токен уходит в заголовке, цикл ожидания скана, фильтр по критичности, отклонённые не попадают
в сводку, код возврата 1 для partial, отсутствие токена -> ошибка, токен не печатается.
Запуск: python tests/run_bridge_tests.py
"""
import contextlib
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import platform_bridge as pb  # noqa: E402

TOKEN = 'secret-token-123'
STATE = {'status': 'completed', 'polls': 0, 'auth': []}
FINDINGS = [
    {'fingerprint': 'a' * 20, 'severity': 'High', 'class': 'CWE-89', 'path': 'a.py', 'line': 3, 'tools': ['semgrep'], 'status': 'unreviewed'},
    {'fingerprint': 'b' * 20, 'severity': 'Low', 'class': 'CWE-1', 'path': 'b.py', 'line': 1, 'tools': ['bandit'], 'status': 'unreviewed'},
    {'fingerprint': 'c' * 20, 'severity': 'High', 'class': 'CWE-79', 'path': 'c.py', 'line': 2, 'tools': ['semgrep'], 'status': 'rejected'},
]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _scan(self, status):
        return {'id': 's1', 'project_id': 'p1', 'number': 1, 'status': status, 'rating': 4.0, 'counts': {'High': 1}}

    def do_POST(self):
        STATE['auth'].append(self.headers.get('Authorization'))
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        if self.path == '/api/projects':
            self._send({'id': 'p1'}, 201)
        else:
            self._send(self._scan('running'), 202)

    def do_GET(self):
        STATE['auth'].append(self.headers.get('Authorization'))
        if self.path == '/api/scans/s1':
            STATE['polls'] += 1
            self._send(self._scan(STATE['status']))
        elif self.path == '/api/scans/s1/findings':
            self._send(FINDINGS)
        else:
            self._send({'remediation': {'fix': ['Параметризуйте запрос']}})


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = pb.main(argv)
    return rc, buf.getvalue()


def main() -> int:
    srv = HTTPServer(('127.0.0.1', 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{srv.server_port}'
    pb.time.sleep = lambda s: None
    os.environ['SCANNER_TOKEN'] = TOKEN
    fails = []

    rc, out = run(['--url', url, 'scan', '/projects/x', '--min-severity', 'High'])
    if rc != 0 or 'CWE-89' not in out or 'CWE-1 ' in out or 'CWE-79' in out or 'Параметризуйте' not in out:
        fails.append(f'scan summary wrong: rc={rc} out={out!r}')
    if TOKEN in out or set(STATE['auth']) != {f'Bearer {TOKEN}'}:
        fails.append('токен печатается или не передаётся в заголовке')

    STATE['status'] = 'partial'
    rc, _ = run(['--url', url, 'findings', 's1'])
    if rc != 1:
        fails.append(f'partial должен давать код 1, получен {rc}')

    del os.environ['SCANNER_TOKEN']
    try:
        run(['--url', url, 'findings', 's1'])
        fails.append('без токена должна быть ошибка')
    except SystemExit as e:
        if 'токен' not in str(e):
            fails.append(f'неверное сообщение: {e}')

    print('FAIL: ' + '; '.join(fails) if fails else 'OK: мост к платформе (4 проверки)')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
