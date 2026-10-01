#!/usr/bin/env python3
"""Проверка собственных правил Semgrep (rules/semgrep/gaps.yml и gaps_java.yml) на корпусе уязвимых и безопасных примеров.

 - tests/vuln_corpus/       — намеренно уязвимые примеры, по файлу на класс (имя файла = CWE-класс)
 - tests/vuln_corpus_safe/  — безопасные эквиваленты: правила НЕ должны срабатывать

Нужен установленный Semgrep (`pip install semgrep` или переменная SEMGREP_BIN); без него тест пропускается (код 0,
строка SKIP) — в CI Semgrep ставится явно. Правила из реестра (p/security-audit и др.) здесь не запускаются
(нужна сеть); их результаты по корпусу описаны в references/coverage_matrix.md.
Запуск: python tests/run_coverage_tests.py   (код 0 — всё прошло или SKIP, 1 — провал)
"""
import json
import os
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RULES = [HERE.parent / 'rules' / 'semgrep' / 'gaps.yml', HERE.parent / 'rules' / 'semgrep' / 'gaps_java.yml']
BAD, SAFE = HERE / 'vuln_corpus', HERE / 'vuln_corpus_safe'

# файл корпуса -> правило gaps.yml, которое обязано сработать
EXPECTED = {
    'cwe079_dom_xss.js': 'gap-dom-xss-innerhtml',
    'cwe362_race_toctou.py': 'gap-toctou-exists-then-open',
    'cwe400_regex_dos.py': 'gap-regex-dos-user-pattern',
    'cwe434_upload.py': 'gap-upload-unsanitized-filename',
    'cwe476_null.c': 'gap-c-malloc-use-without-null-check',
    'cwe502_yaml.py': 'gap-yaml-load-unsafe',
    'cwe601_open_redirect.py': 'gap-open-redirect',
    'cwe611_xxe.py': 'gap-xxe-lxml-resolve-entities',
    'cwe798_hardcoded_secret.py': 'gap-hardcoded-secret-assignment',
    'cwe862_missing_authz.py': 'gap-flask-admin-route-without-auth',
    # Java/Spring (gaps_java.yml)
    'cwe078_java_exec.java': 'gap-java-exec-shell-dynamic',
    'cwe079_java_xss_responsebody.java': 'gap-java-xss-responsebody',
    'cwe113_java_crlf.java': 'gap-java-crlf-header-cookie',
    'cwe117_java_logforging.java': 'gap-java-log-forging',
    'cwe134_java_format.java': 'gap-java-format-string',
    'cwe330_java_random.java': 'gap-java-insecure-random',
    'cwe470_java_reflection.java': 'gap-java-unsafe-reflection',
    'cwe601_java_redirect.java': 'gap-java-open-redirect',
    'cwe501_java_trust_boundary.java': 'gap-java-trust-boundary-session',
    'cwe209_java_error_leak.java': 'gap-java-error-info-leak',
    'cwe259_java_password_field.java': 'gap-java-hardcoded-password-var',
    'cwe798_java_password_call.java': 'gap-java-hardcoded-password-call',
    'cwe798_java_default_creds.java': 'gap-java-default-credentials',
    'cwe134_java_implicit_param.java': 'gap-java-format-string',  # неявная привязка Spring без @RequestParam
}


def scan(semgrep: str, target: Path) -> dict:
    # Корпус копируется во временный каталог вне git: внутри репозитория Semgrep сканирует только отслеживаемые
    # файлы (git ls-files) и применяет .gitignore/.semgrepignore (по умолчанию игнорируется tests/) — результат
    # зависел бы от окружения запуска.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / 'corpus'
        shutil.copytree(target, work, ignore=shutil.ignore_patterns('_*', '__pycache__'))
        out = Path(tmp) / 'out.json'
        p = subprocess.run([semgrep, 'scan', *[a for r in RULES for a in ('--config', str(r))], '--json', '--output', str(out), '--metrics=off',
                            '--disable-version-check', '--quiet', str(work)],
                           capture_output=True, text=True, encoding='utf-8', env={**os.environ, 'PYTHONUTF8': '1'})
        if not out.exists():
            raise RuntimeError(f'semgrep не создал отчёт: {p.stderr[-300:]}')
        data = json.loads(out.read_text(encoding='utf-8'))
    if data.get('errors'):
        raise RuntimeError(f'ошибки правил: {[e.get("message", "")[:120] for e in data["errors"]][:3]}')
    hits = {}
    for r in data['results']:
        hits.setdefault(Path(r['path']).name, set()).add(r['check_id'].split('.')[-1])
    return hits


def main() -> int:
    semgrep = os.environ.get('SEMGREP_BIN') or shutil.which('semgrep')
    if not semgrep:
        print('SKIP: Semgrep не установлен (pip install semgrep или SEMGREP_BIN)')
        return 0
    failed = []
    bad = scan(semgrep, BAD)
    for f, rule in EXPECTED.items():
        if rule not in bad.get(f, set()):
            failed.append(f'пропуск: {f} должен сработать {rule}, получено {sorted(bad.get(f, []))}')
    safe = scan(semgrep, SAFE)
    for f, rules in safe.items():
        failed.append(f'ложное срабатывание на безопасном {f}: {sorted(rules)}')
    for m in failed:
        print('FAIL', m)
    print(f'coverage tests: {"FAIL" if failed else "OK"} ({len(EXPECTED)} классов на уязвимых, '
          f'{len(list(SAFE.iterdir()))} безопасных примеров, {len(failed)} ошибок)')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main())
