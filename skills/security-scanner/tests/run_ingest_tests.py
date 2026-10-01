#!/usr/bin/env python3
"""Тесты ingest_external_report.py на СИНТЕТИЧЕСКИХ выгрузках (имена полей — по документации сканеров).

Фикстуры не являются настоящими отчётами: они доказывают, что парсер корректно читает задокументированную
структуру и правильно считает блокеры; соответствие живым выгрузкам нужно подтверждать на реальных данных.
Запуск: python tests/run_ingest_tests.py   (код 0 — все прошли)
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / 'scripts' / 'ingest_external_report.py'
FX = HERE / 'ingest_fixtures'

# файл -> (ожидаемый код возврата при --fail-on high, число блокеров, ожидается ли «Класс CSRF» в выводе)
CASES = {
    'snyk_like.sarif': (1, 1, True),       # High CSRF + Low; подавленная High не считается
    'codeql_like.sarif': (1, 1, False),    # security-severity 9.8 по ruleIndex -> Critical
    'ghas_alerts.json': (1, 1, True),      # open High CSRF; dismissed Critical не считается
    'sonar.json': (1, 2, True),            # issue HIGH + hotspot HIGH(csrf S4502); FALSE_POSITIVE не считается
    'veracode.json': (1, 1, True),         # severity 5 + CWE 352; severity 2 — нет
    'checkmarx_one.json': (1, 1, True),    # HIGH Spring_CSRF; NOT_EXPLOITABLE не считается
    'cxsast.xml': (1, 1, True),            # блокер: High SQLi; открытая Medium CSRF не блокер, но класс CSRF сообщается
    'fortify.csv': (1, 1, True),
    'appscreener.csv': (1, 1, True),       # «Высокий» -> High
    'kics_real.json': (1, 6, False),       # НАСТОЯЩИЙ родной JSON KICS (точная критичность queries[].severity)
    'kics_real.sarif': (1, 6, False),      # НАСТОЯЩИЙ вывод KICS: level нет, severity в properties.riskScore (1 Critical + 5 High)
    'gitleaks_real.sarif': (1, 1, False),  # НАСТОЯЩИЙ вывод gitleaks (level отсутствует -> warning; секрет = минимум High)
}


def run(*args):
    p = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding='utf-8')
    return p.returncode, p.stdout


def main() -> int:
    failed = []
    for name, (rc_exp, blk_exp, csrf_exp) in CASES.items():
        rc, out = run(str(FX / name))
        blk = int(next((l.split(':')[-1] for l in out.splitlines() if l.startswith('Блокеров')), '-1'))
        if rc != rc_exp or blk != blk_exp or ('Класс CSRF' in out) != csrf_exp:
            failed.append(f'{name}: rc={rc} (ожид. {rc_exp}), блокеров={blk} (ожид. {blk_exp}), '
                          f'CSRF={"Класс CSRF" in out} (ожид. {csrf_exp})\n{out}')
    # порог critical: у sonar/ghas/checkmarx/cxsast нет открытых Critical -> код 0
    rc, _ = run(str(FX / 'ghas_alerts.json'), '--fail-on', 'critical')
    if rc != 0:
        failed.append('ghas --fail-on critical: dismissed Critical не должен блокировать')
    rc, _ = run(str(FX / 'codeql_like.sarif'), '--fail-on', 'critical')
    if rc != 1:
        failed.append('codeql --fail-on critical: открытый Critical должен блокировать')
    # несколько файлов в одном вызове
    rc, out = run(str(FX / 'veracode.json'), str(FX / 'fortify.csv'))
    if rc != 1 or 'Блокеров (открытые, не ниже High): 2' not in out:
        failed.append(f'мульти-файл: ожидалось 2 блокера\n{out}')
    # KICS: критичность из riskScore — порог critical оставляет ровно один блокер (9.1)
    rc, out = run(str(FX / 'kics_real.sarif'), '--fail-on', 'critical')
    if rc != 1 or 'Блокеров (открытые, не ниже Critical): 1' not in out:
        failed.append('kics --fail-on critical: ожидался 1 блокер (riskScore 9.1)')
    # Veracode: неуспешный скан с пустым списком находок НЕ может быть «чисто» (код 2)
    rc, out = run(str(FX / 'veracode_failed.json'))
    if rc != 2 or 'scan_status' not in out:
        failed.append(f'veracode_failed.json должен давать код 2 со scan_status: rc={rc}\n{out}')
    # XML с DTD отклоняется (код 2)
    rc, out = run(str(FX / 'evil.xml'), '--format', 'cxsast')
    if rc != 2 or 'DOCTYPE' not in out:
        failed.append(f'evil.xml должен быть отклонён: rc={rc}\n{out}')
    # пустой SARIF -> блокеров нет
    empty = HERE / 'ingest_fixtures' / '_empty.sarif'
    empty.write_text('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}', encoding='utf-8')
    rc, _ = run(str(empty))
    empty.unlink()
    if rc != 0:
        failed.append('пустой SARIF должен давать код 0')
    for f in failed:
        print('FAIL', f)
    print(f'ingest tests: {"FAIL" if failed else "OK"} ({len(failed)} ошибок из {len(CASES) + 7} проверок)')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main())
