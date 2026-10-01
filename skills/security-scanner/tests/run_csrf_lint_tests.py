#!/usr/bin/env python3
"""Регрессионные тесты csrf_template_lint.py: bad/* обязаны давать находки, good/* — не давать.
Запуск: python tests/run_csrf_lint_tests.py   (код 0 — все прошли)
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
import csrf_template_lint as lint  # noqa: E402


def main() -> int:
    failed = []
    for kind, expect_findings in (('bad', True), ('good', False)):
        for f in sorted((HERE / 'csrf_fixtures' / kind).iterdir()):
            got = bool(lint.scan(f))
            if got != expect_findings:
                failed.append(f'{kind}/{f.name}: ожидалось {"находка" if expect_findings else "чисто"}, '
                              f'получено {"находка" if got else "чисто"}')
    # режим каталога: расширения должны подхватываться без явного указания файла
    in_dir = {Path(x['file']).name for x in lint.scan(HERE / 'csrf_fixtures' / 'bad')}
    for name in ('vue_form.vue', 'php_form.php', 'erb_form.erb', 'tsx_form.tsx', 'jsx.jsx', 'fetch.js'):
        if name not in in_dir:
            failed.append(f'режим каталога не нашёл {name}')
    good_dir = lint.scan(HERE / 'csrf_fixtures' / 'good')
    if good_dir:
        failed.append(f'режим каталога: ложные срабатывания в good/: {sorted({Path(x["file"]).name for x in good_dir})}')
    # проект: токен в layout (hx-headers на <body>) покрывает partial без собственного <body>; .min.js пропускается
    gp = lint.scan(HERE / 'csrf_fixtures' / 'good_project')
    if gp:
        failed.append(f'good_project: ложные срабатывания {[(Path(x["file"]).name, x["line"]) for x in gp]}')
    bp = lint.scan(HERE / 'csrf_fixtures' / 'bad_project')
    if {Path(x['file']).name for x in bp} != {'partial.html'}:
        failed.append(f'bad_project: ожидалась находка в partial.html, получено {[Path(x["file"]).name for x in bp]}')
    for msg in failed:
        print('FAIL', msg)
    print(f'csrf_lint tests: {"FAIL" if failed else "OK"} ({len(failed)} ошибок)')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main())
