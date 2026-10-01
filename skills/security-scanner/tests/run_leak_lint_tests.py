#!/usr/bin/env python3
"""Регрессионные тесты scripts/java_resource_leak_lint.py: bad/* обязаны давать находки, good/* — не давать.
Запуск: python tests/run_leak_lint_tests.py   (код 0 — все прошли). Зависимостей нет (только стандартная библиотека).
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
import java_resource_leak_lint as lint  # noqa: E402

# файл -> сколько утечек ожидаем
BAD = {'LeakStmt.java': 3, 'LeakReader.java': 1, 'LeakInputStream.java': 1, 'LeakAssignedLater.java': 2,
       'LeakScanner.java': 1, 'LeakCommentClose.java': 1,
       'LeakValueRead.java': 2}  # регрессия: new Dto(r.getString(1)) — чтение значения, а не передача владения


def main() -> int:
    failed = []
    for name, n in BAD.items():
        got = len(lint.lint_file(HERE / 'leak_fixtures' / 'bad' / name))
        if got != n:
            failed.append(f'bad/{name}: ожидалось {n} утечек, найдено {got}')
    for f in sorted((HERE / 'leak_fixtures' / 'good').glob('*.java')):
        res = lint.lint_file(f)
        if res:
            failed.append(f'good/{f.name}: ложное срабатывание {[(r["line"], r["variable"]) for r in res]}')
    # строгий режим: закрытие родителя не освобождает дочерние Statement/ResultSet (ParentClosed.java чист по умолчанию)
    pc = HERE / 'leak_fixtures' / 'good' / 'ParentClosed.java'
    lint.STRICT = True
    strict_n = len(lint.lint_file(pc))
    lint.STRICT = False
    if strict_n != 2:
        failed.append(f'--strict: ParentClosed.java должен давать 2 находки (Statement, ResultSet), получено {strict_n}')
    # режим каталога и коды возврата
    p = subprocess.run([sys.executable, str(HERE.parent / 'scripts' / 'java_resource_leak_lint.py'),
                        str(HERE / 'leak_fixtures' / 'good')], capture_output=True, text=True, encoding='utf-8')
    if p.returncode != 0:
        failed.append(f'каталог good/ должен давать код 0, получено {p.returncode}\n{p.stdout}')
    p = subprocess.run([sys.executable, str(HERE.parent / 'scripts' / 'java_resource_leak_lint.py'),
                        str(HERE / 'leak_fixtures' / 'bad'), '--sarif'], capture_output=True, text=True, encoding='utf-8')
    try:
        sarif = json.loads(p.stdout)
        n = len(sarif['runs'][0]['results'])
        if p.returncode != 1 or n != sum(BAD.values()):
            failed.append(f'SARIF по bad/: код {p.returncode}, результатов {n}, ожидалось {sum(BAD.values())}')
    except (ValueError, KeyError) as e:
        failed.append(f'SARIF не разобран: {e}')
    # SARIF принимается общим гейтом внешних отчётов
    tmp = HERE / '_leak_tmp.sarif'
    tmp.write_text(p.stdout, encoding='utf-8')
    q = subprocess.run([sys.executable, str(HERE.parent / 'scripts' / 'ingest_external_report.py'), str(tmp)],
                       capture_output=True, text=True, encoding='utf-8')
    tmp.unlink()
    if f'Всего находок: {sum(BAD.values())}' not in q.stdout:
        failed.append(f'ingest не принял SARIF линтера:\n{q.stdout}')
    for m in failed:
        print('FAIL', m)
    print(f'leak_lint tests: {"FAIL" if failed else "OK"} ({len(BAD)} bad, '
          f'{len(list((HERE / "leak_fixtures" / "good").glob("*.java")))} good, {len(failed)} ошибок)')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.exit(main())
