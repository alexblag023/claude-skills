# Межфайловый корпус (cross-file taint)

Доказательство разрыва, который закрывает эксперт CodeQL (№5), а Semgrep OSS — нет.

- `app_routes.py` — SOURCE: `request.args['id']` уходит в `lookup_user()` из другого модуля.
- `db_helper.py` — SINK: `cursor.execute("..."+uid)` (CWE-89), ввод пришёл из `app_routes.py`.

Semgrep OSS делает taint только внутри одного файла → на этой паре даёт 0 находок
(проверено живьём, см. `references/codeql_crossfile.md`). Корректный прогон CodeQL
(`py/sql-injection`) эту цепочку находит — sanity-check эксперта межфайлового taint.
