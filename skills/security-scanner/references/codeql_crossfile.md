# Межфайловый taint: эксперт CodeQL

## Зачем (доказанный разрыв)

Semgrep OSS делает taint-анализ только **внутри одного файла/метода**. Если источник внешних данных в одном файле, а опасный приёмник — в другом (через вызов функции/метода), цепочка теряется.

Проверено живым прогоном (Semgrep 1.x, Docker `semgrep/semgrep:latest`, 2026-10-03) на `tests/crossfile_corpus/` (источник `request.args` в `app_routes.py` → sink `cursor.execute("..."+uid)` в `db_helper.py`):

| Прогон | Та же уязвимость | Находок OSS Semgrep |
|---|---|---|
| Однофайловый эквивалент | да | **2** (`sql-injection-db-cursor-execute`, `tainted-sql-string`) |
| Межфайловый (2 файла) | да | **0** |

Разрыв не в отсутствии правила, а в межфайловости. Его закрывает **CodeQL** (межпроцедурный Code Property Graph). Это эксперт-анализатор **№5 (межфайловый taint)**, дополняющий SAST-эксперта (Semgrep/intra-file), а не заменяющий его.

## Предусловие и N/A

CodeQL — отдельно устанавливаемый инструмент (CLI + query-пак/bundle), НЕ входит в бандл скилла (лицензия ниже). Если CodeQL недоступен в среде — эксперт возвращает `MANUAL` с пометкой «межфайловый taint не проверен: нужен CodeQL», НЕ `PASS` (принцип скилла: «не проверено» ≠ PASS). В составе платформы `scanner-platform` есть движок CodeQL (образ `scanner-platform/codeql`, прекомпилированный `codeql-bundle`) — там прогон делается через неё (`scripts/platform_bridge.py`, движок `codeql`).

## Команды-пруфы (buildless, где возможно)

CodeQL строит базу из исходников. Для интерпретируемых языков (Python, JS/TS, Ruby, Go) сборка не нужна; Java buildless — `--build-mode=none`; C/C++/C# требуют сборки.

```bash
# 1) создать базу (пример: Python, buildless)
codeql database create cdb --language=python --source-root=<repo> --overwrite

# 2) анализ query-паком безопасности -> SARIF (единый формат с остальными анализаторами)
codeql database analyze cdb codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=codeql.sarif --threads=0

# языки: codeql/{python,javascript,java,go,ruby,csharp,cpp}-queries,
# сюиты: *-security-extended.qls (шире) или *-code-scanning.qls (базовая)
```

SARIF от CodeQL вливается тем же путём, что и прочие выгрузки: `scripts/ingest_external_report.py` (см. `external_tools_cookbook.md`), находки идут в дедуп Шага 3 и питают Z1 (межфайловые инъекции/taint), частично Z3.

## Проверка результата

Прогон считается проведённым, если CodeQL создал базу без ошибок и выдал SARIF. На `tests/crossfile_corpus/` корректный CodeQL-прогон должен дать межфайловую SQL-инъекцию (`py/sql-injection`), которую Semgrep OSS пропускает (см. таблицу выше) — это sanity-check эксперта. Скоринг по манифесту — `tests/score.py --format sarif` (SARIF-загрузчик уже поддержан).

## Fallback и границы

- CodeQL нет → `MANUAL` (не `PASS`), с указанием, что межфайловые цепочки не покрыты.
- C/C++/C# buildless неполон → пометить ограничение, не выдавать частичный результат за полный.
- CodeQL дополняет, а не отменяет Semgrep-эксперта: внутрифайловые находки и собственные gaps-правила остаются.
