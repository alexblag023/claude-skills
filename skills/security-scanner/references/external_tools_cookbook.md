# Внешние сканеры: команды, форматы, как подключить к аудиту

Цель: получить выгрузку внешнего сканера (если он есть у принимающей стороны или в вашем CI), свести её в единый список находок и гейт по High/Critical скриптом `scripts/ingest_external_report.py`. Статусы: **[ПОДТВЕРЖДЕНО]** — проверено в этой сессии прогоном; **[ДОК]** — по официальной документации, живой выгрузки не было; **[ВТОРИЧНО]** — из сторонних источников, сверить на своей инстанции; **[НЕТ ДАННЫХ]** — не найдено, не выдумываем.

## Единый вход: `ingest_external_report.py`
```bash
python scripts/ingest_external_report.py <файл> [<файл>...] [--format sarif|ghas|sonar|veracode|checkmarx|cxsast|fortify|appscreener] [--fail-on critical|high|medium] [--json]
```
Автоопределение формата по содержимому. Код возврата 0 — блокеров нет, 1 — есть открытые находки не ниже порога, 2 — ошибка формата. Подавленные (`dismissed/false_positive/not_exploitable/suppressions`…) не считаются блокерами. Открытая находка класса **CSRF** (CWE-352 или имя правила) выводится отдельной строкой даже ниже порога — это сигнал прогнать `scripts/csrf_template_lint.py`.
Тесты: `python tests/run_ingest_tests.py` (синтетические выгрузки по документации + один настоящий SARIF gitleaks).

Шкалы приводятся к Info/Low/Medium/High/Critical: Veracode 0–5; Sonar `impacts` HIGH/MEDIUM/LOW и классические BLOCKER…INFO; GHAS `security_severity_level` (иначе `error/warning/note`); SARIF `security-severity` (≥9 Critical, ≥7 High, ≥4 Medium), иначе `level`; отсутствующий `level` = `warning` (по SARIF) [ПОДТВЕРЖДЕНО gitleaks]; инструменты поиска секретов (gitleaks/trufflehog/detect-secrets/ggshield) — минимум High.

## GitHub Advanced Security (code scanning / CodeQL)
- Выгрузка: `python scripts/fetch_ghas_alerts.py <owner>/<repo> [--state open] --out alerts.json` (обёртка над `gh api`, только чтение) и далее `ingest_external_report.py alerts.json`. [ПОДТВЕРЖДЕНО: путь ошибки — на репозитории без анализа `gh` вернул 404 «no analysis found», скрипт вернул код 2 с понятным сообщением; положительная выгрузка проверена на синтетической структуре]
- REST: `GET /repos/{owner}/{repo}/code-scanning/alerts` (параметры `state`, `severity`, `tool_name`, `ref`, `pr`, `per_page` ≤ 100); поля: `number`, `state`, `rule.id`, `rule.severity`, `rule.security_severity_level`, `rule.tags`, `tool.name`, `most_recent_instance.location.{path,start_line}`. Secret scanning: `/secret-scanning/alerts`; Dependabot: `/dependabot/alerts` (в ingest не разбираются — это SCA/секреты, их покрывают Trivy/gitleaks). [ДОК: docs.github.com/en/rest/code-scanning]
- Шкалы: `security_severity_level` low/medium/high/critical; `severity` none/note/warning/error; для алертов CodeQL GitHub берёт `security_severity_level`. [ДОК]
- CSRF: CodeQL `py/csrf-protection-disabled` (CWE-352) — находит отключённый/удалённый CSRF-middleware; для JS и HTML-шаблонов аналога в документации не найдено [ДОК/НЕТ ДАННЫХ].
- Бесплатно: CodeQL поддерживает Python, JS/TS; для публичных репозиториев доступен, для приватных нужна лицензия GitHub Code Security (прямо документацией не подтверждено).
- Включение (default setup): Settings → Code security → Code scanning → Default; либо workflow из `scanners_and_tooling.md` §3.

## SonarQube
- Анализ: `sonar-scanner -Dsonar.projectKey=… -Dsonar.host.url=… -Dsonar.token=… -Dsonar.sources=src` (токен лучше через `SONAR_TOKEN`). [ДОК]
- Выгрузка: `GET api/issues/search?componentKeys=<key>&ps=500&p=1` (фильтры `impactSeverities`, `issueStatuses`, `types`; лимит 10 000 результатов — сужайте фильтрами) и `GET api/hotspots/search?projectKey=<key>` (`status`, `resolution`). Сохранить ответ в файл и отдать в ingest (`{"issues":[…]}` / `{"hotspots":[…]}`). [ВТОРИЧНО — официальные страницы API на самой инстанции: Help → Web API]
- Поля: issue — `key, rule, severity, type, component, line, textRange, status, issueStatus, resolution, message, tags, impacts[{softwareQuality,severity}]`; hotspot — `ruleKey, securityCategory, vulnerabilityProbability, status, line, message`. Поля CWE в ответе не найдено: CWE видны тегами и категорией hotspot. [ВТОРИЧНО]
- Шкалы: классическая BLOCKER/CRITICAL/MAJOR/MINOR/INFO; MQR — Blocker/High/Medium/Low/Info. [ДОК]
- CSRF: правило S4502 «Disabling CSRF protections» — это **Security Hotspot** (Django: нет `CsrfViewMiddleware` или `@csrf_exempt`; Flask: нет `CSRFProtect`); для JS/HTML-шаблонов отдельного правила не найдено. [ДОК] Hotspot в статусе `TO_REVIEW` в ingest считается открытым.
- Бесплатно: SonarQube Community Build (self-managed). [ДОК]

## Snyk (Snyk Code, Open Source)
- Команды: `snyk code test --sarif-file-output=snyk-code.sarif` и `snyk test --sarif-file-output=snyk-oss.sarif` (также `--json-file-output`); `--severity-threshold` low|medium|high (Code), + critical (test). Коды выхода: 0 нет проблем, 1 есть, 2 сбой, 3 нет поддерживаемых проектов. [ДОК]
- SARIF: severity в `level` (High→error, Medium→warning, Low→note); правила `tool.driver.rules[]` (`id` вида `javascript/XSS`, `properties` с тегами/CWE); подавления — `suppressions`. [ВТОРИЧНО/ДОК] Ingest берёт именно SARIF; формат `--json` для `snyk test` не подтверждён — не разбирается.
- CSRF: имя правила не найдено [НЕТ ДАННЫХ] — берите из `ruleId` вашей выгрузки.
- Бесплатный тариф ограничен по числу тестов в месяц (цифры в источниках расходятся — проверьте snyk.io/plans). [ВТОРИЧНО]

## Veracode
- Pipeline Scan: `java -jar pipeline-scan.jar --veracode_api_id … --veracode_api_key … --file app.jar --json_output_file results.json --fail_on_severity="Very High, High"`; новый CLI: `veracode static scan` (`--results-file`, по умолчанию `./results.json`). Код возврата ≥ 1 при находках. [ДОК] Ключи — только из переменных окружения/секрет-хранилища, не в командной строке CI-логов.
- `results.json`: поля находки `issue_id, issue_type, cwe_id, severity, files, line, title, flaw_details_link`; полная схема и вложенность `files` не подтверждены — парсер ищет `files.source_file.{file,line}` и запасной `file/line`. [ДОК частично]
- Шкала: 0 Info, 1 Very Low, 2 Low, 3 Medium, 4 High, 5 Very High. [ДОК]
- `detailedreport.xml` (атрибуты `issueid, cweid, type, sourcefile, line, remediation_status`, mitigation в `annotation`) — формально в ingest не разбирается: схема `detailedreport.xsd`; используйте Pipeline Scan JSON или Findings API. [ВТОРИЧНО]
- API: `GET /appsec/v2/applications/{guid}/findings` (`scan_type`, `cwe`, `severity`), pipeline: `/pipeline_scan/v1/scans/{id}/findings`; аутентификация HMAC (API ID/key). [ДОК]
- CSRF: CWE-352 «Cross-Site Request Forgery (CSRF)», severity 3 (Medium) по умолчанию. [ДОК] Бесплатного SAST-trial не найдено (14-дневный trial только у DAST).

## Checkmarx (Checkmarx One / CxSAST)
- Checkmarx One CLI: `cx scan create --project-name <P> -s <путь> --branch <b> --report-format json --output-name cx_result --output-path .` (форматы: json, json-v2, sarif, summaryHTML/JSON/CONSOLE, gl-sast, sonar, markdown, PDF, SBOM); выгрузка готового скана: `cx results show --scan-id <id> --report-format sarif`. Один формат на запуск. [ДОК]
- JSON результата (из исходников ast-cli): `type, id, similarityId, status, state, severity, firstFoundAt, firstScanId, data{queryId, queryName, line, column, fileName}, vulnerabilityDetails{cweId, cvssScore}`; значения `severity`/`state` в документации не перечислены — парсер сравнивает без регистра и считает `NOT_EXPLOITABLE` подавленным. [ДОК частично]
- CxSAST XML: `<CxXMLResults><Query cweId name Severity …><Result FileName Line Status FalsePositive Severity/>`; `FalsePositive=True` считается подавленным. XML с `DOCTYPE/ENTITY` отклоняется. [ВТОРИЧНО]
- API Checkmarx One: токен OAuth `client_credentials` на `…iam.checkmarx.net/auth/realms/<tenant>/protocol/openid-connect/token`; результаты `GET /api/results?scan-id=<id>`. [ВТОРИЧНО]
- CSRF: запросы `CSRF`, `JSF_CSRF`, `Spring_CSRF`, `Spring_XSRF`, `Heuristic_CSRF`, `XS_CSRF` (JS); для HTML-шаблонов отдельного запроса не найдено. [ДОК] Бесплатного community/trial нет — PoC через продажи.

## Fortify (SCA + SSC)
- Скан: `sourceanalyzer -b <id> -clean`, трансляция, `sourceanalyzer -b <id> -scan -f out.fpr`. Выгрузка: `FPRUtility -information -listIssues -project out.fpr -f out.csv -outputFormat CSV`; фильтр `-search -query "[fortify priority order]:critical"`. [ДОК]
- Ingest читает CSV с поиском колонок по имени (`category/issue name`, `friority/priority/severity`, `path/file`, `line`) — это **best-effort**: точные заголовки колонок FPRUtility CSV не подтверждены. SARIF нативно SCA не отдаёт (через fcli), FVDL-XML в ingest не разбирается (схема не официальная). [ДОК частично]
- SSC API: токен `POST /api/v1/tokens`, находки `GET /api/v1/projectVersions/{id}/issues?q=…` с заголовком `Authorization: FortifyToken <token>`. [ВТОРИЧНО]
- CSRF: категория «Cross-Site Request Forgery» (Kingdom: Encapsulation); варианты для HTML не найдено. [ВТОРИЧНО] Публичного trial SCA нет.

## Solar appScreener
См. `external_sast_profiles.md`. Формат `Detailed_Results.csv` (`Vulnerability, Severity Level, File, Line…`) читается ingest-скриптом; русские уровни «Критический/Высокий/Средний/Низкий» распознаются. [ДОК парсера DefectDojo; живой выгрузки appScreener не было]

## Что это даёт аудиту (и чего не даёт)
- Даёт: единый гейт по внешним отчётам и ранний сигнал по классу CSRF; пруф для Z1/Z3 «внешний сканер: 0 открытых High/Critical».
- Не даёт: запуска платных сканеров (нужны лицензии и доступ принимающей стороны), оценки реальной эксплуатируемости, соответствия живым выгрузкам на 100 %: парсеры Veracode/Checkmarx/Fortify построены по документации и открытым клиентам, их нужно сверить на первой настоящей выгрузке (`--json` покажет, как распознаны поля; предупреждение выводится, если все находки получили Info при непустом исходном severity).
- Новый формат/сканер: добавьте парсер по образцу в `ingest_external_report.py`, фикстуру в `tests/ingest_fixtures/` и кейс в `tests/run_ingest_tests.py`.
