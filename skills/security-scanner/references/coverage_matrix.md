# Матрица покрытия классов уязвимостей

Что скил реально ловит, а что нет. Построена **эмпирически** на корпусе `tests/vuln_corpus/` (по одному каноническому примеру на класс; 33 файла) и безопасных эквивалентах `tests/vuln_corpus_safe/` (10 файлов), прогон 2026-10-01: Semgrep 1.178.0 (правила реестра `p/security-audit`, `p/owasp-top-ten`, `p/python`, `p/secrets`, `p/dockerfile`, `p/javascript`, `p/c` + собственные `rules/semgrep/gaps.yml`), bandit 1.9.4, `scripts/csrf_template_lint.py`, gitleaks.

**Результат прогона:** до добавления собственных правил 25 из 33 применимых классов; после — **33 из 33** (регрессия: `python tests/run_coverage_tests.py`, нужен Semgrep; на безопасных примерах ложных срабатываний 0).

## Как читать
- ✔ — класс обнаружен на корпусе указанным средством (подтверждено прогоном).
- ◐ — только эвристика/узкий шаблон: ловит канонический пример, на реальном коде нужна проверка человеком.
- ▲ — есть текстовый чек-лист для эксперта-аудитора (`references/third_party/fortify_change_review/`, MIT), но нет скрипта: помогает ревью, **не гарантия**.
- ✗ — ни скрипта, ни чек-листа: только описание в тексте скила или внешний инструмент, не проверявшийся здесь.

> ВАЖНО: ✔ означает «способность обнаружения подтверждена на простом примере», а не «все варианты класса найдены». Один пример на класс не доказывает полноту. Мы НЕ утверждаем, что скил ловит все уязвимости, и не знаем набор правил закрытых сканеров.

## CWE/SANS Top 25 (2021) — классификатор, по которому отчитывается appScreener
| CWE | Класс | Чем покрыто | Статус |
|---|---|---|---|
| 787, 119 | Запись за границы буфера | Semgrep `p/c` (`insecure-use-string-copy-fn`: strcpy) | ◐ только небезопасные функции копирования; общая memory-safety C/C++ (cppcheck, clang-tidy, CodeQL) не проверялась |
| 125 | Чтение за границами | — | ✗ |
| 79 | XSS | Semgrep (`raw-html-format`, `template-unescaped-with-safe`), `gap-dom-xss-innerhtml` | ✔ |
| 20 | Валидация ввода | текст (Z1-01), taint-правила Semgrep косвенно; чек-лист `sc-injection.md` | ▲ |
| 78, 77 | Command injection | Semgrep + bandit (B602/B605) | ✔ |
| 89 | SQL injection | Semgrep + bandit B608 | ✔ |
| 416 | Use after free | Semgrep `p/c` (`use-after-free`) | ◐ канонический шаблон |
| 22 | Path traversal | Semgrep `path-traversal-open` | ✔ |
| 352 | CSRF | `csrf_template_lint.py` (формы, htmx, fetch/axios — эвристика); Semgrep `flask-wtf-csrf-disabled` | ✔ шаблоны/JS, Flask; ✗ серверные конфиги других фреймворков (Django `csrf_exempt` и т.п.) не проверялись |
| 434 | Небезопасная загрузка файлов | `gap-upload-unsanitized-filename` | ◐ |
| 476 | NULL-разыменование | `gap-c-malloc-use-without-null-check` | ◐ |
| 502 | Небезопасная десериализация | Semgrep/bandit (pickle), bandit + `gap-yaml-load-unsafe` (yaml.load) | ✔ |
| 190 | Переполнение целых | — | ✗ (актуально для C/C++; в Python неприменимо) |
| 287, 306 | Аутентификация / отсутствие её для критичной функции | текст (Z1-03); чек-лист `sc-authentication.md` | ▲ (логика, сканеры не ловят надёжно) |
| 798 | Секреты в коде | bandit B105, `gap-hardcoded-secret-assignment` (по имени переменной); gitleaks — форматы токенов | ◐: gitleaks НЕ нашёл `DB_PASSWORD='…'` — нужна связка |
| 862 | Отсутствие авторизации | `gap-flask-admin-route-without-auth`; чек-лист `sc-authorization.md` (IDOR, mass assignment) | ◐+▲ скрипт — только Flask-маршруты с `admin` в пути без декоратора; общая авторизация/IDOR — чек-лист и тесты |
| 276 | Небезопасные права по умолчанию | Semgrep + bandit (chmod 777) | ✔ |
| 918 | SSRF | Semgrep + bandit | ✔ |
| 362 | Гонки | `gap-toctou-exists-then-open` | ◐ только exists→open |
| 400 | Исчерпание ресурсов | `gap-regex-dos-user-pattern` (WARNING) | ◐; по политике скила DoS — не блокер (`scanners_and_tooling.md` §1, §10) |
| 611 | XXE | `gap-xxe-lxml-resolve-entities` | ◐ только lxml `XMLParser(resolve_entities=True)`; Semgrep и bandit этот пример пропустили; другие парсеры не проверялись |
| 94 | Code injection | Semgrep + bandit (`eval`) | ✔ |

## OWASP Top 10 (2021)
| Категория | Чем покрыто | Статус |
|---|---|---|
| A01 Broken Access Control | `gap-flask-admin-route-without-auth`, `gap-open-redirect`, path traversal; IDOR/авторизация — текст (Z1-04) и тесты | ◐ |
| A02 Cryptographic Failures | Semgrep/bandit: MD5, слабый random (bandit B311), отключённая проверка TLS | ✔ |
| A03 Injection | см. 78/89/79/94/611 | ✔ |
| A04 Insecure Design | текст (§1 «Insecure Design», threat-model); транспорт/крипто — `sc-crypto-transport.md` | ✗ дизайн / ▲ крипто |
| A05 Security Misconfiguration | Flask `debug=True`, Dockerfile без USER (Semgrep), `chmod 777`; IaC — чек-листы `sc-iac-*.md` и KICS; заголовки/CORS — ZAP baseline (не проверялся) | ◐+▲ |
| A06 Vulnerable Components | Trivy/OSV/pip-audit (команды в `scanners_and_tooling.md`) | ✗ не проверялось в этой сессии |
| A07 Auth Failures | пароль в коде (CWE-798); логика входа — текст | ◐ |
| A08 Integrity Failures | десериализация (pickle/yaml); цепочка поставки — текст и команды | ◐ |
| A09 Logging/Monitoring Failures | текст (Z4); чек-лист `sc-logging-audit.md` | ▲ |
| A10 SSRF | Semgrep + bandit | ✔ |

## Не из Top 25/Top 10: безопасность LLM-агентов
| Класс | Чем покрыто | Статус |
|---|---|---|
| Prompt injection, избыточные полномочия агента, небезопасные вызовы инструментов (CWE-77, 285; OWASP LLM) | чек-лист `sc-ai-agent-safety.md`; для самих скиллов — ревью вклада по `docs/review-checklist.md` репозитория скиллов | ▲ |

## Бенчмарк на реальном уязвимом Java-приложении (veracode/verademo, MIT)
Прогон 2026-10-01: Spring Boot, 52 файла (Java + JSP), авторская разметка заложенных уязвимостей (`docs/flaws/`, 14 классов) и настоящий результат Veracode Pipeline Scan (`docs/scan_results/results.json`, 225 находок).

| Заложенный класс (CWE) | Semgrep, реестровые правила | + наши `gaps*.yml` | Veracode |
|---|---|---|---|
| 89 SQL injection | ✔ | ✔ | ✔ |
| 73 Path traversal / имя файла | ✔ | ✔ | ✔ |
| 327 Слабая криптография | ✔ | ✔ | ✔ |
| 502 Небезопасная десериализация | ✔ | ✔ | ✔ |
| 78 Внедрение команд ОС | — | ✔ | ✔ |
| 80 XSS | — | ✔ | ✔ |
| 117 Log forging | — | ✔ | ✔ |
| 113 HTTP response splitting / CRLF | — | ✔ | ✔ |
| 470 Unsafe reflection | — | ✔ | ✔ |
| 601 Open redirect | — | ✔ | — |
| 134 Format string | — | ✔ | — |
| 200 Information exposure (через ошибки) | — | ✔ | — |
| 384 Session fixation | — | — | — |
| 501 Trust boundary violation | — | — | — |
| **Итого из 14** | **4** | **12** | **9** |

Что показал бенчмарк:
- **Реестровые правила Semgrep OSS пропустили самое очевидное** (внедрение команд `Runtime.exec(new String[]{"bash","-c","ping " + host})`, XSS, CRLF, reflection): уязвимости завязаны на Spring MVC. Мы добавили правила `rules/semgrep/gaps_java.yml`; на Verademo внедрение команд находится ровно на тех же строках, что у Veracode (`ToolsController.java:53, :83`), SQL injection — на всех 14 местах.
- **Пределы Semgrep OSS** (причины пропусков, не «слабость модели»): taint работает только внутри одного метода (источник в контроллере и `exec` во вспомогательном методе → нужно правило по приёмнику); типизированный шаблон `(Runtime $R)` не сопоставляется с цепочкой `Runtime.getRuntime().exec(...)` (нужна буквальная форма); неявная привязка параметров Spring без `@RequestParam` не считается источником (добавлена отдельно); `focus-metavariable` в списке sink'ов обязан быть внутри `patterns:`.
- **Не закрыто**: CWE-384 и CWE-501 — логические (вход после регистрации, переиспользование сессии); синтаксическими правилами не ловятся, нужен ручной разбор/чек-листы `sc-authentication.md`.
- **Veracode нашёл больше классов сверх разметки** (hardcoded credentials 798 ×28, resource leak 404, J2EE bad practices 245, insufficient entropy 331): часть из них наши правила не закрывают (404/245/798 в Java).
- Наши правила — эвристики: в Verademo они дают 45 срабатываний (в основном log forging и утечки через ошибки — WARNING); на безопасных эквивалентах (`tests/vuln_corpus_safe/`) — 0 ложных.

Воспроизведение: `git clone https://github.com/veracode/verademo`; `semgrep scan --config p/java --config p/security-audit --config p/owasp-top-ten --config p/command-injection --config p/sql-injection --config p/xss app` и `semgrep scan --config <скил>/rules/semgrep/gaps_java.yml app`; сверка с `docs/scan_results/results.json` — `scripts/ingest_external_report.py`.

## Что даёт бандл скила и что требует установки
- В скиле (тестируется): `csrf_template_lint.py`, `rules/semgrep/gaps.yml`, `ingest_external_report.py`.
- IaC/Dockerfile: KICS (Checkmarx) прогнан на `tests/iac_corpus/` (Dockerfile, Pod, Terraform) — 37 находок, из них 6 High/Critical (S3 ACL public-read, privileged-контейнер, root, SSH 0.0.0.0/0); Checkov/hadolint/Trivy config не прогонялись.
- Нужно ставить отдельно: Semgrep (правила реестра подтягиваются из сети, `--metrics=off`), bandit, gitleaks, Trivy. Без них класс переходит в ✗ — сообщайте «не проверено», а не PASS.
- Языки корпуса: Python, JavaScript, C, Java (Spring), Dockerfile, IaC, HTML-шаблоны. Java проверена ещё и на реальном приложении (бенчмарк выше). C#, PHP, Go, Ruby и др. **не проверялись**.
- Не проверялись: межфайловый taint, DAST (ZAP/Nuclei), SCA, секреты в истории.

## Как расширять
Новый пропущенный класс → файл-пример в `tests/vuln_corpus/` + безопасный эквивалент в `tests/vuln_corpus_safe/` + правило в `rules/semgrep/gaps.yml` + строка в `EXPECTED` в `tests/run_coverage_tests.py`. Тест должен падать при поломке правила и не срабатывать на безопасном примере.
