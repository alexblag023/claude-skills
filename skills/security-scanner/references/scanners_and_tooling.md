# Сканеры и инструменты: встроенное знание аудита

Этот справочник встроен в скилл, чтобы **не запускать отдельно** `/security-review` и разные внешние сканеры: их таксономия уязвимостей, сильные стороны и команды-пруфы собраны здесь. Эксперт-аудитор использует это как (а) чек-лист классов уязвимостей для ручной/семантической проверки кода и (б) набор команд, которыми получают объективный пруф `PASS/FAIL` (вывод сканера = доказательство).

> Пути к файлам скилла в промптах указываются **от корня скилла** `security-scanner/` (например `references/default_checklist.md`), а не относительно текущего файла.

---

## 1. Таксономия уязвимостей (вобрана из `/security-review` Anthropic + OWASP Top 10 2021 + CWE Top 25)

Скилл покрывает те же классы, что и `/security-review`, и шире; правила подавления шума частично отличаются намеренно (строгий гейт требует то, что `/security-review` исключает) — см. §10. Отдельно `/security-review` запускать не нужно. По каждому классу эксперт проверяет реальный код (grep/чтение пути данных), а не намерение.

**Классы (проверять все применимые):**
- **Инъекции:** SQL, command, LDAP, XPath, NoSQL, XXE.
- **XSS:** reflected, stored, DOM-based.
- **SSRF (server-side request forgery):** переход по пользовательскому URL в исходящий запрос сервера; блокер, если атакующий контролирует **host/protocol** (path-only SSRF — не блокер), доступ к internal/metadata-эндпоинтам. Механизм: allow-list доверенных хостов (см. Z1-10).
- **Path traversal:** `../`/абсолютные пути в операциях с ФС (чтение/запись/удаление по пользовательскому пути); канонизация + запрет `..` (см. Z1-10).
- **SSTI:** пользовательский ввод в шаблонизатор (Jinja2/Twig/Freemarker/EJS) без экранирования.
- **CSRF:** отсутствие anti-CSRF токена в state-changing формах/запросах (`<form method=post>`, `hx-post`, `fetch`) и/или `SameSite` у cookie-сессий (см. Z1-05). Loopback/«нет логина» — не исключение. Semgrep шаблоны не проверяет → `scripts/csrf_template_lint.py` (§9).
- **Аутентификация/авторизация:** сломанная аутентификация, повышение привилегий, IDOR, обход логики доступа, дефекты сессий.
- **JWT-уязвимости:** `alg:none`, слабый/захардкоженный secret, отсутствие проверки `exp`/`aud`/`iss`.
- **Mass assignment / BOPLA:** автобиндинг клиентского JSON в модель/ORM без allow-list полей (позволяет менять `role`/`isAdmin`).
- **Unrestricted file upload:** нет проверки типа/расширения/размера; путь сохранения из пользовательского ввода.
- **Раскрытие данных:** хардкод-секреты, логирование чувствительного/секретов, information disclosure, нарушение обработки ПДн.
- **Криптография:** слабые алгоритмы (MD5/SHA-1/DES/RC4/ECB), плохое управление ключами, небезопасный ГПСЧ (`Math.random` для токенов), **обход валидации TLS-сертификата** (`verify=False`, `rejectUnauthorized:false`).
- **Валидация ввода:** отсутствие/неправильная санитизация, переполнения.
- **Бизнес-логика:** гонки, TOCTOU, non-atomic read-modify-write.
- **Конфигурация:** небезопасные дефолты, отсутствие security-заголовков (CSP/HSTS/X-Frame-Options), слишком широкий CORS, clickjacking.
- **Цепочка поставки:** уязвимые зависимости, typosquatting/dependency confusion, немутабельность сборки (pinning).
- **Исполнение кода:** RCE через десериализацию, pickle-инъекция, eval-инъекция.
- **Insecure Design (OWASP A04):** отсутствие threat-model для фичи, критичная бизнес-операция без компенсирующего контроля (архитектурный пробел, не баг реализации).

**Что СОЗНАТЕЛЬНО не считаем блокером** (снижение ложных срабатываний, из официального `/security-review`). Понижаем до примечания, только если эксперт **зафиксировал конкретную причину отсутствия impact** (голое «низкий impact» без проверки — запрещено):
- DoS, rate-limiting, исчерпание памяти/CPU;
- «общая валидация ввода» без продемонстрированного воздействия; ReDoS/regex-инъекция без доказанного impact;
- open redirect, tabnabbing, XS-Leaks, prototype pollution — репортим только при высокой уверенности;
- path-only SSRF (атакующий не контролирует host/protocol);
- memory-safety находки в memory-safe языках (Go/Rust/Java с GC);
- секреты на диске, если иначе защищены (не в git, права ограничены); находки в документации (markdown);
- уязвимые зависимости — это ответственность SCA-слоя (Trivy/OSV, Z1/Z3), а не ручного код-ревью;
- файлы, которые только тесты или используются только при прогоне тестов (кроме реальных секретов в них — это блокер по Z1-07);
- значения из переменных окружения и CLI-флагов считаются доверенными: атака, требующая контроля над env/флагами, невалидна (не касается секретов, лежащих в env без защиты, и небезопасных дефолтов);
- UUID считаются неугадываемыми и не требуют валидации; попадание пользовательского текста в системный промпт ИИ — не уязвимость;
- command injection в shell-скриптах и уязвимости в `*.ipynb` — только при конкретном пути атаки для недоверенного ввода; логирование не-ПДн данных — не уязвимость (секреты и ПДн в логах — блокер);
- клиентская JS/TS-«авторизация» — не блокер (авторизация = ответственность сервера); React/Angular XSS — только при `dangerouslySetInnerHTML`/`bypassSecurityTrustHtml`.

**Метод (как в security-review):** анализ по diff (изменённые файлы + контекст), несколько узких проходов вместо одного общего («один на инъекции, один на доступ, один на секреты»), семантический разбор в контексте (не по сигнатурам), фильтрация по реальному impact (порог уверенности), находки — с `file:line` и severity.

---

## 2. Топ-инструменты по слоям (что запускать для пруфа)

Ни один сканер не покрывает всё — слои SAST / SCA / секреты / IaC / DAST ловят разное.

### SAST (статический анализ кода)
- **Semgrep** — практичный open-source, быстрый, свои правила. `semgrep --config=p/security-audit --config=p/owasp-top-ten .` (правила `ssrf`, `path-traversal`, `server-side-template-injection` входят в `p/security-audit`). SARIF: `--sarif -o semgrep.sarif`.
- **CodeQL** — глубокий семантический анализ, включая cross-file taint в пределах анализируемого репозитория/языка; движок GitHub code scanning, питает Copilot Autofix. Кастомные запросы на QL — дорого.
- **SonarQube (Community Build)** — бесплатный, качество+безопасность под единым quality gate; хорош для Java/большого legacy.
- **Коммерческие** (Snyk Code, Checkmarx One, Veracode, Fortify, Coverity) — обычно ниже FP-rate, удобнее enterprise-триаж, иногда cross-service/cross-repo taint и IDE-интеграция «на лету». Берём редко — когда открытый набор даёт неприемлемый уровень ложных срабатываний.

### SCA (зависимости / CVE) и контейнеры
- **Trivy** — доминирующий open-source: CVE по npm/PyPI/Maven/Go/Cargo/Composer/RubyGems/NuGet + образы + IaC + секреты. `trivy fs --scanners vuln .`, `trivy image <img>`. Численный CVSS: `trivy image --format json <img>` → `.Results[].Vulnerabilities[].CVSS.nvd.V3Score`. SARIF: `--format sarif -o trivy.sarif`.
- **OSV-Scanner** (Google) — `osv-scanner -r .` по lock-файлам.
- **Родные:** `npm ci` + `npm audit`, `pip-audit --require-hashes`, `govulncheck ./...`.
- **Dependabot / Renovate** — авто-PR на уязвимые зависимости и обновление pinned-версий.
- **Typosquatting / dependency confusion** (Trivy/OSV НЕ ловят): **OSSF Scorecard** `scorecard --repo=<repo>`, Socket.dev, private-registry scoping (`.npmrc` с явным `registry=`), ручной allow-list имён при code review.
- ⚠️ Open-source SCA (Trivy/OSV/Grype) **не делают reachability-анализ** (достижима ли уязвимая функция) — это моат коммерческих (Snyk/Mend). «Нет CVE в скане» ≠ «код не уязвим».

### Секреты
- **gitleaks** — `gitleaks detect --source . --redact` (`--source .` по умолчанию проходит **всю git-историю**, не только рабочее дерево). Pre-commit (иной режим!): `gitleaks protect --staged --redact` или хук в `.pre-commit-config.yaml` (repo `gitleaks/gitleaks`, hook `gitleaks`). Кастомные форматы токенов организации — обязательно `.gitleaks.toml` с org-правилами. SARIF: `--report-format sarif`.
- **TruffleHog** — верифицирует «живость» секрета. Рабочее дерево: `trufflehog filesystem . --only-verified`. **История (обязательно):** `trufflehog git file://. --only-verified`. Нативного SARIF нет — прикладывать JSON-артефакт CI, не полагаться на автозаливку в Security tab.
- **Секреты в образах/build-слоях:** `trivy image --scanners secret <img>` (+ `trivy fs --scanners secret .`) — gitleaks/trufflehog по рабочему дереву их не видят.
- **GitHub Secret Scanning + push protection** — Settings → Code security (требует GHAS для приватных репо). Если GHAS недоступен — компенсация: pre-commit + CI-гейт gitleaks/trufflehog на **всех** merge-путях (branch protection), не только на main.

### IaC / конфигурация / контейнеры
- **Checkov** — `checkov -d .` (Terraform/K8s/Docker/CloudFormation), SARIF `-o sarif`.
- **Trivy config** — `trivy config .` (misconfig IaC; отличать от `trivy fs --scanners vuln` — это SCA).
- **hadolint** — `hadolint Dockerfile` (best-practice lint, SARIF `-f sarif`).
- **kube-bench** — `kube-bench run --targets node,policies` (CIS Kubernetes Benchmark). **kube-linter** — `kube-linter lint ./k8s/`.
- **docker-bench-security** — `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security`.
- **CSPM (облачные аккаунты)** — Prowler `prowler aws`, ScoutSuite, Steampipe `steampipe check all` (public storage, permissive IAM, open security groups).
- **Проверяемые CIS-контролы** (маппить находку на пункт): privileged-контейнеры, `hostNetwork/hostPID/hostIPC`, drop capabilities, `allowPrivilegeEscalation:false`, PodSecurity `restricted`, read-only root FS, resource limits, default-deny `NetworkPolicy`.
- **TLS-конфигурация** — `testssl.sh --parallel <host>:443` или `sslyze --regular <host>:443` (гейт: TLS<1.2 или слабые шифры).
- **Браузерные расширения** — `web-ext lint` (манифест/permissions/CSP расширения).

### DAST (динамика, работающее приложение)
- **OWASP ZAP baseline (пассивный):** `zap-baseline.py -t <url>` — только заголовки/куки/пассив. **Полный/активный:** `zap-full-scan.py -t <url>` — инъекции/auth-bypass. ⚠️ baseline PASS ≠ пруф против инъекций/обхода auth — для них нужен active-скан или SAST; всегда указывай, какой скан прогнан.
- **Nuclei** — `nuclei -u <url> -t cves/,exposures/,misconfiguration/`.
- **Правило N/A:** DAST-требования помечаются `N/A` (с обоснованием), если объект не разворачивает HTTP(S)-эндпоинт (библиотека, CLI, batch-job, воркер без сети).

### Платформенные пакеты
- **GitHub Advanced Security (GHAS)** = CodeQL + Dependabot + secret scanning + push protection.
- **GitLab Ultimate** = встроенные SAST + DAST + dependency scanning + secret detection в CI.

---

## 3. Интеграция в GitHub Code Scanning (SARIF) — единая витрина

Любой сторонний сканер отдаёт **SARIF**, который заливается в GitHub, и все находки видны в **Security → Code scanning alerts** рядом с CodeQL.

**Default setup** — CodeQL в один клик (Settings → Code security → Code scanning → Default), без правки workflow.

**Advanced setup** — свой workflow (CodeQL для Python):
```yaml
permissions:
  actions: read
  contents: read
  security-events: write   # обязательно для загрузки результатов
steps:
  - uses: github/codeql-action/init@v4      # v3 depreciated к декабрю 2026 — используем v4
    with: { languages: 'python' }
  - uses: github/codeql-action/analyze@v4
    with: { category: "/language:python" }
```

**Сторонний сканер → SARIF → Security tab:**
```yaml
permissions: { security-events: write, actions: read, contents: read }
steps:
  - uses: actions/checkout@<full-sha>       # actions пинуем по SHA, не по тегу
  - run: semgrep --config=auto --sarif -o results.sarif || true
  - uses: github/codeql-action/upload-sarif@v4
    with: { sarif_file: results.sarif, category: semgrep }   # своя category на инструмент
```
Правила: `security-events: write` обязателен; `actions:read`+`contents:read` — для приватных репо; каждому инструменту — своя `category` (иначе результаты перезаписываются). До декабря 2026 v3 ещё работает, но GitHub рекомендует v4.

**GitLab:** `include: { template: Security/SAST.gitlab-ci.yml }` (+ `Dependency-Scanning`, `Secret-Detection`, `DAST`); отчёты — во вкладке Security & Compliance.

---

## 4. Карта «зона аудита → инструмент → команда-пруф»

| Зона | Класс проверки | Инструмент | Команда-пруф |
|---|---|---|---|
| **Z1** | Инъекции/XSS/RCE/крипто/логика | Semgrep, CodeQL | `semgrep --config=p/security-audit --config=p/owasp-top-ten .` |
| **Z1** | SSRF / path traversal / SSTI | Semgrep | те же конфиги (`p/security-audit` содержит правила) |
| **Z1** | CSRF в HTML/Jinja-шаблонах (+htmx) | `scripts/csrf_template_lint.py` | `python scripts/csrf_template_lint.py <корень>` → 0 находок (Semgrep это не ловит) |
| **Z1** | Clickjacking / CORS / заголовки | ZAP baseline | `zap-baseline.py -t <url>` (пассивная проверка заголовков) |
| **Z1** | TLS-конфигурация | testssl.sh/sslyze | `testssl.sh --parallel <host>:443` |
| **Z1/Z2** | Секреты в коде и истории | gitleaks + TruffleHog | `gitleaks detect --source . --redact` **и** `trufflehog git file://. --only-verified` (владелец пруфа — Z1-07; verified secret = инцидент, не гигиена) |
| **Z1/Z3** | Уязвимые зависимости (SCA) | Trivy, OSV, `*-audit` | `trivy fs --scanners vuln .` (PASS ≠ подтверждённая неэксплуатируемость — см. reachability, §2) |
| **Z1/Z3** | Секреты в образах/артефактах | Trivy | `trivy image --scanners secret <img>` |
| **Z1/Z3** | CI supply-chain / provenance | cosign, slsa-github-generator, Scorecard | `cosign verify --key cosign.pub <image>`; `scorecard --repo=<repo>` |
| **Z3** | Образы/контейнеры, IaC-харденинг | Trivy config, Checkov, hadolint | `trivy config .` / `checkov -d .` / `hadolint Dockerfile` |
| **Z3** | Kubernetes-харденинг (CIS) | kube-bench, kube-linter | `kube-bench run --targets node,policies` |
| **Z3** | Облачный аккаунт (IAM/storage/SG) | Prowler/ScoutSuite | `prowler aws --output-formats json` |
| **Z3** | Сроки устранения по CVSS | (из JSON-отчёта SCA) | численный `V3Score` → таблица CVSS зоны Z3; источник=регулятор ⇒ SLA критический |
| **Z1** (веб) | Инъекции/auth (динамика) | ZAP full/active, Nuclei | `zap-full-scan.py -t <url>` / `nuclei -u <url> -t cves/,misconfiguration/` |
| **Z4** | Аудит-логи, состав/защита/SIEM | ручной обзор + grep | grep точек логирования событий безопасности + проверка redaction секретов в логах |
| **Z5** | Утечка данных вовне (эксфильтрация) | grep/чтение + сеть | grep внешних `fetch/XHR/beacon`/хостов; проверка egress |

**Правило пруфа:** `PASS` по классу, для которого существует сканер, подтверждается **прогоном сканера с чистым/приемлемым выводом** (или наличием CI-гейта с этим сканером); `FAIL` — находкой сканера или найденным вручную дефектом с `file:line`. «Просто посмотрел» — невалидно (см. `verdict_schema.md`).

---

## 5. Минимальный CI-гейт (рекомендация в отчёт)
Когда всплывает «нет CI-гейта», предлагай near-zero-cost стек, каждый заливает SARIF в Security tab:
`Semgrep` (SAST) + `Trivy` (SCA/образы/IaC/секреты) + `gitleaks` (секреты + pre-commit) + `Checkov`/`hadolint` (IaC/Dockerfile) + `testssl.sh` (TLS для веб).

## 6. Целостность цепочки поставки и сборки (supply-chain integrity)
- **Lock-файлы обязательны и закоммичены** (`package-lock.json`/`poetry.lock`/`Cargo.lock`/`go.sum`); установка в CI строго `npm ci` / `pip install --require-hashes` / `cargo build --locked` / `go mod verify`, не `install` без хешей. Пруф: `git ls-files | grep -E 'package-lock|poetry.lock|Cargo.lock|go.sum'`.
- **GitHub Actions пинуются по полному commit SHA**, не по мутируемому тегу (`uses: actions/checkout@<sha>`); обновляет Dependabot/Renovate.
- **Docker базовые образы — по digest** (`FROM image@sha256:...`), не по тегу.
- **Provenance/подпись артефактов:** `cosign sign`/`cosign verify` образов, SLSA-attestation (`slsa-github-generator`) перед деплоем. Покрывает OWASP A08 (Software/Data Integrity Failures).

## 7. Расследование компрометации цепочки поставки (форензика) — опциональный deep-dive
Наш сканер по умолчанию работает **превентивно** (SCA/pinning/secret-scan). Если возник **признак компрометации** репозитория/зависимости (подозрительный коммит, force-push, аномальный релиз, dependency confusion), запускается расследование по evidence-first методу:
- **Триггеры:** «был ли репозиторий скомпрометирован», подозрительный коммит/мейнтейнер, force-push, IOC.
- **Метод (7 фаз):** парсинг цели+IOC → сбор из независимых источников (GitHub API, GitHub Archive/Events, Wayback, локальный `git fsck` для восстановления удалённых коммитов) → извлечение IOC → формирование гипотез → **валидация гипотез против первоисточников** → отчёт.
- **Дисциплина (совпадает с дисциплиной скилла):** каждый вывод цитирует evidence-ID; факт vs `[HYPOTHESIS]`; двойная проверка SHA/URL из ≥2 источников; **не запускать код из исследуемого репо** (только статически/в песочнице); редактировать найденные секреты в отчёте.
- **Сценарии:** dependency confusion (внешний пакет с версией выше внутренней), maintainer takeover (бэкдор в `.github/workflows` после простоя аккаунта), force-push для сокрытия утёкшего секрета (восстановление через `git fsck` + Archive).
- **Модуль встроен в скилл (полный порт из hermes oss-forensics):** `references/supply_chain_forensics/` — метод `forensics_SKILL.md` (7 фаз), CLI `scripts/evidence-store.py` (add/list/verify/query/export/summary), шаблоны отчётов `templates/`, справочники `references/` (evidence-types, github-archive-guide, recovery-techniques, investigation-templates). Запускается экспертом-форензиком (Эксперт 4 в `analysis_experts.md`).

Связь с зонами: питает Z1-14/Z3 (цепочка поставки), Z1-07 (утёкшие секреты), Z4 (реагирование на инцидент).

## 8. Вспомогательные инструменты (порт из hermes helpers)
- **API-тестирование (REST/GraphQL)** — `references/hermes_helpers/rest-graphql-debug/` — методика диагностики auth/authz/схем/repro; используется экспертом DAST для ручной проверки IDOR/BOLA/обхода auth на работающем API.
- **Пассивная разведка домена** — `references/hermes_helpers/domain-intel/scripts/domain_intel.py` (Python stdlib, без API-ключей): `subdomains`/`ssl`/`whois`/`dns` — инспекция SSL-сертификатов и внешнего периметра; питает Z3-06 (TLS) и DAST-эксперта. Пример: `python domain_intel.py ssl <host>`.

## 9. Слепые зоны и эмуляция внешнего (паттерн-) SAST
Критерий приёмки принимающей стороны — часто отчёт **её** SAST (коммерческого паттерн-сканера), а он работает по сигнатурам исходников/шаблонов и **не понимает серверные гварды**. Аудит, проверяющий «есть ли механизм-гарант», может честно поставить PASS там, где внешний сканер поставит High. Это пробел протокола, а не ошибка сканера: «PASS» обязан иметь **два слоя** — рантайм-гарантию И статически видимый след.

Типовой пример: веб-приложение (FastAPI + Jinja + htmx) с рабочим Origin/Sec-Fetch-Site middleware, подтверждённым DAST, но с `<form method="post" …>` и `hx-post` без токена в шаблонах — внешний SAST выдаёт серию High «CSRF (CWE-352)». Аудит пропустил их, потому что (1) «механизм есть» трактовался как PASS; (2) требование не предписывало токен в шаблоне; (3) Semgrep не анализирует HTML/Jinja на CSRF; (4) не было шага «смоделировать сигнатуры внешнего SAST» и инструмента для шаблонов. `scripts/csrf_template_lint.py` находит такие места до внешней экспертизы.

Что делать в каждом аудите веб-объекта (пруф каждого пункта — вывод команды):
- **CSRF в шаблонах:** `python scripts/csrf_template_lint.py <корень>` → 0. Починка: токен-middleware + `{{ csrf_token }}` в формах + `hx-headers` на `<body>` (для htmx) — и оставить Origin-гвард как второй слой.
- **Покрытие и пределы линтера** (регрессионные тесты: `python tests/run_csrf_lint_tests.py`, фикстуры `tests/csrf_fixtures/`): html/jinja/twig/ejs/hbs/blade/erb/php/cshtml, jsx/tsx/vue/svelte; хелперы токена Django/Flask-WTF/Laravel/Rails/ASP.NET; глобальный токен в `hx-headers` на `<body>` layout покрывает partial-шаблоны; для JS (`fetch`/axios/`$.post`/XHR) — только эвристика уровня файла; `*.min.js` пропускаются. Не видит: формы, собираемые строками в JS, и токен, который подставляет только серверный middleware без следа в разметке (это и есть цель проверки). Находка линтера = `FAIL` слоя SAST; регрессию линтера ловит CI репозитория скилла.
- **Принцип общий:** для каждого класса, где защита реализована «невидимо» (middleware, прокси, WAF, конфиг), задай вопрос: «увидит ли это сигнатурный сканер по исходнику?». Если нет — добавь видимый след (токен в разметке, явный декоратор `@csrf_protect`, явный `secure=True/httponly=True` в коде cookie, явный `autoescape=True`, явный `verify=True`) либо зафиксируй как `MANUAL`: «обосновать принимающей стороне/отклонить находку внешнего SAST с ссылкой на гвард» — не молча PASS.
- **Экспортированный отчёт внешнего SAST может быть отфильтрован** (например, только High из полного списка). Medium/Low того же скана нужно запрашивать отдельно — не считать «чисто».
- **Триаж принимающей стороны обычно окончателен:** отклонять находку аргументом «у нас есть middleware» нельзя; закрывается правкой шаблона.

## 10. Отличия от `/security-review` (сверено с его реальным текстом, 2026-09-30)
`/security-review` — PR-ревью: только дифф ветки к `origin/HEAD`, только новое, только read-only, порог уверенности ≥8/10, отчёт High/Medium. Наш скилл — гейт соответствия требованиям: весь объект, запуск сканеров с пруфами, все `FAIL` в план. Поэтому часть его исключений мы **сознательно не принимаем**, а часть перенесли (§1).

| Исключение `/security-review` | Наша позиция | Почему |
|---|---|---|
| Нет аудит-логов — не уязвимость | **Не принимаем** (Z4) | Гейт требует журналирование событий безопасности |
| Log spoofing / неэкранированный ввод в лог — не уязвимость | **Не принимаем** (Z4-03) | Требуется экранирование управляющих символов (`\n`, `\r`, `\t`) в логах |
| Отсутствие hardening не репортить | **Не принимаем** (Z3, Z1-12) | Харденинг и заголовки — предмет проверки |
| Rate limiting / DoS исключены | Частично: DoS и ресурсы — не блокер; защита входа от перебора (Z1-03) — обязательна | Лимит попыток аутентификации — базовая мера |
| Устаревшие зависимости не репортить | **Не принимаем** (слой SCA, Z3-01) | Критерий приёмки — отсутствие критических/высоких CVE |
| Находки в документации (`*.md`) не репортить | Принимаем для уязвимостей; документы Z6 (политики, ознакомление) проверяются как `MANUAL` | Документ не исполняется, но может быть обязателен |
| GitHub Actions: большинство не эксплуатируемо | Строже: пин по SHA, provenance (§6) | Цепочка поставки |
| Только новое (дифф) | Не принимаем: аудит всего объекта и истории | Гейт сдачи, а не ревью PR |
| Тесты, env/CLI, UUID, промпты ИИ, shell/ipynb, не-ПДн в логах | **Перенесено** (§1, «не блокер», с оговорками) | Снижает шум без потери требований |

**Чего нет у `/security-review`, а у нас есть:** CSRF (у него нет в списке категорий), SSRF как класс, mass assignment, загрузка файлов, CORS/заголовки/clickjacking, цепочка поставки, секреты в истории и образах, IaC, DAST, эмуляция внешнего SAST (§9), критерии приёмки и ранжирование.

**Что у него взято в идею, а не перенесено:** пороговая перепроверка. Обязательное правило: каждую находку слоя A (SAST/DAST) и каждый `FAIL` с severity High/Critical перед включением в план перепроверяет **отдельный субагент** («это реально эксплуатируемо? чем доказано: `file:line`, вывод сканера?»). Не подтверждённая пруфом находка → `MANUAL`/`N/A` с причиной, а не в блокеры. Это дополняет (не заменяет) независимые проверки зон.

---

## Источники
- Anthropic `/security-review` (реальные `prompts.py`, `.claude/commands/security-review.md`): [claude-code-security-review](https://github.com/anthropics/claude-code-security-review), [справка](https://support.claude.com/en/articles/11932705-automated-security-reviews-in-claude-code)
- GitHub Code Scanning: [christosgalano.github.io/github-code-scanning](https://christosgalano.github.io/github-code-scanning/), [загрузка SARIF](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github), депрекация CodeQL Action v3 (v4 с 2025-10)
- OWASP Top 10 2021, OWASP API Security Top 10 2023, CWE Top 25 2024
- Supply-chain форензика: hermes `optional-skills/security/oss-forensics` (evidence-first метод, вдохновлён RAPTOR OSS Forensics)
- Обзор сканеров 2026: [getastra](https://www.getastra.com/blog/security-audit/code-security-scan-tools/), [Cycode](https://cycode.com/blog/top-10-code-analysis-tools/), [Rafter](https://rafter.so/blog/vulnerability-scanning-tools-comparison)
