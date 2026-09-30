# Модуль: Форензика компрометации цепочки поставки (порт из hermes oss-forensics)

Полный порт метода расследования supply-chain-компрометации GitHub-репозиториев (7 фаз, мульти-агент). Вобран в `security-scanner` как опциональный **deep-dive**: запускается, когда есть признак компрометации (подозрительный коммит/мейнтейнер, force-push, аномальный релиз, dependency confusion, утёкший секрет). Источник метода: hermes `optional-skills/security/oss-forensics` (вдохновлён RAPTOR OSS Forensics). Ассеты рядом: `scripts/evidence-store.py`, `templates/`, `references/`.

**Адаптация под этот скилл:**
- `MODULE_DIR` = `references/supply_chain_forensics/` (в оригинале `SKILL_DIR`).
- Инструменты: делегирование расследователей → **субагенты Agent** (параллельно, ≤3–5); `execute_code` → **Bash/Python**; `web_extract` → **WebFetch**; `terminal` → **Bash**.
- Вердикт форензики питает зоны **Z1-14/Z3** (цепочка поставки), **Z1-07** (утёкшие секреты), **Z4** (реагирование на инцидент); находки идут в общий отчёт об уязвимостях (дедуп по Шагу 3 SKILL.md).
- Совместимо с пруф-подходом скилла: evidence-first + факт vs `[HYPOTHESIS]`.

---

## ⚠️ Анти-галлюцинация (гварды — читать перед каждым шагом)
1. **Evidence-First:** каждое утверждение в отчёте/гипотезе цитирует ≥1 evidence-ID (`EV-XXXX`). Без цитаты — запрещено.
2. **Строго одна зона источника:** каждый расследователь-субагент работает с ОДНИМ источником данных (не смешивать GH Archive и GitHub API и т.д.).
3. **Факт vs гипотеза:** все невыверенные выводы помечать `[HYPOTHESIS]`; фактом — только подтверждённое против первоисточника.
4. **Без фабрикации:** валидатор механически проверяет, что каждый цитируемый EV-ID реально есть в evidence-store.
5. **Опровержение требует доказательства:** «нет доказательств» не опровергает гипотезу, лишь делает её inconclusive.
6. **Двойная проверка SHA/URL:** любой SHA/URL/идентификатор как evidence подтверждается из ≥2 независимых источников.
7. **НЕ запускать код из исследуемого репозитория** локально — только статический анализ или изолированная песочница.
8. **Редакция секретов:** найденные ключи/токены/креды в отчёте — `[REDACTED]` (лог — только внутренне).

## Сценарии
- **Dependency confusion:** вредоносный `internal-lib-v2` в публичном реестре с версией выше внутренней; отследить первое появление и PushEvents, обновившие `package.json`.
- **Maintainer takeover:** аккаунт давнего контрибьютора пушит бэкдор в `.github/workflows/*` (после простоя / с нового IP).
- **Force-push hide:** секрет закоммичен и затёрт force-push; восстановить исходный SHA через `git fsck` + GH Archive, проверить что утекло.

---

## Фаза 0 — Инициализация
```bash
mkdir investigation_$(echo "OWNER_REPO" | tr '/' '_') && cd $_
python3 MODULE_DIR/scripts/evidence-store.py --store evidence.json list
cp MODULE_DIR/templates/forensic-report.md ./investigation-report.md
: > iocs.md   # трекер индикаторов компрометации
```
Зафиксируй время старта, целевой репозиторий, цель расследования.

## Фаза 1 — Парсинг цели и извлечение IOC
Извлеки из запроса: целевой `owner/repo`; акторов (GitHub-хэндлы, email); окно времени; заданные IOC (SHA коммитов, пути файлов, имена пакетов, IP, домены, ключи/токены, вредоносные URL); ссылки на отчёты вендоров. Занеси в `iocs.md`: {тип из EV-таксономии, значение, источник}. Таксономия — `references/evidence-types.md`.

## Фаза 2 — Параллельный сбор доказательств (до 5 субагентов, ≤3 одновременно)
Запусти расследователей **субагентами Agent**, каждому — только его источник (жёсткая граница роли), передай IOC и окно времени. Каждый добавляет находки: `python3 MODULE_DIR/scripts/evidence-store.py add ...`.

- **Расследователь 1 — Local Git** (только локальный git): `git clone`, затем `git log --all --full-history --stat`, `git fsck --lost-found --unreachable` (dangling-коммиты = следы force-push), `git reflog --all`, `git branch -a -v`, поиск подозрительных бинарников (`--diff-filter=A -- '*.so' '*.dll' '*.exe'`), `git log --show-signature` (аномалии GPG). Восстановление force-pushed — `references/recovery-techniques.md`.
- **Расследователь 2 — GitHub API** (только REST API): commits/pulls(state=all)/issues/contributors/events/releases; `git/commits/SHA` (force-pushed могут 404 на `commits/` но жить на `git/commits/`). Кросс-сверка: PR в архиве, но нет в API → удаление; коммит в архиве PushEvents, но нет в API → force-push/удаление.
- **Расследователь 3 — Wayback Machine** (только CDX API): восстановление удалённых страниц (README/issues/PR/releases/wiki) через `web.archive.org/cdx/search/cdx?url=github.com/OWNER/REPO...`. Параметры — `references/github-archive-guide.md`.
- **Расследователь 4 — GH Archive/BigQuery** (только BigQuery; при отсутствии Google Cloud — пропустить и отметить в отчёте): `--dry_run` ОБЯЗАТЕЛЕН перед каждым запросом; фильтр `_TABLE_SUFFIX`; детект force-push (`payload.size>0 AND payload.distinct_size=0`), DeleteEvent, WorkflowRunEvent. 12 типов событий — `references/github-archive-guide.md`.
- **Расследователь 5 — Обогащение IOC** (пассивные публичные источники; НЕ запускать код репо): восстановление коммитов через `.../commit/SHA.patch`; passive DNS/WHOIS через WebFetch; проверка пакетов в npm/PyPI на репорты о вредоносности; профиль/возраст аккаунта актора.

## Фаза 3 — Консолидация доказательств
`evidence-store.py list`; для каждого — сверь `content_sha256` с оригиналом; сгруппируй по времени/актору/IOC; выяви расхождения источников (индикаторы удаления); помечай `[VERIFIED]` (≥2 источника) / `[UNVERIFIED]`.

## Фаза 4 — Формирование гипотез
Гипотеза: конкретное утверждение + ≥2 цитируемых EV-ID + что её опровергло бы + метка `[HYPOTHESIS]`. Шаблоны (maintainer compromise / dependency confusion / CI-CD injection / typosquatting / credential leak) — `references/investigation-templates.md`. По каждой гипотезе — субагент на поиск ОПРОВЕРГАЮЩИХ доказательств.

## Фаза 5 — Валидация гипотез
Валидатор механически: извлекает все цитируемые EV-ID → проверяет существование каждого в `evidence.json` (нет ID → REJECTED как возможная фабрикация) → проверяет `[VERIFIED]` (≥2 источника) → логическую согласованность таймлайна → альтернативные (benign) объяснения. Итог: `VALIDATED` / `INCONCLUSIVE` / `REJECTED`. Отклонённые → назад в Фазу 4 (≤3 итераций).

## Фаза 6 — Итоговый отчёт
Заполни `investigation-report.md` (шаблон `templates/forensic-report.md`): Executive Summary (вердикт Compromised/Clean/Inconclusive + уровень уверенности High/Medium/Low); Timeline с цитатами; валидированные гипотезы; реестр EV-XXXX; список IOC; chain of custody; рекомендации. Каждое фактическое утверждение — с `[EV-XXXX]`; секреты — `[REDACTED]`.

## Фаза 7 — Завершение
Финальный `evidence-store.py list`; заархивировать директорию расследования. Если компрометация подтверждена: немедленные меры (ротация кредов, пиновка хешей зависимостей, уведомление затронутых), затронутые версии/пакеты, обязательства по раскрытию (координация с реестром пакетов). Представь `investigation-report.md`.

---

## Этика и лимиты
Только **защитная** security-форензика. Запрещено: харассмент/сталкинг/доксинг контрибьюторов, расследование чужих проприетарных репозиториев без авторизации, публикация обвинений без валидированных доказательств. Принцип минимальной интрузии; при реальной компрометации — координированное раскрытие (сначала мейнтейнерам приватно, затем реестрам, при необходимости — CVE).

## Rate limiting
GitHub API: аутентифицированно 5000/ч (`GITHUB_TOKEN`/`gh`), без auth 60/ч (непригодно). Пагинацию — последовательно; следить за `X-RateLimit-Remaining`. BigQuery — всегда `--dry_run`. Wayback CDX — 1–2 req/sec.

## Ассеты модуля
- `scripts/evidence-store.py` — CLI управления JSON-хранилищем доказательств (add/list/verify).
- `templates/forensic-report.md`, `templates/malicious-package-report.md` — шаблоны отчётов.
- `references/evidence-types.md` — таксономия IOC/типов доказательств.
- `references/github-archive-guide.md` — BigQuery/CDX, 12 типов событий.
- `references/recovery-techniques.md` — восстановление удалённых коммитов/PR/issues.
- `references/investigation-templates.md` — шаблоны гипотез по типам атак.
