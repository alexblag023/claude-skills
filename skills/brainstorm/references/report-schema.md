# Артефакт прогона: `run.json`, отчет `report.md`, чек-лист качества

## 1. `run.json` — единый артефакт прогона

```json
{
  "schema_version": "1.0",
  "run_id": "2026-11-04T09-12-33Z-7f3a",
  "created_at": "2026-11-04T09:12:33Z",
  "task": {
    "title": "Выбрать схему хранения событий",
    "spec_path": "spec.md",
    "spec_sha256": "...",
    "context_path": "context.md",
    "context_sha256": "...",
    "acceptance_path": "acceptance.json",
    "ac_sha256": "...",
    "public_tests_path": "public_tests",
    "public_tests_sha256": "...",
    "hidden_tests_path": "hidden_tests",
    "hidden_tests_sha256": "...",
    "prompts_path": "prompts",
    "prompts_sha256": "...",
    "config_sha256": "...",
    "acceptance": [{"id": "AC-1", "text": "...", "check": "test"}]
  },
  "config": {
    "n_authors": 3,
    "max_crosscheck_rounds": 1,
    "max_repair_rounds": 2,
    "max_calls": 16,
    "delta_tie": 0.05,
    "rubric_weights": {"correctness": 0.4, "ac_coverage": 0.25, "robustness": 0.15,
                      "simplicity": 0.1, "spec_adherence": 0.1},
    "seed": 42,
    "allow_claude_by": null,
    "allow_paid_reason": null
  },
  "recon": {
    "skipped": false,
    "agents": [{"slot": "X1", "zone": "Карта кода", "model": "...", "family": "...",
                "facts": 12, "status": "ok"}],
    "zones": [{"name": "Карта кода", "closed": true},
              {"name": "Контракты", "closed": true}],
    "context_sha256": "..."
  },
  "roster": [
    {"slot": "A1", "role": "author", "provider": "...", "model": "...", "family": "...",
     "temperature": 0.2, "status": "ok", "replaced_by": null}
  ],
  "candidates": [
    {"cid": "C1", "author_slot": "A1", "origin": "diverge", "parent_cid": null,
     "sha256": "...", "path": "candidates/C1.md", "valid_format": true}
  ],
  "label_map_sha256": "...",
  "clusters": {
    "path": "clusters.json",
    "sha256": "...",
    "candidates": 3,
    "clusters": 3,
    "diversity_ratio": 1.0,
    "warnings": []
  },
  "reviews": [
    {"reviewer_slot": "R2", "reviewer_family": "...", "role": "critic", "cid": "C1",
     "ac_results": {"AC-1": "pass"},
     "defects": [{"severity": "major", "ac": "AC-1", "location": "app.py:12",
                  "claim": "...", "evidence": "..."}],
     "rubric": {"correctness": 3, "ac_coverage": 4, "robustness": 2,
                "simplicity": 3, "spec_adherence": 4},
     "pairwise": [{"a": "C1", "b": "C2", "winner": "C1", "consistent": true}]}
  ],
  "aggregation": {
    "method": "rubric-weighted+copeland",
    "excluded": [],
    "scores": {"C1": {"R": 0.71, "R_w": 0.73, "P": 0.8, "S": 0.75, "hard_gate": true,
                      "hidden_ratio": 1.0}},
    "quorum": {"required": 2, "support_for_winner": 2, "met": true},
    "ranking": ["C1", "C3", "C2"],
    "tie": null,
    "disagreement_flags": [],
    "verdict_suggestion": "ACCEPT",
    "dissent": []
  },
  "verification": [
    {"cid": "C1", "round": 0, "commands": ["pytest -q"], "compile_ok": true,
     "lint_errors": 0, "lint_warnings": 1, "public_pass": 2, "public_total": 2,
     "hidden_pass": 8, "hidden_total": 8, "exit_codes": [0],
     "log_path": "verification/C1.log", "log_sha256": "..."}
  ],
  "repairs": [
    {"cid": "C1", "round": 1, "status": "applied", "hidden_pass_before": 6,
     "hidden_pass_after": 8, "regression": false}
  ],
  "decision": {
    "verdict": "ACCEPT",
    "winner_cid": "C1",
    "winner_sha256": "...",
    "decided_by": "aggregate+verify",
    "decision_rule": "quorum",
    "vote_counts": {"C1": 2, "C3": 1},
    "tie_break_path": [],
    "escalated": false,
    "rationale": "...",
    "dissent": [],
    "open_risks": [],
    "override": null,
    "stop_reason": "quorum_met"
  },
  "integrity": {"freeze_ok": true, "rechecked_at": ["2026-11-04T09:41:02Z"],
                "test_dispute": false},
  "cost": {"calls": 11, "input_tokens": 214000, "output_tokens": 38000,
           "wall_seconds": 512}
  "warnings": []
}
```

## 2. `report.md` — отчет для человека

1. **Вердикт, победитель, одна фраза «почему».**
2. **Таблица кандидатов:** метка -> автор (после раскрытия карты), `R_w`, `P`, `S`,
   compile/lint, пройденные скрытые тесты.
3. **Решающие аргументы** и `dissent`: что оспаривает итог.
4. **`open_risks`**: что осталось непроверенным.
5. **История REPAIR**: что чинили, что стало зеленым, был ли откат.
6. **Отказы участников и замены:** кто, когда, по какой причине.
7. **Как применить и как откатить**: конкретные команды.
8. **Целостность:** `freeze_ok` и хэши.
9. **Стоимость:** вызовы, токены, время.
10. **Как это было решено против одиночного исполнителя** (метрика успеха, см.
    `references/voting.md`, п. 11).

Отчет пишется оркестратором по данным `run.json`, а не по памяти: числа копируются,
интерпретация добавляется.

## 3. Чек-лист качества

Проверяемый признак, а не пожелание. Пустой пункт = методика не сработала.

1. **Хэши заморозки сходятся** после прогона (`freeze_ok=true`).
2. **Картина задачи собрана и заморожена**: `context_sha256` сходится, каждая зона
   закрыта непустым разделом, либо разведка пропущена с причиной.
3. **Картина одинакова у всех участников**: никто не получил больше контекста, чем другой.
4. **Спека и критерии не менялись** после первого вызова: иначе весь прогон недействителен.
3. **Каждый кандидат имеет минимум 2 независимых ревью** (при N=3-4).
4. **Ни один ревьюер не ревьюил сам себя** и не ревьюил кандидат своего семейства.
5. **Порядок кандидатов в ревью перемешан**, а не в порядке авторства.
6. **Pairwise-сравнения проведены в обоих порядках**, несогласованные пары помечены как ничьи.
7. **Тесты кандидатов написаны до появления кандидатов** (по хэшу и времени).
8. **Sanity-проверка тестов пройдена**: на заглушке все тесты красные.
9. **У каждого ревьюера есть вес из истории**, а не назначенный вручную.
10. **Победитель по голосам прошел проверку исполнением** либо расхождение записано в `dissent`.
11. **Единогласие подтверждено внешним сигналом** (тест, источник, эталон); если нет — в отчете
    написано «консенсус без верификации».
12. **Ни один дефект не вычеркнут по мнению одного ревьюера** без независимого подтверждения.
13. **Разнообразие измерено**: доля уникальных кластеров идей и межсемейное сходство в отчете.
14. **Все отказы записаны**: таймауты, замены, исчерпание бюджета.
15. **Стоимость посчитана**: вызовы, токены, время.
16. **Есть сравнение с одиночным исполнителем** на той же задаче.
17. **Вердикт соответствует агрегации** либо переопределение объяснено в `override`.
18. **Отчет содержит способ отката.**

## 4. Пять типичных провалов методики

| Симптом | Как обнаружить | Что делать |
|---|---|---|
| **Все кандидаты почти одинаковы** | доля уникальных кластеров ниже 0.6; межсемейное сходство высокое | Сменить состав: другие семейства, разные линзы и запреты на входе; добавить явный список исключенных очевидных решений |
| **Победил не тот, кто прошел тесты** | `dissent` с `votes_vs_execution`; `hard_gate=false` у лидера голосов | Исполнение приоритетно: пересчитать ранжирование с `hard_gate` первым; проверить, не завышены ли веса ревьюеров |
| **Консенсус без внешнего сигнала** | кворум набран, но проверка исполнением невозможна | Пометить «консенсус без верификации»; добавить внешний источник или эталон; не повышать уверенность в отчете |
| **Штурм дороже одиночного исполнителя и не лучше** | метрика успеха: одиночный исполнитель выиграл | Сократить раунды, сузить задачу, заменить штурм best-of-k с проверкой; зафиксировать в памяти |
| **Инфраструктура штурма сломалась в середине** | статусы `timeout|error|invalid|replaced`, `integrity.freeze_ok=false` | Перезапустить с теми же входами (все хэши зафиксированы); если артефакты менялись — честно пометить прогон как недействительный |
