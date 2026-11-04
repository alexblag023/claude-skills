#!/usr/bin/env python3
"""aggregate_votes.py — детерминированный подсчет голосов и правило итогового решения.

Считает рубрику, взвешенные голоса, pairwise-ранжирование, кворум и предлагает вердикт.
Никакой "оценки на глаз": все числа выведены из входного JSON, порядок кандидатов
разрешается детерминированно, результат воспроизводим при одинаковом входе.

Вход (JSON-файл или stdin при пути "-"):
  {
    "candidates":   [{"cid": "C1", "author_slot": "A1", "family": "qwen"}],
    "reviews":      [{"reviewer_slot": "R1", "reviewer_family": "qwen", "cid": "C1",
                     "ac_results": {"AC-1": "pass"},
                     "defects": [{"severity": "critical", "ac": "AC-1",
                                  "location": "app.py:12", "claim": "...",
                                  "evidence": "..."}],
                     "rubric": {"correctness": 3, "ac_coverage": 3,
                                "robustness": 2, "simplicity": 4,
                                "spec_adherence": 3},
                     "pairwise": [{"a": "C1", "b": "C2", "winner": "C1"}]}],
    "verification": [{"cid": "C1", "compile_ok": true, "lint_errors": 0,
                      "public_pass": 2, "public_total": 2, "hidden_pass": 8,
                      "hidden_total": 8, "ac_results": {"AC-2": "fail"}}],
    "reliability":  {"R1": {"pass": 3, "n": 5}},   # опционально: история вердиктов
    "config":       {"rubric_weights": {...}, "delta_tie": 0.05}
  }

Выход (JSON): method, excluded, scores, ranking, quorum, tie,
disagreement_flags, verdict_suggestion, dissent, warnings.

Код возврата: 0 — подсчет выполнен; 1 — некорректный вход;
с --strict: 1 при вердикте NO_CONSENSUS / REJECT_ALL / DEGRADED.

Запуск: python aggregate_votes.py input.json [--out out.json] [--strict]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Веса рубрики по умолчанию (шкала 0..4).
RUBRIC_WEIGHTS = {
    "correctness": 0.40,
    "ac_coverage": 0.25,
    "robustness": 0.15,
    "simplicity": 0.10,
    "spec_adherence": 0.10,
}
RUBRIC_KEYS = tuple(RUBRIC_WEIGHTS)

# Вес роли ревьюера: обычный критик — 1.0, судья эскалации — 1.2.
W_ROLE = {"critic": 1.0, "judge": 1.2, "escalation": 1.2}

# Доля rubric-score и pairwise в итоговой оценке S.
W_S_RUBRIC = 0.7
W_S_PAIRWISE = 0.3

# Ничья: разница итоговых оценок меньше этого порога.
DELTA_TIE = 0.05

# Максимальное отношение весов ревьюеров: ни одна модель не становится диктатором.
MAX_WEIGHT_RATIO = 2.0

VERDICTS = ("ACCEPT", "ACCEPT_WITH_NOTES", "NO_CONSENSUS", "REJECT_ALL", "DEGRADED")


class InputError(Exception):
    """Некорректный вход: скрипт обязан упасть с кодом 1, а не угадывать."""


def _require(payload, key, kind=None):
    if key not in payload:
        raise InputError(f"в входе нет поля {key!r}")
    value = payload[key]
    if kind is not None and not isinstance(value, kind):
        raise InputError(f"поле {key!r} имеет тип {type(value).__name__}, ожидался {kind}")
    return value


def defect_fingerprint(defect: dict) -> str:
    """Отпечаток дефекта: критерий + категория + нормализованное место.

    Нормализация места убирает номера строк и разделители, чтобы одинаковые находки
    разных ревьюеров совпали: "app.py:12" и "app.py:37" -> один и тот же отпечаток.
    """
    ac = str(defect.get("ac") or "")
    category = str(defect.get("severity") or "")
    location = str(defect.get("location") or "")
    norm = re.sub(r"\d+", "#", location.lower())
    norm = re.sub(r"[^a-zа-я0-9#]+", "_", norm).strip("_")
    raw = f"{ac}|{category}|{norm}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def is_critical(defect: dict) -> bool:
    return str(defect.get("severity") or "").strip().lower() == "critical"


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def reviewer_weight(review: dict, reliability: dict) -> tuple[float, float]:
    """Вес ревьюера: вес роли × сглаженная по Лапласу надёжность по истории.

    w_rel = (pass_count + 1) / (n + 2) — для новой модели даёт 0.5,
    что не даёт ни одной модели решающего веса "из воздуха".
    """
    role = str(review.get("role") or "critic").strip().lower()
    w_role = W_ROLE.get(role, 1.0)
    slot = str(review.get("reviewer_slot") or review.get("reviewer") or "")
    history = (reliability or {}).get(slot) or {}
    try:
        passed = float(history.get("pass", 0.0))
        total = float(history.get("n", 0.0))
    except (TypeError, ValueError):
        passed, total = 0.0, 0.0
    if total <= 0:
        w_rel = 0.5
    else:
        w_rel = (passed + 1.0) / (total + 2.0)
    return w_role * w_rel, w_rel


def cap_weights(weights: dict[str, float]) -> dict[str, float]:
    """Ограничивает отношение max/min: одна модель не должна решать всё."""
    if not weights:
        return {}
    values = list(weights.values())
    lo, hi = min(values), max(values)
    if lo <= 0:
        return {k: 1.0 for k in weights}
    if hi > MAX_WEIGHT_RATIO * lo:
        limit = MAX_WEIGHT_RATIO * lo
        return {k: min(v, limit) for k, v in weights.items()}
    return dict(weights)


def rubric_score(review: dict, weights: dict | None = None) -> float:
    """Оценка одного ревьюера по рубрике, нормализованная в 0..1.

    Веса берутся из конфигурации прогона: иначе кастомные веса влияли бы только на
    агрегированную оценку R, но не на взвешенную R_w, а в итоговую S входит именно R_w.
    """
    weights = weights or RUBRIC_WEIGHTS
    rubric = review.get("rubric") or {}
    total = 0.0
    for key, weight in weights.items():
        value = rubric.get(key)
        if not isinstance(value, (int, float)):
            continue
        value = max(0.0, min(4.0, float(value)))
        total += weight * value
    return total / 4.0


def failing_checks(verification: dict | None) -> list[str]:
    """Список непройденных проверок кандидата (пусто — все зеленые)."""
    if not verification:
        return []
    failed: list[str] = []
    if verification.get("compile_ok") is False:
        failed.append("compile")
    if (verification.get("lint_errors") or 0) > 0:
        failed.append("lint")
    hidden_total = verification.get("hidden_total")
    hidden_pass = verification.get("hidden_pass")
    if isinstance(hidden_total, int) and isinstance(hidden_pass, int) and hidden_pass < hidden_total:
        failed.append("hidden_tests")
    public_total = verification.get("public_total")
    public_pass = verification.get("public_pass")
    if isinstance(public_total, int) and isinstance(public_pass, int) and public_pass < public_total:
        failed.append("public_tests")
    for ac, status in (verification.get("ac_results") or {}).items():
        if str(status).strip().lower() == "fail":
            failed.append(f"ac:{ac}")
    return failed


def hard_gate(verification: dict | None) -> bool:
    """Ворота исполнения: компиляция, линтер и все проверяемые критерии зеленые."""
    if not verification:
        return False
    return not failing_checks(verification)


def prefilter(candidates, reviews, verification) -> list[dict]:
    """Исключает кандидатов с подтвержденным критическим дефектом.

    Порог: два независимых ревьюера с одним отпечатком дефекта, либо один ревьюер
    плюс провал соответствующей проверки исполнением. Одиночный неподтвержденный
    critical — это флаг для REPAIR, а не повод исключать кандидата.
    """
    by_cid: dict[str, list[dict]] = defaultdict(list)
    for review in reviews:
        by_cid[str(review.get("cid") or "")].append(review)
    vmap = {str(v.get("cid") or ""): v for v in verification}
    excluded: list[dict] = []
    for candidate in candidates:
        cid = str(candidate.get("cid") or "")
        crit_by_fp: dict[str, set] = defaultdict(set)
        for position, review in enumerate(by_cid.get(cid, [])):
            reviewer = str(review.get("reviewer_slot") or review.get("reviewer") or "")
            if not reviewer:
                # без слота ревьюера два отдельных отзыва все равно считаются
                # двумя независимыми свидетельствами, а не одним
                reviewer = f"__unlabelled_{position}"
            for defect in review.get("defects") or []:
                if is_critical(defect):
                    crit_by_fp[defect_fingerprint(defect)].add(reviewer)
        confirmed = sorted(fp for fp, who in crit_by_fp.items() if len(who) >= 2)
        if confirmed:
            excluded.append({
                "cid": cid,
                "reason": "критический дефект подтвержден двумя независимыми ревьюерами",
                "fingerprints": confirmed,
            })
            continue
        unconfirmed = sorted(fp for fp in crit_by_fp)
        if unconfirmed:
            failed = failing_checks(vmap.get(cid))
            if failed:
                excluded.append({
                    "cid": cid,
                    "reason": "критический дефект одного ревьюера плюс провал проверки",
                    "fingerprints": unconfirmed,
                    "failed_checks": failed,
                })
    return excluded


def supports(review: dict, cid: str, others: list[str]) -> bool:
    """Поддерживает ли ревьюер кандидата: нет critical, correctness >= 3, не beaten."""
    for defect in review.get("defects") or []:
        if is_critical(defect):
            return False
    rubric = review.get("rubric") or {}
    correctness = rubric.get("correctness")
    if not isinstance(correctness, (int, float)) or correctness < 3:
        return False
    for pair in review.get("pairwise") or []:
        a, b = str(pair.get("a") or ""), str(pair.get("b") or "")
        winner = str(pair.get("winner") or "")
        if cid not in (a, b):
            continue
        other = b if cid == a else a
        if other in others and winner == other:
            return False
    return True


def compute(payload: dict) -> dict:
    candidates = _require(payload, "candidates", list)
    reviews = _require(payload, "reviews", list)
    verification = payload.get("verification") or []
    reliability = payload.get("reliability") or {}
    config = payload.get("config") or {}
    if not isinstance(verification, list):
        raise InputError("поле verification должно быть списком")
    if not isinstance(reliability, dict):
        raise InputError("поле reliability должно быть объектом")
    if not isinstance(config, dict):
        raise InputError("поле config должно быть объектом")

    weights = dict(RUBRIC_WEIGHTS)
    custom = config.get("rubric_weights")
    if isinstance(custom, dict) and custom:
        for key, value in custom.items():
            if key not in weights:
                raise InputError(f"в rubric_weights неизвестный критерий {key!r}")
            if not isinstance(value, (int, float)) or value < 0:
                raise InputError(f"некорректный вес {key!r}")
        total = sum(float(v) for v in custom.values())
        if total <= 0:
            raise InputError("сумма rubric_weights должна быть больше нуля")
        weights = {k: float(custom.get(k, 0.0)) / total for k in weights}

    delta_tie = config.get("delta_tie", DELTA_TIE)
    if not isinstance(delta_tie, (int, float)) or delta_tie < 0:
        raise InputError("delta_tie должен быть неотрицательным числом")

    warnings: list[str] = []
    valid_candidates = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise InputError("элемент candidates должен быть объектом")
        cid = str(candidate.get("cid") or "")
        if not cid:
            raise InputError("у кандидата нет поля cid")
        if candidate.get("valid_format") is False:
            warnings.append(f"{cid}: формат ответа нарушен — кандидат исключен из подсчета")
            continue
        valid_candidates.append(candidate)

    excluded = prefilter(valid_candidates, reviews, verification)
    excluded_ids = {item["cid"] for item in excluded}
    alive = [c for c in valid_candidates if str(c.get("cid")) not in excluded_ids]

    by_cid: dict[str, list[dict]] = defaultdict(list)
    for review in reviews:
        cid = str(review.get("cid") or "")
        if cid:
            by_cid[cid].append(review)
    vmap = {str(v.get("cid") or ""): v for v in verification}

    # --- веса ревьюеров ---
    raw_weights: dict[str, float] = {}
    for review in reviews:
        slot = str(review.get("reviewer_slot") or review.get("reviewer") or "")
        if not slot or slot in raw_weights:
            continue
        weight, _ = reviewer_weight(review, reliability)
        raw_weights[slot] = weight
    capped = cap_weights(raw_weights)
    if capped != raw_weights:
        warnings.append("веса ревьюеров ограничены: отношение max/min не должно превышать 2")

    scores: dict[str, dict] = {}
    for candidate in alive:
        cid = str(candidate.get("cid"))
        own = by_cid.get(cid, [])
        if not own:
            warnings.append(f"{cid}: ни одного ревью — кандидат без оценки")
        per_criterion: dict[str, float] = {}
        for key in weights:
            values = []
            for review in own:
                value = (review.get("rubric") or {}).get(key)
                if isinstance(value, (int, float)):
                    values.append(max(0.0, min(4.0, float(value))))
            if not values:
                continue
            per_criterion[key] = median(values) if len(values) >= 3 else mean(values)
        missing = [k for k in weights if k not in per_criterion]
        if missing and own:
            warnings.append(f"{cid}: в рубрике нет критериев {missing} — они учтены как ноль")
        rubric_agg = sum(weights[k] * per_criterion.get(k, 0.0) for k in weights) / 4.0

        weighted_total = 0.0
        weight_sum = 0.0
        for review in own:
            slot = str(review.get("reviewer_slot") or review.get("reviewer") or "")
            weight = capped.get(slot, 1.0)
            weighted_total += weight * rubric_score(review, weights)
            weight_sum += weight
        rubric_weighted = (weighted_total / weight_sum) if weight_sum else 0.0

        correctness_values = [
            float((r.get("rubric") or {}).get("correctness"))
            for r in own
            if isinstance((r.get("rubric") or {}).get("correctness"), (int, float))
        ]
        spread = (max(correctness_values) - min(correctness_values)) if correctness_values else 0.0

        wins = 0.0
        losses = 0.0
        pairs = 0
        for review in own:
            slot = str(review.get("reviewer_slot") or review.get("reviewer") or "")
            weight = capped.get(slot, 1.0)
            for pair in review.get("pairwise") or []:
                a, b = str(pair.get("a") or ""), str(pair.get("b") or "")
                winner = str(pair.get("winner") or "")
                if cid not in (a, b):
                    continue
                if pair.get("consistent") is False:
                    continue
                pairs += 1
                if winner == cid:
                    wins += weight
                elif winner == (b if cid == a else a):
                    losses += weight
        if pairs:
            raw_p = (wins - losses) / pairs
            pairwise_score = max(0.0, min(1.0, (raw_p + 1.0) / 2.0))
        else:
            pairwise_score = 0.5

        final_score = W_S_RUBRIC * rubric_weighted + W_S_PAIRWISE * pairwise_score
        ver = vmap.get(cid)
        hidden_total = (ver or {}).get("hidden_total")
        hidden_pass = (ver or {}).get("hidden_pass")
        if isinstance(hidden_total, int) and hidden_total > 0 and isinstance(hidden_pass, int):
            hidden_ratio = hidden_pass / hidden_total
        else:
            hidden_ratio = 0.0
        scores[cid] = {
            "R": round(rubric_agg, 4),
            "R_w": round(rubric_weighted, 4),
            "P": round(pairwise_score, 4),
            "S": round(final_score, 4),
            "reviews": len(own),
            "rubric_aggregated": {k: round(v, 3) for k, v in per_criterion.items()},
            "correctness_spread": round(spread, 3),
            "hard_gate": hard_gate(ver),
            "hidden_ratio": round(hidden_ratio, 4),
            "failed_checks": failing_checks(ver),
            "family": candidate.get("family", ""),
            "author_slot": candidate.get("author_slot", ""),
        }

    # --- ранжирование: лексикографическое ---
    ranking = sorted(
        scores.items(),
        key=lambda item: (item[1]["hard_gate"], item[1]["hidden_ratio"], item[1]["S"], item[0]),
        reverse=True,
    )
    ranking_ids = [cid for cid, _ in ranking]

    # --- голосование по рубрике (для dissent) ---
    by_votes = sorted(scores.items(), key=lambda item: (item[1]["S"], item[0]), reverse=True)
    vote_winner = by_votes[0][0] if by_votes else ""

    # --- кворум ---
    n = len(alive)
    required = n // 2 + 1
    all_ids = [str(c.get("cid")) for c in alive]
    support_counts: dict[str, int] = {cid: 0 for cid in all_ids}
    supporters: dict[str, list[str]] = {cid: [] for cid in all_ids}
    for review in reviews:
        cid = str(review.get("cid") or "")
        if cid not in support_counts:
            continue
        others = [x for x in all_ids if x != cid]
        if supports(review, cid, others):
            slot = str(review.get("reviewer_slot") or review.get("reviewer") or "")
            if slot and slot not in supporters[cid]:
                supporters[cid].append(slot)
                support_counts[cid] += 1

    quorum_met = False
    support_for_winner = 0
    if ranking_ids:
        top = ranking_ids[0]
        support_for_winner = support_counts.get(top, 0)
        quorum_met = support_for_winner >= required

    tie = None
    if len(ranking_ids) >= 2:
        first, second = ranking_ids[0], ranking_ids[1]
        delta = abs(scores[first]["S"] - scores[second]["S"])
        same_hidden = scores[first]["hidden_ratio"] == scores[second]["hidden_ratio"]
        if delta < float(delta_tie) and same_hidden:
            tie = {
                "cids": [first, second],
                "delta_S": round(delta, 4),
                "delta_tie": float(delta_tie),
                "resolution": "эскалация к сильнейшей модели, не являющейся автором ни одного из двух",
            }

    disagreement_flags: list[dict] = []
    for cid, data in scores.items():
        if data["correctness_spread"] >= 2:
            disagreement_flags.append({
                "cid": cid,
                "kind": "correctness_spread",
                "spread": data["correctness_spread"],
                "note": "ревьюеры расходятся в оценке корректности на 2 и более балла",
            })
        if data["reviews"] < 2:
            disagreement_flags.append({
                "cid": cid,
                "kind": "few_reviews",
                "reviews": data["reviews"],
                "note": "кандидата ревьюировал меньше двух моделей",
            })

    dissent: list[dict] = []
    if vote_winner and ranking_ids and vote_winner != ranking_ids[0]:
        dissent.append({
            "kind": "votes_vs_execution",
            "vote_winner": vote_winner,
            "final_winner": ranking_ids[0],
            "note": "победитель по голосам не прошел проверку исполнением; исполнение важнее голосов",
        })

    # --- вердикт ---
    if not alive:
        verdict = "NO_CONSENSUS"
        warnings.append("не осталось кандидатов после исключений")
    elif len(alive) < 2:
        verdict = "DEGRADED"
        warnings.append("участников меньше двух: полноценное голосование невозможно")
    elif not any(scores[cid]["hard_gate"] for cid in scores):
        verdict = "REJECT_ALL"
    elif tie is not None:
        verdict = "NO_CONSENSUS"
        warnings.append("ничья не разрешена голосованием — нужна эскалация")
    elif not quorum_met:
        verdict = "NO_CONSENSUS"
        warnings.append(f"кворум не набран: {support_for_winner} из требуемых {required}")
    else:
        open_flags = [f for f in disagreement_flags if f["kind"] != "few_reviews"]
        unconfirmed_critical = []
        for cid in ranking_ids[:1]:
            for review in by_cid.get(cid, []):
                for defect in review.get("defects") or []:
                    if is_critical(defect):
                        unconfirmed_critical.append(cid)
        if open_flags or unconfirmed_critical:
            verdict = "ACCEPT_WITH_NOTES"
        else:
            verdict = "ACCEPT"

    return {
        "method": {
            "rubric_weights": {k: round(v, 4) for k, v in weights.items()},
            "S": f"{W_S_RUBRIC}*R_w + {W_S_PAIRWISE}*P",
            "quorum_required": required,
            "candidates_counted": len(alive),
        },
        "excluded": excluded,
        "scores": scores,
        "ranking": ranking_ids,
        "quorum": {
            "required": required,
            "support_for_winner": support_for_winner,
            "met": quorum_met,
            "supporters": supporters,
        },
        "tie": tie,
        "disagreement_flags": disagreement_flags,
        "verdict_suggestion": verdict,
        "dissent": dissent,
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aggregate_votes.py",
        description="Детерминированный подсчет голосов и предложение вердикта.",
    )
    parser.add_argument("input", help="путь к JSON со входом (или - для stdin)")
    parser.add_argument("--out", help="куда записать JSON (по умолчанию stdout)")
    parser.add_argument("--strict", action="store_true",
                        help="код 1 при вердикте NO_CONSENSUS/REJECT_ALL/DEGRADED")
    args = parser.parse_args(argv)

    try:
        if args.input == "-":
            raw = sys.stdin.read()
        else:
            raw = Path(args.input).read_text(encoding="utf-8")
        payload = json.loads(raw)
    except OSError as exc:
        print(f"aggregate_votes: не удалось прочитать вход: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"aggregate_votes: вход не является корректным JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("aggregate_votes: вход должен быть JSON-объектом", file=sys.stderr)
        return 1

    try:
        result = compute(payload)
    except InputError as exc:
        print(f"aggregate_votes: некорректный вход: {exc}", file=sys.stderr)
        return 1

    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        print(text)

    if args.strict and result["verdict_suggestion"] not in ("ACCEPT", "ACCEPT_WITH_NOTES"):
        return 1
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
