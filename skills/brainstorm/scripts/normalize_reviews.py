#!/usr/bin/env python3
"""normalize_reviews.py — приводит ответы ревьюеров к виду, который считает aggregate_votes.py.

Зачем: модели, которым показывают двух кандидатов, часто отвечают одной общей
рубрикой и одним сравнением. Такую рубрику нельзя приписать кандидату — это
выдумывание оценки, а не измерение. Скрипт либо разбирает ответ по кандидатам,
либо отказывает с понятным сообщением.

Вторая задача скрипта — проверить согласованность пары в коде. Модель не знает,
в каком порядке ей покажут кандидатов в следующий раз, поэтому поле consistent
заполняет не она, а оркестратор: тот же ревьюер отвечает на ту же пару в
обратном порядке, и если вердикт изменился — пара считается ничьей.

Запуск:
  python normalize_reviews.py --in order1.json --in order2.json \
      --reviewer-slot R1 --reviewer-family qwen [--role critic] \
      [--out reviews.json] [--notes-out notes.json]

Код возврата: 0 — отзывы по кандидатам готовы; 1 — ответ не разбирается или
рубрика не привязана к кандидату.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from validate_answers import extract_json
except ImportError:  # запуск из другого каталога
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from validate_answers import extract_json

# Порядок «хуже» для расхождения AC между порядками: fail хуже unknown, unknown хуже pass.
AC_RANK = {"pass": 0, "unknown": 1, "fail": 2}


class ReviewError(Exception):
    """Ответ ревьюера нельзя превратить в отзывы по кандидатам."""


def load_answer(path: Path) -> dict:
    """Читает ответ ревьюера и достает из него JSON-объект."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReviewError(f"{path.name}: не удалось прочитать файл: {exc}") from exc
    chunk = extract_json(text)
    if not chunk:
        raise ReviewError(f"{path.name}: в ответе нет корректного JSON-объекта")
    try:
        data = json.loads(chunk)
    except json.JSONDecodeError as exc:
        raise ReviewError(f"{path.name}: JSON не разбирается: {exc}") from exc
    if not isinstance(data, dict):
        raise ReviewError(f"{path.name}: ожидался JSON-объект")
    return data


def _clean_review(item: dict, source: str) -> dict:
    """Оставляет в отзыве только поля схемы и проверяет их типы."""
    cid = item.get("cid")
    if not isinstance(cid, str) or not cid.strip():
        raise ReviewError(f"{source}: у отзыва нет поля cid")
    rubric = item.get("rubric")
    if not isinstance(rubric, dict):
        raise ReviewError(f"{source}: у отзыва {cid} нет рубрики")
    ac_results = item.get("ac_results")
    if ac_results is None:
        ac_results = {}
    if not isinstance(ac_results, dict):
        raise ReviewError(f"{source}: ac_results отзыва {cid} должен быть объектом")
    defects = item.get("defects")
    if defects is None:
        defects = []
    if not isinstance(defects, list):
        raise ReviewError(f"{source}: defects отзыва {cid} должен быть списком")
    pairwise = item.get("pairwise")
    if pairwise is None:
        pairwise = []
    if not isinstance(pairwise, list):
        raise ReviewError(f"{source}: pairwise отзыва {cid} должен быть списком")
    return {
        "cid": cid.strip(),
        "ac_results": dict(ac_results),
        "defects": [d for d in defects if isinstance(d, dict)],
        "rubric": dict(rubric),
        "pairwise": [p for p in pairwise if isinstance(p, dict)],
    }


def candidate_reviews(data: dict, source: str) -> tuple[list[dict], list[dict]]:
    """Достает из ответа отзывы по кандидатам.

    Допустимы две формы:
      - {"reviews": [{"cid": ...}, ...], "pairwise": [...]} — разбор по кандидатам;
      - {"cid": ..., "rubric": ..., "pairwise": [...]} — один кандидат.
    Форма с общей рубрикой без привязки к кандидату отвергается: приписать одну
    оценку двум кандидатам — выдумывание оценки.
    """
    raw = data.get("reviews")
    if isinstance(raw, list):
        if not raw:
            raise ReviewError(f"{source}: пустой список reviews")
        out = []
        for item in raw:
            if not isinstance(item, dict):
                raise ReviewError(f"{source}: элемент reviews должен быть объектом")
            out.append(_clean_review(item, source))
        # Парные сравнения в этой форме лежат на верхнем уровне ответа:
        # они относятся к паре кандидатов, а не к одному отзыву.
        top = data.get("pairwise")
        if top is None:
            top = []
        if not isinstance(top, list):
            raise ReviewError(f"{source}: pairwise должен быть списком")
        return out, [pair for pair in top if isinstance(pair, dict)]
    if isinstance(data.get("cid"), str) and data["cid"].strip():
        return [_clean_review(data, source)], []
    if "rubric" in data:
        raise ReviewError(
            f"{source}: рубрика не привязана к кандидату — нужен разбор по кандидатам "
            f"(поле reviews с cid у каждого) либо один кандидат с полем cid")
    raise ReviewError(f"{source}: в ответе нет ни поля cid, ни списка reviews")


def pair_key(a: str, b: str) -> str:
    """Ключ пары, не зависящий от порядка показа."""
    return "|".join(sorted([a, b]))


def merge_pairs(answers: list[tuple[str, list[dict]]]) -> tuple[dict[str, dict], list[str]]:
    """Сводит вердикты по каждой паре из всех порядков одного ревьюера.

    Возвращает (pairs, notes). pairs: ключ пары -> {"a", "b", "winner", "consistent",
    "orders"}; consistent: True — обратный порядок подтвердил вердикт, False —
    вердикт изменился (пара — ничья), None — обратного порядка не было, предпочтение
    не засчитывается.
    """
    raw_pairs: dict[str, dict] = {}
    for source, reviews, top_pairs in answers:
        for pair in top_pairs:
            a = str(pair.get("a") or "").strip()
            b = str(pair.get("b") or "").strip()
            winner = str(pair.get("winner") or "").strip()
            if not a or not b or not winner:
                continue
            key = pair_key(a, b)
            info = raw_pairs.setdefault(key, {"a": a, "b": b, "winners": []})
            info["winners"].append((winner, source))
        for review in reviews:
            for pair in review["pairwise"]:
                a = str(pair.get("a") or "").strip()
                b = str(pair.get("b") or "").strip()
                winner = str(pair.get("winner") or "").strip()
                if not a or not b or not winner:
                    continue
                key = pair_key(a, b)
                info = raw_pairs.setdefault(key, {"a": a, "b": b, "winners": []})
                info["winners"].append((winner, source))
    pairs: dict[str, dict] = {}
    notes: list[str] = []
    for key, info in raw_pairs.items():
        winners = {winner for winner, _ in info["winners"]}
        orders = len(info["winners"])
        if len(winners) > 1:
            consistent = False
            notes.append(f"пара {info['a']}-{info['b']}: вердикт изменился при смене "
                         f"порядка — пара считается ничьей")
        elif orders < 2:
            consistent = None
            notes.append(f"пара {info['a']}-{info['b']}: обратный порядок не проверен — "
                         f"предпочтение не засчитывается")
        else:
            consistent = True
        pairs[key] = {
            "a": info["a"], "b": info["b"],
            "winner": info["winners"][0][0],
            "consistent": consistent, "orders": orders,
        }
    return pairs, notes


def _merge_rubric(values: list[dict]) -> dict:
    """Усредняет рубрику по порядкам: оценка не должна зависеть от порядка показа."""
    keys: set[str] = set()
    for value in values:
        keys.update(value)
    merged = {}
    for key in sorted(keys):
        numbers = []
        for value in values:
            item = value.get(key)
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                continue
            numbers.append(float(item))
        if numbers:
            merged[key] = round(sum(numbers) / len(numbers), 3)
    return merged


def _merge_ac(values: list[dict]) -> tuple[dict, list[str]]:
    """Сводит ac_results по порядкам; при расхождении берется худший статус."""
    merged: dict[str, str] = {}
    notes: list[str] = []
    keys: set[str] = set()
    for value in values:
        keys.update(value)
    for key in sorted(keys):
        statuses = [str(value.get(key) or "unknown").strip().lower() for value in values]
        if len(set(statuses)) == 1:
            merged[key] = statuses[0]
            continue
        worst = max(statuses, key=lambda s: AC_RANK.get(s, 1))
        merged[key] = worst
        notes.append(f"AC {key}: расхождение между порядками ({'/'.join(sorted(set(statuses)))}) "
                     f"— учтен худший статус")
    return merged, notes


def _defect_fingerprint(defect: dict) -> str:
    return "|".join(str(defect.get(key) or "") for key in ("severity", "ac", "location", "claim"))


def merge_reviews(reviews: list[dict], pairs: dict[str, dict]) -> tuple[list[dict], list[str]]:
    """Сводит отзывы одного ревьюера по кандидатам: по одному отзыву на кандидата.

    Порядок показа не должен влиять на оценку: рубрика усредняется, расхождение
    по критериям приемки трактуется как худший статус, дефекты объединяются.
    """
    notes: list[str] = []
    by_cid: dict[str, list[dict]] = {}
    for review in reviews:
        by_cid.setdefault(review["cid"], []).append(review)
    out = []
    for cid in sorted(by_cid):
        own = by_cid[cid]
        rubric = _merge_rubric([r["rubric"] for r in own])
        ac_results, ac_notes = _merge_ac([r["ac_results"] for r in own])
        notes.extend(f"{cid}: {note}" for note in ac_notes)
        defects = []
        seen = set()
        for review in own:
            for defect in review["defects"]:
                fingerprint = _defect_fingerprint(defect)
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                defects.append(defect)
        pairwise = []
        for key, info in pairs.items():
            if cid not in (info["a"], info["b"]):
                continue
            entry = {"a": info["a"], "b": info["b"], "winner": info["winner"]}
            if info["consistent"] is not None:
                entry["consistent"] = info["consistent"]
            pairwise.append(entry)
        out.append({
            "cid": cid, "ac_results": ac_results, "defects": defects,
            "rubric": rubric, "pairwise": pairwise,
        })
    return out, notes


def normalize(answers: list[tuple[str, dict]], reviewer_slot: str,
              reviewer_family: str, role: str) -> tuple[list[dict], list[str]]:
    """Разбирает ответы одного ревьюера и возвращает отзывы по кандидатам."""
    per_answer: list[tuple[str, list[dict], list[dict]]] = []
    for source, data in answers:
        reviews, top_pairs = candidate_reviews(data, source)
        per_answer.append((source, reviews, top_pairs))
    pairs, notes = merge_pairs(per_answer)
    merged, merge_notes = merge_reviews(
        [review for _source, reviews, _top in per_answer for review in reviews], pairs)
    notes.extend(merge_notes)
    for review in merged:
        review["reviewer_slot"] = reviewer_slot
        review["reviewer_family"] = reviewer_family
        review["role"] = role
    return merged, notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="normalize_reviews.py",
        description="Нормализация ответов ревьюеров и проверка согласованности пар.",
    )
    parser.add_argument("--in", dest="inputs", action="append", required=True,
                        help="файл с ответом ревьюера (можно указать несколько: "
                             "разные порядки одной пары)")
    parser.add_argument("--reviewer-slot", required=True, help="слот ревьюера")
    parser.add_argument("--reviewer-family", required=True, help="семейство модели ревьюера")
    parser.add_argument("--role", default="critic", help="роль ревьюера (critic/judge)")
    parser.add_argument("--out", help="куда записать отзывы (по умолчанию — stdout)")
    parser.add_argument("--notes-out", help="куда записать замечания о согласованности")
    args = parser.parse_args(argv)

    answers = []
    for item in args.inputs:
        path = Path(item)
        answers.append((path.name, load_answer(path)))
    try:
        reviews, notes = normalize(answers, args.reviewer_slot,
                                   args.reviewer_family, args.role)
    except ReviewError as exc:
        print(f"normalize_reviews: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(reviews, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8", newline="\n")
    else:
        print(payload)
    if args.notes_out:
        Path(args.notes_out).write_text(json.dumps(notes, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8", newline="\n")
    for note in notes:
        print(f"normalize_reviews: {note}", file=sys.stderr)
    print(f"normalize_reviews: отзывов — {len(reviews)}, пар — "
          f"{sum(len(r['pairwise']) for r in reviews) // 2}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
