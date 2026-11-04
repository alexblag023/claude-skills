#!/usr/bin/env python3
"""dedup_ideas.py — кластеризация идей и измерение разнообразия.

Детектор ловушки "гомогенизация": если все модели выдали почти одно и то же, штурм
вырождается в одно мнение. Скрипт меряет долю уникальных кластеров и сравнивает
межсемейное сходение с внутрисемейным.

Запуск:
  python dedup_ideas.py --candidates candidates/ --out clusters.json [--threshold 0.55]

Код возврата: 0 — разнообразие в норме; 1 — разнообразие ниже порога (гомогенизация)
или вход не читается.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from difflib import SequenceMatcher
from pathlib import Path

DEFAULT_THRESHOLD = 0.55
DEFAULT_MIN_DIVERSITY = 0.6


def normalize(text: str) -> list[str]:
    """Нормализованные токены: нижний регистр, без пунктуации, без коротких слов."""
    words = re.findall(r"[\w\-]+", text.lower(), re.UNICODE)
    return [w for w in words if len(w) > 2]


def shingles(tokens: list[str], size: int = 3) -> set[str]:
    """Набор n-грамм: устойчивая к перестановкам и к опечаткам в словах."""
    if len(tokens) < size:
        return {" ".join(tokens)} if tokens else set()
    return {" ".join(tokens[i:i + size]) for i in range(len(tokens) - size + 1)}


def jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    union = len(left | right)
    return intersection / union if union else 0.0


def similarity(left: dict, right: dict) -> float:
    """Сходство двух идей: 0.6 на 3-граммах тела + 0.4 на сходстве заголовков."""
    body = jaccard(left["shingles"], right["shingles"])
    title = SequenceMatcher(None, left["title"], right["title"]).ratio()
    return round(0.6 * body + 0.4 * title, 4)


def parse_candidate(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    title = ""
    body = text
    for line in lines:
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            break
    if not title and lines:
        title = lines[0][:120]
    tokens = normalize(title + " " + body)
    return {
        "file": path.name,
        "slot": path.stem,
        "title": title,
        "tokens": tokens,
        "shingles": shingles(tokens),
    }


class Union:
    """Простой find/union: объединение кандидатов в кластеры."""

    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            self.parent[max(a, b)] = min(a, b)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dedup_ideas.py",
        description="Кластеризация идей кандидатов и мера разнообразия.",
    )
    parser.add_argument("--candidates", required=True, help="каталог с решениями")
    parser.add_argument("--out", help="файл с результатом (по умолчанию stdout)")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help="порог сходства для объединения в кластер")
    parser.add_argument("--min-diversity", type=float, default=DEFAULT_MIN_DIVERSITY,
                        help="минимальная доля уникальных кластеров")
    args = parser.parse_args(argv)

    source_dir = Path(args.candidates)
    if not source_dir.is_dir():
        print(f"dedup_ideas: каталог кандидатов не найден: {source_dir}", file=sys.stderr)
        return 1
    paths = sorted(p for p in source_dir.iterdir() if p.is_file() and p.suffix in (".md", ".txt"))
    if not paths:
        print(f"dedup_ideas: в каталоге {source_dir} нет файлов-кандидатов", file=sys.stderr)
        return 1

    candidates = []
    for path in paths:
        try:
            candidates.append(parse_candidate(path))
        except (OSError, UnicodeDecodeError) as exc:
            print(f"dedup_ideas: не удалось прочитать {path}: {exc}", file=sys.stderr)
            return 1

    union = Union(len(candidates))
    pairs = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            score = similarity(candidates[i], candidates[j])
            pairs.append((score, i, j))
            if score >= args.threshold:
                union.union(i, j)
    pairs.sort(reverse=True)

    groups: dict[int, list[int]] = {}
    for index in range(len(candidates)):
        groups.setdefault(union.find(index), []).append(index)

    clusters = []
    for number, (_, members) in enumerate(sorted(groups.items(), key=lambda kv: min(kv[1])), start=1):
        leader = min(members)
        entries = []
        for member in members:
            candidate = candidates[member]
            entries.append({
                "file": candidate["file"],
                "slot": candidate["slot"],
                "title": candidate["title"],
                "similarity_to_leader": similarity(candidate, candidates[leader]),
            })
        clusters.append({"cluster": f"K{number}", "members": entries})

    total = len(candidates)
    unique = len(clusters)
    diversity = unique / total if total else 0.0
    warnings = []
    if total >= 2 and diversity < args.min_diversity:
        warnings.append(
            f"гомогенизация: {unique} уникальных кластеров на {total} кандидатов "
            f"({diversity:.2f} < {args.min_diversity}) — смените состав или линзы авторов",
        )
    near = [
        {"a": candidates[i]["file"], "b": candidates[j]["file"], "score": score}
        for score, i, j in pairs[:5]
        if score > 0
    ]
    result = {
        "schema_version": "1.0",
        "threshold": args.threshold,
        "candidates": total,
        "clusters": unique,
        "diversity_ratio": round(diversity, 4),
        "min_diversity": args.min_diversity,
        "cluster_list": clusters,
        "closest_pairs": near,
        "warnings": warnings,
    }
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8", newline="\n")
    else:
        print(text)
    for warning in warnings:
        print(f"dedup_ideas: {warning}", file=sys.stderr)
    return 1 if warnings else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
