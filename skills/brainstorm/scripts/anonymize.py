#!/usr/bin/env python3
"""anonymize.py — слепая раздача меток кандидатам перед перекрестным ревью.

Делает три вещи:
  1) раздает метки C1..Cn в перемешанном (seeded) порядке, чтобы порядок авторства
     не выдавал победителя заранее;
  2) вырезает самоидентификацию модели (имя, "как языковая модель"), которая выдает
     автора ревью;
  3) пишет карту соответствия с sha256, чтобы раскрытие меток можно было проверить.

Запуск:
  python anonymize.py --candidates candidates/ --out blinded/ --seed 42

Код возврата: 0 — карта собрана; 1 — нет кандидатов или вход не читается.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

# Строки, которые выдают модель. Удаляются целиком: в ревью важен аргумент, а не подпись.
SELF_ID_PATTERNS = [
    r"^\s*(?:as an ai|i am an ai|i am (?:a )?(?:large language model|llm|assistant))\b.*$",
    r"^\s*(?:my model|i was trained by|i am (?:gpt|claude|gemini|qwen|llama|mistral)\b).*$",
    r"^\s*(?:как языковая модель|как ИИ|я — (?:gpt|claude|gemini|qwen|llama|mistral|ии))\b.*$",
    r"^\s*\(?(?:model|модель):?\s*(?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi)\b.*$",
]

SELF_ID_RE = re.compile("|".join(SELF_ID_PATTERNS), re.IGNORECASE | re.MULTILINE)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_self_identification(text: str) -> tuple[str, int]:
    """Убирает строки с самоидентификацией. Возвращает текст и число удаленных строк."""
    cleaned = SELF_ID_RE.sub("[идентификация удалена]", text)
    removed = len(SELF_ID_RE.findall(text))
    return cleaned, removed


def collect_candidates(directory: Path) -> list[Path]:
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in (".md", ".txt", ".json"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anonymize.py",
        description="Слепая раздача меток кандидатам и очистка самоидентификации.",
    )
    parser.add_argument("--candidates", required=True, help="каталог с решениями авторов")
    parser.add_argument("--out", required=True, help="каталог для слепых копий и карты")
    parser.add_argument("--seed", type=int, default=42, help="зерно перемешивания меток")
    args = parser.parse_args(argv)

    source_dir = Path(args.candidates)
    out_dir = Path(args.out)
    if not source_dir.is_dir():
        print(f"anonymize: каталог кандидатов не найден: {source_dir}", file=sys.stderr)
        return 1
    candidates = collect_candidates(source_dir)
    if not candidates:
        print(f"anonymize: в каталоге {source_dir} нет файлов-кандидатов", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    by_slot: dict[str, Path] = {}
    for candidate in candidates:
        by_slot.setdefault(candidate.stem, candidate)
    slots = list(by_slot)
    order = list(slots)
    random.Random(args.seed).shuffle(order)

    labels = []
    removed_total = 0
    for index, slot in enumerate(order, start=1):
        label = f"C{index}"
        source_path = by_slot[slot]
        try:
            text = source_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"anonymize: не удалось прочитать {source_path}: {exc}", file=sys.stderr)
            return 1
        cleaned, removed = strip_self_identification(text)
        removed_total += removed
        blinded_path = out_dir / f"{label}.md"
        blinded_path.write_text(cleaned, encoding="utf-8", newline="\n")
        labels.append({
            "label": label,
            "slot": slot,
            "source_file": source_path.name,
            "source_sha256": sha256_text(text),
            "blinded_sha256": sha256_text(cleaned),
            "stripped_lines": removed,
        })

    canonical = json.dumps(labels, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    label_map_sha256 = sha256_text(canonical)
    mapping = {
        "schema_version": "1.0",
        "seed": args.seed,
        "source_dir": source_dir.name,
        "labels": labels,
        "label_map_sha256": label_map_sha256,
    }
    (out_dir / "label_map.json").write_text(
        json.dumps(mapping, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"anonymize: {len(labels)} меток, перемешивание seed={args.seed}, "
          f"удалено строк с самоидентификацией: {removed_total}")
    map_path = out_dir / "label_map.json"
    print(f"anonymize: карта -> {map_path} (sha256 {label_map_sha256[:16]})")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
