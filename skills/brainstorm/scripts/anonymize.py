#!/usr/bin/env python3
"""anonymize.py — слепая раздача меток кандидатам перед перекрестным ревью.

Делает три вещи:
  1) раздает метки C1..Cn в перемешанном (seeded) порядке, чтобы порядок авторства
     не выдавал победителя заранее;
  2) вырезает самоидентификацию модели (общие правила — blind_rules.py), которая
     выдает автора ревью;
  3) пишет карту соответствия с sha256, чтобы раскрытие меток можно было проверить.

Запуск:
  python anonymize.py --candidates candidates/ --out blinded/ --seed 42
  python anonymize.py --candidates candidates/ --out blinded/ --map-out .

Код возврата: 0 — карта собрана; 1 — нет кандидатов, коллизия имен или вход не читается.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

try:
    from blind_rules import strip_self_identification
except ImportError:  # запуск из другого каталога
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from blind_rules import strip_self_identification

CANDIDATE_SUFFIXES = (".md", ".txt")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def collect_candidates(directory: Path) -> list[Path]:
    """Кандидаты — только .md и .txt. Одинаковые имена без расширения — ошибка."""
    files = sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in CANDIDATE_SUFFIXES)
    stems: dict[str, str] = {}
    for path in files:
        if path.stem in stems:
            raise ValueError(
                f"коллизия имен кандидатов: {stems[path.stem]} и {path.name} "
                f"дают одну метку; переименуйте один из файлов"
            )
        stems[path.stem] = path.name
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anonymize.py",
        description="Слепая раздача меток кандидатам и очистка самоидентификации.",
    )
    parser.add_argument("--candidates", required=True, help="каталог с решениями авторов")
    parser.add_argument("--out", required=True, help="каталог для слепых копий")
    parser.add_argument("--map-out", help="куда положить label_map.json (по умолчанию каталог --out)")
    parser.add_argument("--seed", type=int, default=42, help="зерно перемешивания меток")
    args = parser.parse_args(argv)

    source_dir = Path(args.candidates)
    out_dir = Path(args.out)
    map_dir = Path(args.map_out) if args.map_out else out_dir
    if not source_dir.is_dir():
        print(f"anonymize: каталог кандидатов не найден: {source_dir}", file=sys.stderr)
        return 1
    try:
        candidates = collect_candidates(source_dir)
    except ValueError as exc:
        print(f"anonymize: {exc}", file=sys.stderr)
        return 1
    if not candidates:
        print(f"anonymize: в каталоге {source_dir} нет файлов-кандидатов (.md, .txt)", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    map_dir.mkdir(parents=True, exist_ok=True)
    slots = [path.stem for path in candidates]
    by_slot = dict(zip(slots, candidates))
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
        (out_dir / f"{label}.md").write_text(cleaned, encoding="utf-8", newline="\n")
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
    map_path = map_dir / "label_map.json"
    map_path.write_text(
        json.dumps(mapping, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(f"anonymize: {len(labels)} меток, перемешивание seed={args.seed}, "
          f"удалено строк с самоидентификацией: {removed_total}")
    print(f"anonymize: карта -> {map_path} (sha256 {label_map_sha256[:16]})")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
