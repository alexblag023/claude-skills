#!/usr/bin/env python3
"""check_run.py — проверка целостности прогона перед выдачей отчета.

Проверяет то, что нельзя проверить "на глаз": не менялись ли замороженные входы,
слепое ли было ревью, не ревьюил ли кто сам себя, согласован ли вердикт с агрегацией.

Запуск:
  python check_run.py runs/2026-11-04T09-12-33Z-7f3a

Код возврата: 0 — нарушений нет; 1 — есть ошибки (warnings не влияют на код).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from blind_rules import find_self_identification
except ImportError:  # запуск из другого каталога
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from blind_rules import find_self_identification


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_canonical(data) -> str:
    return sha256_text(json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def sha256_tree(directory: Path) -> str:
    """Хэш дерева каталога: отсортированные относительные пути и хэши файлов."""
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        lines.append(f"{path.relative_to(directory).as_posix()}:{sha256_file(path)}")
    return sha256_text("\n".join(lines))


class Report:
    """Сборка нарушений с уровнем серьезности."""

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def check_freeze(run_dir: Path, run: dict, report: Report) -> None:
    """Сверяет хэши заморозки с фактическими файлами."""
    task = run.get("task") or {}
    # Пары (хэш, ключ пути, путь по умолчанию). Путь по умолчанию позволяет
    # собирать run.json по схеме report-schema.md, не дублируя его вручную.
    checks = [
        ("spec_sha256", "spec_path", "spec.md"),
        ("ac_sha256", "acceptance_path", "acceptance.json"),
        ("public_tests_sha256", "public_tests_path", "public_tests"),
        ("hidden_tests_sha256", "hidden_tests_path", "hidden_tests"),
        ("prompts_sha256", "prompts_path", "prompts"),
    ]
    for hash_key, path_key, default_relative in checks:
        expected = task.get(hash_key)
        relative = task.get(path_key) or default_relative
        if not expected:
            continue
        target = run_dir / relative
        if not target.exists():
            report.error(f"заморозка: есть {hash_key}, но файл {relative} не найден")
            continue
        actual = sha256_tree(target) if target.is_dir() else sha256_file(target)
        if actual != expected:
            report.error(f"заморозка: хэш {relative} не совпадает ({actual[:16]} != {expected[:16]})")
    config = run.get("config")
    expected_config = task.get("config_sha256")
    if config is not None and expected_config:
        actual = sha256_canonical(config)
        if actual != expected_config:
            report.error("заморозка: хэш конфигурации не совпадает — состав участников или лимиты менялись")


def check_recon(run_dir: Path, run: dict, report: Report) -> None:
    """Проверяет общую картину: заморожена, зоны закрыты, пропуск объяснён.

    Картина (context.md) — общий вход всех участников. Если она изменилась после
    заморозки, сравнивать решения нечестно; если зона не закрыта, участники решали
    по догадкам; если пропуск не объяснён, прогон неполон.
    """
    recon = run.get("recon")
    if recon is None:
        report.error("в run.json нет блока recon — разведка картины не зафиксирована")
        return
    if not isinstance(recon, dict):
        report.error("блок recon должен быть объектом")
        return
    if recon.get("skipped"):
        reason = recon.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            report.error("recon пропущен, но причина не указана")
        return

    task = run.get("task") or {}
    relative = task.get("context_path") or "context.md"
    target = run_dir / relative
    if not target.exists():
        report.error(f"разведка: нет картины {relative}")
        return
    expected = task.get("context_sha256")
    if not expected:
        report.error("разведка: не зафиксирован context_sha256 — картина не заморожена")
        return
    actual = sha256_file(target)
    if actual != expected:
        report.error(f"разведка: хэш {relative} не совпадает ({actual[:16]} != {expected[:16]})")

    zones = recon.get("zones")
    if not isinstance(zones, list) or not zones:
        report.error("разведка: не заявлены зоны (recon.zones)")
        return
    text = target.read_text(encoding="utf-8", errors="replace")
    for zone in zones:
        name = str(zone.get("name") if isinstance(zone, dict) else zone)
        if not name.strip():
            report.error("разведка: зона без имени")
            continue
        marker = re.search(r"^#{1,6}\s+" + re.escape(name) + r"\s*$", text, re.MULTILINE)
        if not marker:
            report.error(f"разведка: в картине нет раздела зоны {name!r}")
            continue
        tail = text[marker.end():]
        nxt = re.search(r"^#{1,6}\s+", tail, re.MULTILINE)
        body = tail[: nxt.start()] if nxt else tail
        if not body.strip():
            report.error(f"разведка: раздел зоны {name!r} пуст — зона не закрыта")


def check_candidates(run_dir: Path, run: dict, report: Report) -> dict:
    """Проверяет кандидатов и строит карту метка -> автор."""
    mapping: dict[str, dict] = {}
    for candidate in run.get("candidates") or []:
        cid = str(candidate.get("cid") or "")
        if not cid:
            report.error("кандидат без поля cid")
            continue
        mapping[cid] = candidate
        relative = candidate.get("path")
        expected = candidate.get("sha256")
        if relative and expected:
            target = run_dir / relative
            if not target.exists():
                report.error(f"кандидат {cid}: файл {relative} не найден")
            elif sha256_file(target) != expected:
                report.error(f"кандидат {cid}: файл изменен после фиксации хэша")
        if candidate.get("valid_format") is False:
            report.warn(f"кандидат {cid}: формат ответа нарушен")
    return mapping


def check_label_map(run_dir: Path, run: dict, report: Report) -> dict:
    """Проверяет карту меток: наличие, целостность и отсутствие самоидентификации."""
    slot_by_label: dict[str, str] = {}
    map_path = run_dir / "label_map.json"
    if not map_path.exists():
        # карта могла остаться рядом со слепыми копиями кандидатов
        for folder in ("candidates", "blinded"):
            candidate_map = run_dir / folder / "label_map.json"
            if candidate_map.exists():
                map_path = candidate_map
                break
    if not map_path.exists():
        report.error("нет карты меток label_map.json")
        return slot_by_label
    try:
        data = json.loads(map_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.error(f"карта меток не читается: {exc}")
        return slot_by_label
    labels = data.get("labels") or []
    for entry in labels:
        slot_by_label[str(entry.get("label"))] = str(entry.get("slot"))
    expected = run.get("label_map_sha256")
    if expected:
        actual = sha256_canonical(labels)
        if actual != expected:
            report.error("карта меток изменена после фиксации хэша")
    for entry in labels:
        blinded_name = str(entry.get("label")) + ".md"
        blinded = run_dir / "candidates" / blinded_name
        if not blinded.exists():
            continue
        try:
            text = blinded.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        match = find_self_identification(text)
        if match:
            report.error(f"слепота: в {blinded_name} есть самоидентификация {match.group(0)!r}")
    return slot_by_label


def check_reviews(run: dict, mapping: dict, slot_by_label: dict, report: Report) -> None:
    """Проверяет ревью: свои ли кандидаты, из своего ли семейства, по известной ли метке."""
    family_by_slot: dict[str, str] = {}
    for member in run.get("roster") or []:
        slot = str(member.get("slot"))
        family_by_slot[slot] = str(member.get("family") or "")

    counts: dict[str, set] = {}
    for review in run.get("reviews") or []:
        cid = str(review.get("cid") or "")
        reviewer = str(review.get("reviewer_slot") or "")
        if cid not in mapping:
            report.error(f"ревью ссылается на неизвестную метку {cid!r}")
            continue
        author = str(mapping[cid].get("author_slot") or slot_by_label.get(cid) or "")
        if author and reviewer == author:
            report.error(f"ревью: {reviewer} ревьюит собственный кандидат {cid}")
        reviewer_family = family_by_slot.get(reviewer, "")
        candidate_family = str(mapping[cid].get("family") or "")
        if reviewer_family and candidate_family and reviewer_family == candidate_family:
            report.error(f"ревью: {reviewer} ({reviewer_family}) ревьюит кандидата своего семейства {cid}")
        counts.setdefault(cid, set()).add(reviewer)

    # Кандидат без ревью не должен молча пройти гейт: если он в топе — это ошибка,
    # иначе предупреждение.
    aggregation = run.get("aggregation") or {}
    decision = run.get("decision") or {}
    top = (aggregation.get("ranking") or [None])[0]
    winner = decision.get("winner_cid")
    for cid in sorted(mapping):
        reviewers = counts.get(cid, set())
        if not reviewers:
            message = f"кандидат {cid}: ни одного ревью"
            if cid in (top, winner):
                report.error(message + " — при этом он в топе ранжирования")
            else:
                report.warn(message)
            continue
        if len(reviewers) < 2:
            report.warn(f"кандидат {cid}: ревьюировал меньше двух независимых моделей")


def check_decision(run: dict, report: Report) -> None:
    """Проверяет согласованность вердикта с агрегацией."""
    aggregation = run.get("aggregation") or {}
    decision = run.get("decision") or {}
    if not aggregation:
        report.warn("нет блока aggregation")
        return
    verdict = decision.get("verdict")
    suggested = aggregation.get("verdict_suggestion")
    override = decision.get("override")
    ranking = aggregation.get("ranking") or []
    winner = decision.get("winner_cid")

    if verdict not in ("ACCEPT", "ACCEPT_WITH_NOTES", "NO_CONSENSUS", "REJECT_ALL", "DEGRADED"):
        report.error(f"неизвестный вердикт {verdict!r}")
        return
    if winner and ranking and winner not in ranking:
        report.error(f"победитель {winner} не входит в ранжирование агрегации")
    quorum = aggregation.get("quorum") or {}
    if not quorum.get("met", True) and verdict in ("ACCEPT", "ACCEPT_WITH_NOTES") and not override:
        report.error("вердикт принят без кворума и без записи override")
    if suggested == "REJECT_ALL" and verdict == "ACCEPT" and not override:
        report.error("вердикт ACCEPT при REJECT_ALL по агрегации и без override")
    if override:
        report.warn(f"вердикт переопределен вручную: {override}")


def check_artifacts(run_dir: Path, run: dict, report: Report) -> None:
    """Проверяет наличие артефактов прогона, объявленных в SKILL.md."""
    aggregation = run.get("aggregation") or {}
    if aggregation and not (run_dir / "aggregation.json").exists():
        report.warn("в каталоге нет aggregation.json, хотя блок aggregation заполнен")
    for folder, label in (("reviews", "ревью"), ("verification", "логи проверок")):
        path = run_dir / folder
        if path.exists() and not any(path.iterdir()):
            report.warn(f"каталог {folder} пуст — нет ни одного {label[:-1]}")
    if (run_dir / "label_map.json").exists():
        pass
    clusters = run.get("clusters")
    if clusters and clusters.get("path") and not (run_dir / clusters["path"]).exists():
        report.warn("в каталоге нет clusters.json — разнообразие не измерено")
    if not (run_dir / "report.md").exists():
        report.warn("нет report.md — отчет для человека еще не собран")


def check_integrity(run: dict, report: Report) -> None:
    """Флаги целостности, выставленные самим прогоном."""
    integrity = run.get("integrity") or {}
    if integrity.get("freeze_ok") is False:
        report.error("прогон помечен как недействительным: freeze_ok=false")
    if integrity.get("test_dispute"):
        report.warn("зафиксирован спор о тестах между участниками")
    for warning in run.get("warnings") or []:
        report.warn(f"предупреждение прогона: {warning}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="check_run.py",
        description="Проверка целостности прогона мозгового штурма.",
    )
    parser.add_argument("run_dir", help="каталог прогона с run.json")
    parser.add_argument("--json", action="store_true", help="вывести отчет в JSON")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir)
    run_path = run_dir / "run.json"
    if not run_path.exists():
        print(f"check_run: нет файла {run_path}", file=sys.stderr)
        return 1
    try:
        run = json.loads(run_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check_run: run.json не читается: {exc}", file=sys.stderr)
        return 1
    if not isinstance(run, dict):
        print("check_run: run.json должен быть объектом", file=sys.stderr)
        return 1

    report = Report()
    for key in ("task", "config", "candidates", "decision", "recon"):
        if key not in run:
            report.error(f"в run.json нет обязательного поля {key!r}")
    if report.errors:
        for message in report.errors:
            print(f"check_run: ОШИБКА {message}", file=sys.stderr)
        return 1

    check_freeze(run_dir, run, report)
    check_recon(run_dir, run, report)
    mapping = check_candidates(run_dir, run, report)
    slot_by_label = check_label_map(run_dir, run, report)
    check_reviews(run, mapping, slot_by_label, report)
    check_decision(run, report)
    check_artifacts(run_dir, run, report)
    check_integrity(run, report)

    if args.json:
        print(json.dumps({
            "errors": report.errors,
            "warnings": report.warnings,
            "ok": not report.errors,
        }, ensure_ascii=False, indent=2))
    else:
        for message in report.errors:
            print(f"check_run: ОШИБКА {message}")
        for message in report.warnings:
            print(f"check_run: ВНИМАНИЕ {message}")
        if not report.errors:
            print(f"check_run: целостность подтверждена (предупреждений: {len(report.warnings)})")
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
