#!/usr/bin/env python3
"""validate_answers.py — проверка формата ответов внешних моделей.

Роли: author (решение), critic (ревью), judge (сравнение/эскалация), repair (починка).

Запуск:
  python validate_answers.py --role author FILE [FILE ...]
  python validate_answers.py --role critic --dir reviews/
  python validate_answers.py --role critic --check-blind FILE

Код возврата: 0 — нарушений нет; 1 — нарушения найдены или вход не читается.
Опция --json печатает находки машиночитаемо (для run.json).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Признаки самоидентификации: модель, узнавшая себя, выдает автора ревью.
BLIND_PATTERNS = [
    r"\bas an ai\b",
    r"\bi am an ai\b",
    r"\bi am (?:large language model|llm|ai assistant|assistant)\b",
    r"\bi.?m (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok)\b",
    r"\bas (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok)\b",
    r"\bкак (?:языковая |большая )?модель\b",
    r"\bя — (?:gpt|claude|gemini|qwen|llama|mistral|deepseek|kimi|grok|ии|ai)\b",
    r"\bмоя версия\b",
    r"\bmy model\b",
    r"\bchatgpt\b",
    r"\bcopilot\b",
    r"\bdeepseek[- ]?r1\b",
    r"\bgpt[- ]?4\b",
    r"\bclaude[- ]?(?:opus|sonnet|haiku)\b",
    r"\bgemini[- ]?[0-9]\b",
    r"\bqwen[0-9.-]*\b",
]

RUBRIC_KEYS = ("correctness", "ac_coverage", "robustness", "simplicity", "spec_adherence")
AC_STATUSES = {"pass", "fail", "unknown"}
SEVERITIES = {"critical", "major", "minor"}


class Finding:
    """Одно нарушение: где, что не так."""

    def __init__(self, source: str, rule: str, message: str):
        self.source = source
        self.rule = rule
        self.message = message

    def as_dict(self) -> dict:
        return {"source": self.source, "rule": self.rule, "message": self.message}

    def __str__(self) -> str:
        return f"{self.source}: {self.rule}: {self.message}"


def strip_fences(text: str) -> str:
    """Убирает markdown-обертку ```json ... ``` и обычные тройные кавычки."""
    stripped = text.strip()
    stripped = re.sub(r"^```[a-zA-Z0-9_+-]*\s*", "", stripped)
    stripped = re.sub(r"\s*```$", "", stripped)
    return stripped.strip()


def extract_json(text: str) -> str | None:
    """Достает первый корректный JSON-объект из текста ответа.

    Скобки считаются с учетом строковых литералов: так объект внутри текста не
    разваливается на запятые внутри строк.
    """
    body = strip_fences(text)
    start = body.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(body)):
            char = body[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == chr(92):
                    escaped = True
                elif char == chr(34):
                    in_string = False
                continue
            if char == chr(34):
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    chunk = body[start:index + 1]
                    try:
                        json.loads(chunk)
                    except json.JSONDecodeError:
                        break
                    return chunk
        start = body.find("{", start + 1)
    return None


def _is_str(value) -> bool:
    return isinstance(value, str)


def _is_str_list(value) -> bool:
    return isinstance(value, list) and all(_is_str(item) for item in value)


def check_author(data: dict, source: str) -> list[Finding]:
    """Схема роли author: решение, предположения, самопроверки, риски, уверенность."""
    findings: list[Finding] = []
    solution = data.get("solution")
    if not _is_str(solution) or not solution.strip():
        findings.append(Finding(source, "author.solution", "поле solution должно быть непустой строкой"))
    for key in ("assumptions", "self_tests", "risks"):
        if key not in data:
            findings.append(Finding(source, f"author.{key}", f"нет поля {key}"))
        elif not _is_str_list(data[key]):
            findings.append(Finding(source, f"author.{key}", f"поле {key} должно быть списком строк"))
    if "confidence" not in data:
        findings.append(Finding(source, "author.confidence", "нет поля confidence"))
    else:
        confidence = data["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            findings.append(Finding(source, "author.confidence", "confidence должен быть числом"))
        elif not 0.0 <= float(confidence) <= 1.0:
            findings.append(Finding(source, "author.confidence", "confidence вне диапазона 0..1"))
    return findings


def check_critic(data: dict, source: str) -> list[Finding]:
    """Схема роли critic: критерии, дефекты с доказательством, рубрика, парные сравнения."""
    findings: list[Finding] = []
    cid = data.get("cid")
    if not _is_str(cid) or not cid.strip():
        findings.append(Finding(source, "critic.cid", "поле cid должно быть непустой строкой"))

    ac_results = data.get("ac_results")
    if not isinstance(ac_results, dict):
        findings.append(Finding(source, "critic.ac_results", "ac_results должен быть объектом"))
    else:
        for key, value in ac_results.items():
            if str(value).strip().lower() not in AC_STATUSES:
                findings.append(Finding(
                    source, "critic.ac_results",
                    f"AC {key}: статус {value!r} не из {sorted(AC_STATUSES)}",
                ))

    defects = data.get("defects")
    if not isinstance(defects, list):
        findings.append(Finding(source, "critic.defects", "defects должен быть списком"))
    else:
        for index, defect in enumerate(defects):
            tag = f"critic.defects[{index}]"
            if not isinstance(defect, dict):
                findings.append(Finding(source, tag, "дефект должен быть объектом"))
                continue
            severity = str(defect.get("severity") or "").strip().lower()
            if severity not in SEVERITIES:
                findings.append(Finding(source, f"{tag}.severity",
                                             f"severity {severity!r} не из {sorted(SEVERITIES)}"))
            for key in ("claim", "evidence"):
                value = defect.get(key)
                if not _is_str(value) or not value.strip():
                    findings.append(Finding(source, f"{tag}.{key}",
                                                 f"поле {key} обязательно и не должно быть пустым"))

    rubric = data.get("rubric")
    if not isinstance(rubric, dict):
        findings.append(Finding(source, "critic.rubric", "rubric должен быть объектом"))
    else:
        for key in RUBRIC_KEYS:
            if key not in rubric:
                findings.append(Finding(source, f"critic.rubric.{key}", f"нет критерия {key}"))
                continue
            value = rubric[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                findings.append(Finding(source, f"critic.rubric.{key}", "оценка должна быть числом"))
            elif not 0 <= value <= 4:
                findings.append(Finding(source, f"critic.rubric.{key}", "оценка вне диапазона 0..4"))

    pairwise = data.get("pairwise")
    if pairwise is None:
        pairwise = []
    if not isinstance(pairwise, list):
        findings.append(Finding(source, "critic.pairwise", "pairwise должен быть списком"))
    else:
        for index, pair in enumerate(pairwise):
            tag = f"critic.pairwise[{index}]"
            if not isinstance(pair, dict):
                findings.append(Finding(source, tag, "сравнение должно быть объектом"))
                continue
            for key in ("a", "b", "winner"):
                if not _is_str(pair.get(key)) or not pair[key].strip():
                    findings.append(Finding(source, f"{tag}.{key}", f"поле {key} обязательно"))
            winner = pair.get("winner")
            if _is_str(winner) and winner not in (pair.get("a"), pair.get("b")):
                findings.append(Finding(source, f"{tag}.winner",
                                             "winner должен совпадать с a или b"))
    return findings


def check_judge(data: dict, source: str) -> list[Finding]:
    """Схема роли judge: победитель, решающий довод, риск проигравшего."""
    findings: list[Finding] = []
    winner = data.get("winner")
    if not _is_str(winner) or not winner.strip():
        findings.append(Finding(source, "judge.winner", "поле winner обязательно"))
    elif winner.strip().lower() not in ("tie", "ничья") and not re.match(r"^[A-Za-z0-9_-]+$", winner.strip()):
        findings.append(Finding(source, "judge.winner", "winner должен быть меткой кандидата или tie"))
    reason = data.get("decisive_reason")
    if not _is_str(reason) or not reason.strip():
        findings.append(Finding(source, "judge.decisive_reason", "поле decisive_reason обязательно"))
    if "risk_of_loser" not in data:
        findings.append(Finding(source, "judge.risk_of_loser", "нет поля risk_of_loser"))
    elif not _is_str(data["risk_of_loser"]):
        findings.append(Finding(source, "judge.risk_of_loser", "risk_of_loser должен быть строкой"))
    return findings


def check_repair(text: str, source: str) -> list[Finding]:
    """Схема роли repair: unified diff с заголовками файлов и хотя бы одним хунком."""
    findings: list[Finding] = []
    body = strip_fences(text)
    if not re.search(r"^---\s+\S+", body, re.MULTILINE):
        findings.append(Finding(source, "repair.header", "нет заголовка --- файл"))
    if not re.search(r"^\+\+\+\s+\S+", body, re.MULTILINE):
        findings.append(Finding(source, "repair.header", "нет заголовка +++ файл"))
    if "@@" not in body:
        findings.append(Finding(source, "repair.hunk", "нет ни одного хунка @@"))
    return findings


def check_blind(text: str, source: str) -> list[Finding]:
    """Ищет самоидентификацию модели: она выдает автора ревью."""
    findings: list[Finding] = []
    lowered = text.lower()
    for pattern in BLIND_PATTERNS:
        match = re.search(pattern, lowered)
        if match:
            findings.append(Finding(
                source, "blind.self_identification",
                f"в тексте есть самоидентификация: {match.group(0)!r}",
            ))
            break
    return findings


def validate_text(role: str, text: str, source: str, check_blind_mode: bool) -> list[Finding]:
    findings: list[Finding] = []
    if check_blind_mode:
        findings.extend(check_blind(text, source))
    if role == "repair":
        findings.extend(check_repair(text, source))
        return findings
    chunk = extract_json(text)
    if chunk is None:
        findings.append(Finding(source, f"{role}.json", "в ответе не найден корректный JSON-объект"))
        return findings
    try:
        data = json.loads(chunk)
    except json.JSONDecodeError as exc:  # pragma: no cover - extract_json уже проверил
        findings.append(Finding(source, f"{role}.json", f"JSON не разбирается: {exc}"))
        return findings
    if not isinstance(data, dict):
        findings.append(Finding(source, f"{role}.json", "ожидался JSON-объект"))
        return findings
    if role == "author":
        findings.extend(check_author(data, source))
    elif role == "critic":
        findings.extend(check_critic(data, source))
    elif role == "judge":
        findings.extend(check_judge(data, source))
    else:
        findings.append(Finding(source, "role.unknown", f"неизвестная роль {role!r}"))
    return findings


def collect_files(paths: list[str], directory: str | None) -> list[Path]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.exists():
            files.append(path)
    if directory:
        base = Path(directory)
        if base.is_dir():
            files.extend(sorted(p for p in base.rglob("*") if p.is_file()))
    seen: set[str] = set()
    unique: list[Path] = []
    for path in files:
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_answers.py",
        description="Проверка формата ответов внешних моделей.",
    )
    parser.add_argument("files", nargs="*", help="файлы с ответами")
    parser.add_argument("--role", required=True,
                        choices=["author", "critic", "judge", "repair"],
                        help="роль, по схеме которой проверяем ответ")
    parser.add_argument("--dir", help="каталог с ответами (рекурсивно)")
    parser.add_argument("--check-blind", action="store_true",
                        help="дополнительно искать самоидентификацию модели")
    parser.add_argument("--json", action="store_true", help="вывести находки в JSON")
    args = parser.parse_args(argv)

    targets = collect_files(args.files, args.dir)
    if not targets:
        print("validate_answers: не найдено файлов для проверки", file=sys.stderr)
        return 1

    findings: list[Finding] = []
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            findings.append(Finding(str(path), "io", f"не удалось прочитать файл: {exc}"))
            continue
        findings.extend(validate_text(args.role, text, str(path), args.check_blind))

    if args.json:
        print(json.dumps({"findings": [f.as_dict() for f in findings]},
                         ensure_ascii=False, indent=2))
    else:
        for finding in findings:
            print(finding)
        if not findings:
            print(f"OK: {len(targets)} файл(ов), нарушений нет")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
