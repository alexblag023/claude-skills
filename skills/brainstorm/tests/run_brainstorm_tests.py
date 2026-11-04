#!/usr/bin/env python3
"""Регрессионные тесты скилла "Мозговой штурм": подсчет голосов, формат ответов,
анонимизация, дедупликация идей, целостность прогона.

Запуск: python tests/run_brainstorm_tests.py   (код 0 — все прошли)
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import aggregate_votes as agg   # noqa: E402
import anonymize as anon        # noqa: E402
import check_run as chk         # noqa: E402
import dedup_ideas as dedup     # noqa: E402
import validate_answers as val   # noqa: E402


def rubric(correctness=3, ac=3, robustness=3, simplicity=3, spec=3):
    return {
        "correctness": correctness, "ac_coverage": ac, "robustness": robustness,
        "simplicity": simplicity, "spec_adherence": spec,
    }


def review(reviewer, cid, score=3, family="f2", defects=None, pairwise=None):
    return {
        "reviewer_slot": reviewer, "reviewer_family": family, "cid": cid,
        "ac_results": {"AC-1": "pass"}, "defects": defects or [],
        "rubric": rubric(score), "pairwise": pairwise or [],
    }


def verification(cid, hidden_pass=8, hidden_total=8, compile_ok=True):
    return {
        "cid": cid, "compile_ok": compile_ok, "lint_errors": 0,
        "public_pass": 2, "public_total": 2,
        "hidden_pass": hidden_pass, "hidden_total": hidden_total,
    }


def payload():
    """Базовый прогон: три кандидата, у каждого два ревью."""
    return {
        "candidates": [
            {"cid": "C1", "author_slot": "A1", "family": "f1"},
            {"cid": "C2", "author_slot": "A2", "family": "f2"},
            {"cid": "C3", "author_slot": "A3", "family": "f3"},
        ],
        "reviews": [
            review("R2", "C1", 4, "f2", pairwise=[{"a": "C1", "b": "C2", "winner": "C1"}]),
            review("R3", "C1", 4, "f3", pairwise=[{"a": "C1", "b": "C2", "winner": "C1"}]),
            review("R1", "C2", 2, "f1"),
            review("R3", "C2", 2, "f3"),
            review("R1", "C3", 3, "f1"),
            review("R2", "C3", 3, "f2"),
        ],
        "verification": [verification("C1"), verification("C2", 6), verification("C3", 7)],
        "reliability": {}, "config": {},
    }


def test_aggregate_basic(failed):
    """Зеленый прогон: победитель по S и по исполнению, кворум набран, вердикт ACCEPT."""
    result = agg.compute(payload())
    if result["ranking"][0] != "C1":
        failed.append(f"aggregate: ожидался победитель C1, получено {result['ranking']}")
    if result["verdict_suggestion"] != "ACCEPT":
        failed.append(f"aggregate: ожидался ACCEPT, получено {result['verdict_suggestion']}")
    if not result["quorum"]["met"]:
        failed.append("aggregate: кворум должен быть набран")
    if result["quorum"]["required"] != 2:
        failed.append(f"aggregate: требуемый кворум должен быть 2, получено {result['quorum']['required']}")


def test_aggregate_excludes_confirmed_critical(failed):
    """Критический дефект, подтвержденный двумя ревьюерами, исключает кандидата."""
    data = payload()
    defect_a = {"severity": "critical", "ac": "AC-1", "location": "app.py:12",
                "claim": "гонка", "evidence": "строка 12"}
    defect_b = {"severity": "critical", "ac": "AC-1", "location": "app.py:37",
                "claim": "гонка", "evidence": "строка 37"}
    data["reviews"].append(review("R3", "C2", 2, "f3", defects=[defect_a]))
    data["reviews"].append(review("R1", "C2", 2, "f1", defects=[defect_b]))
    result = agg.compute(data)
    excluded = [item["cid"] for item in result["excluded"]]
    if "C2" not in excluded:
        failed.append(f"aggregate: C2 должен быть исключен, excluded={excluded}")
    if "C2" in result["scores"]:
        failed.append("aggregate: исключенный кандидат не должен попадать в scores")


def test_aggregate_single_critical_is_flag_only(failed):
    """Один неподтвержденный critical — флаг, а не исключение."""
    data = payload()
    data["verification"] = [verification("C1"), verification("C2"), verification("C3")]
    defect = {"severity": "critical", "ac": "AC-1", "location": "app.py:12",
              "claim": "подозрение", "evidence": "строка 12"}
    data["reviews"].append(review("R3", "C2", 2, "f3", defects=[defect]))
    result = agg.compute(data)
    if "C2" in [item["cid"] for item in result["excluded"]]:
        failed.append("aggregate: одиночный critical не должен исключать кандидата")


def test_aggregate_execution_beats_votes(failed):
    """Победитель по голосам, упавший на тестах, проигрывает проходящему кандидату."""
    data = payload()
    data["reviews"] = [r for r in data["reviews"] if r["cid"] != "C2"]
    data["reviews"].append(review("R1", "C2", 4, "f1"))
    data["reviews"].append(review("R3", "C2", 4, "f3"))
    data["reviews"] = [r for r in data["reviews"] if r["cid"] != "C1"]
    data["reviews"].append(review("R2", "C1", 2, "f2"))
    data["reviews"].append(review("R3", "C1", 2, "f3"))
    data["verification"] = [verification("C1"), verification("C2", 4), verification("C3", 7)]
    result = agg.compute(data)
    if result["ranking"][0] != "C1":
        failed.append(f"aggregate: исполнение должно побеждать голоса, ranking={result['ranking']}")
    kinds = [d["kind"] for d in result["dissent"]]
    if "votes_vs_execution" not in kinds:
        failed.append(f"aggregate: расхождение голосов и исполнения должно попасть в dissent, got {result['dissent']}")


def test_aggregate_no_quorum(failed):
    """Низкие оценки correctness не дают кворума."""
    data = payload()
    for item in data["reviews"]:
        if item["cid"] == "C1":
            item["rubric"]["correctness"] = 2
    result = agg.compute(data)
    if result["verdict_suggestion"] != "NO_CONSENSUS":
        failed.append(f"aggregate: ожидался NO_CONSENSUS, получено {result['verdict_suggestion']}")


def test_aggregate_tie(failed):
    """Два одинаковых кандидата дают ничью и требуют эскалации."""
    data = payload()
    data["candidates"] = [
        {"cid": "C1", "author_slot": "A1", "family": "f1"},
        {"cid": "C2", "author_slot": "A2", "family": "f2"},
    ]
    data["reviews"] = [
        review("R2", "C1", 4, "f2"), review("R3", "C1", 4, "f3"),
        review("R1", "C2", 4, "f1"), review("R3", "C2", 4, "f3"),
    ]
    data["verification"] = [verification("C1"), verification("C2")]
    result = agg.compute(data)
    if result["tie"] is None:
        failed.append("aggregate: ничья не распознана")
    if result["verdict_suggestion"] != "NO_CONSENSUS":
        failed.append(f"aggregate: при ничьей ожидался NO_CONSENSUS, получено {result['verdict_suggestion']}")


def test_aggregate_reject_all(failed):
    """Ни один кандидат не прошел проверку исполнением — REJECT_ALL."""
    data = payload()
    data["verification"] = [verification("C1", 3, 8), verification("C2", 2, 8), verification("C3", 1, 8)]
    result = agg.compute(data)
    if result["verdict_suggestion"] != "REJECT_ALL":
        failed.append(f"aggregate: ожидался REJECT_ALL, получено {result['verdict_suggestion']}")


def test_aggregate_degraded(failed):
    """Один кандидат — режим DEGRADED."""
    data = payload()
    data["candidates"] = [{"cid": "C1", "author_slot": "A1", "family": "f1"}]
    data["reviews"] = [review("R2", "C1", 4, "f2")]
    data["verification"] = [verification("C1")]
    result = agg.compute(data)
    if result["verdict_suggestion"] != "DEGRADED":
        failed.append(f"aggregate: ожидался DEGRADED, получено {result['verdict_suggestion']}")


def test_aggregate_bad_input(failed):
    """Некорректный вход должен поднимать InputError, а не угадывать."""
    try:
        agg.compute({"reviews": []})
    except agg.InputError:
        return
    failed.append("aggregate: отсутствие candidates должно давать InputError")


def test_aggregate_weight_cap(failed):
    """Веса ревьюеров ограничены: отношение max/min не больше 2."""
    weights = {"R1": 1.0, "R2": 0.01}
    capped = agg.cap_weights(weights)
    if max(capped.values()) / min(capped.values()) > 2.0 + 1e-9:
        failed.append(f"aggregate: веса не ограничены: {capped}")
    weight, rel = agg.reviewer_weight({"reviewer_slot": "R9"}, {})
    if abs(rel - 0.5) > 1e-9:
        failed.append(f"aggregate: новая модель должна получать w_rel=0.5, получено {rel}")


def test_aggregate_missing_rubric_warns(failed):
    """Пропущенный критерий рубрики — предупреждение, а не молчание."""
    data = payload()
    for item in data["reviews"]:
        item["rubric"].pop("simplicity", None)
    result = agg.compute(data)
    if not any("нет критериев" in warning for warning in result["warnings"]):
        failed.append(f"aggregate: пропуск критерия рубрики должен давать предупреждение: {result['warnings']}")


def test_aggregate_custom_weights(failed):
    """Кастомные веса рубрики влияют и на взвешенную оценку R_w, а не только на R."""
    data = payload()
    data["config"] = {"rubric_weights": {"correctness": 1.0, "ac_coverage": 0.0,
                                   "robustness": 0.0, "simplicity": 0.0,
                                   "spec_adherence": 0.0}}
    result = agg.compute(data)
    if abs(result["scores"]["C1"]["R_w"] - 1.0) > 1e-6:
        failed.append(f"aggregate: кастомные веса не применились к R_w: {result['scores']['C1']}")
    weights = result["method"]["rubric_weights"]
    if abs(sum(weights.values()) - 1.0) > 1e-6:
        failed.append(f"aggregate: веса не нормализованы: {weights}")


def test_validate_author(failed):
    """Схема роли author: обязательные поля и диапазон confidence."""
    good = json.dumps({"solution": "решение", "assumptions": [], "self_tests": [],
                      "risks": [], "confidence": 0.8})
    if val.validate_text("author", good, "t", False):
        failed.append("validate: корректный ответ author не должен давать замечаний")
    bad = json.dumps({"solution": "", "assumptions": "не список", "self_tests": [],
                     "risks": [], "confidence": 5})
    findings = val.validate_text("author", bad, "t", False)
    rules = {f.rule for f in findings}
    for expected in ("author.solution", "author.assumptions", "author.confidence"):
        if expected not in rules:
            failed.append(f"validate: ожидалось замечание {expected}, получено {sorted(rules)}")


def test_validate_critic(failed):
    """Схема роли critic: дефект без доказательства и оценка вне 0..4."""
    good = json.dumps({"cid": "C1", "ac_results": {"AC-1": "pass"}, "defects": [],
                      "rubric": rubric(3), "pairwise": []})
    if val.validate_text("critic", good, "t", False):
        failed.append("validate: корректный ответ critic не должен давать замечаний")
    bad = json.dumps({"cid": "C1", "ac_results": {"AC-1": "maybe"},
                     "defects": [{"severity": "critical", "ac": "AC-1",
                                 "location": "a.py:1", "claim": "x"}],
                     "rubric": {"correctness": 9, "ac_coverage": 3, "robustness": 3,
                                "simplicity": 3, "spec_adherence": 3}, "pairwise": []})
    rules = {f.rule for f in val.validate_text("critic", bad, "t", False)}
    for expected in ("critic.ac_results", "critic.defects[0].evidence", "critic.rubric.correctness"):
        if expected not in rules:
            failed.append(f"validate: ожидалось замечание {expected}, получено {sorted(rules)}")


def test_validate_json_extraction(failed):
    """JSON достается даже из текста с markdown-оберткой и рассуждением перед ним."""
    text = "Сначала подумаю.\n```json\n{\"cid\": \"C1\", \"ac_results\": {}, "
    text += "\"defects\": [], \"rubric\": " + json.dumps(rubric(3)) + ", \"pairwise\": []}\n```"
    findings = val.validate_text("critic", text, "t", False)
    if findings:
        failed.append(f"validate: JSON из markdown-обертки не распознан: {[f.rule for f in findings]}")


def test_validate_blind(failed):
    """Самоидентификация модели ловится отдельной проверкой."""
    findings = val.validate_text("critic", "As an AI, I am Claude and I think...", "t", True)
    if not any(f.rule == "blind.self_identification" for f in findings):
        failed.append("validate: самоидентификация не найдена")


def test_validate_repair(failed):
    """Схема роли repair: unified diff обязателен."""
    good = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    if val.validate_text("repair", good, "t", False):
        failed.append("validate: корректный diff не должен давать замечаний")
    bad = "просто исправьте код"
    rules = {f.rule for f in val.validate_text("repair", bad, "t", False)}
    if "repair.hunk" not in rules:
        failed.append(f"validate: diff без хунка должен давать замечание, получено {sorted(rules)}")


def run_script(script: str, args: list[str], cwd: Path) -> int:
    return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPTS / script), *args],
                          cwd=str(cwd), capture_output=True, text=True).returncode


def test_anonymize(failed):
    """Метки перемешиваются детерминированно, самоидентификация вырезается."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        src = base / "candidates"
        src.mkdir()
        (src / "A1.md").write_text("решение одно\nAs an AI, I am Claude.\n", encoding="utf-8")
        (src / "A2.md").write_text("решение два\n", encoding="utf-8")
        (src / "A3.md").write_text("решение три\n", encoding="utf-8")
        out = base / "blinded"
        code = run_script("anonymize.py", ["--candidates", str(src), "--out", str(out), "--seed", "7"], base)
        if code != 0:
            failed.append("anonymize: ненулевой код возврата")
            return
        data = json.loads((out / "label_map.json").read_text(encoding="utf-8"))
        labels = {entry["label"]: entry["slot"] for entry in data["labels"]}
        if sorted(labels) != ["C1", "C2", "C3"]:
            failed.append(f"anonymize: метки неверны: {labels}")
        if labels["C1"] == "A1":
            failed.append("anonymize: метки не перемешаны при seed=7")
        for entry in data["labels"]:
            text = (out / f"{entry['label']}.md").read_text(encoding="utf-8")
            if "I am Claude" in text:
                failed.append(f"anonymize: самоидентификация не вырезана в {entry['label']}")
        recomputed = chk.sha256_bytes(json.dumps(data["labels"], ensure_ascii=False, sort_keys=True,
                                           separators=(",", ":")).encode("utf-8"))
        if recomputed != data["label_map_sha256"]:
            failed.append("anonymize: хэш карты меток не сходится")


def test_dedup(failed):
    """Похожие идеи сливаются в кластер, разные — расходятся."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        src = base / "candidates"
        src.mkdir()
        (src / "A1.md").write_text("# Хранить события в Postgres\n\nСобытия пишем в таблицу событий Postgres.\n", encoding="utf-8")
        (src / "A2.md").write_text("# Хранить события в Postgres\n\nСобытия пишем в таблицу событий Postgres.\n", encoding="utf-8")
        (src / "A3.md").write_text("# Очередь на Kafka\n\nПоток событий уходит в Kafka с партициями по ключу.\n", encoding="utf-8")
        out = base / "clusters.json"
        code = run_script("dedup_ideas.py", ["--candidates", str(src), "--out", str(out)], base)
        if code != 0:
            failed.append("dedup: ненулевой код возврата")
            return
        data = json.loads(out.read_text(encoding="utf-8"))
        if data["clusters"] != 2:
            failed.append(f"dedup: ожидалось 2 кластера, получено {data['clusters']}")
        if not 0 < data["diversity_ratio"] <= 1:
            failed.append(f"dedup: некорректный diversity_ratio {data['diversity_ratio']}")


def build_run(base: Path) -> dict:
    """Готовый прогон для проверки целостности."""
    (base / "candidates").mkdir(parents=True, exist_ok=True)
    (base / "candidates" / "C1.md").write_text("решение один\n", encoding="utf-8")
    (base / "candidates" / "C2.md").write_text("решение два\n", encoding="utf-8")
    spec = base / "spec.md"
    spec.write_text("спека\n", encoding="utf-8")
    config = {"n_authors": 3, "max_calls": 16, "delta_tie": 0.05}
    run = {
        "schema_version": "1.0",
        "task": {
            "title": "тест", "spec_path": "spec.md",
            "spec_sha256": chk.sha256_file(spec),
            "config_sha256": chk.sha256_canonical(config),
        },
        "config": config,
        "roster": [
            {"slot": "A1", "family": "f1"}, {"slot": "A2", "family": "f2"},
            {"slot": "R1", "family": "f3"}, {"slot": "R2", "family": "f4"},
        ],
        "candidates": [
            {"cid": "C1", "author_slot": "A1", "family": "f1", "path": "candidates/C1.md",
             "sha256": chk.sha256_file(base / "candidates" / "C1.md")},
            {"cid": "C2", "author_slot": "A2", "family": "f2", "path": "candidates/C2.md",
             "sha256": chk.sha256_file(base / "candidates" / "C2.md")},
        ],
        "label_map_sha256": "",
        "reviews": [
            {"reviewer_slot": "R1", "cid": "C1", "role": "critic"},
            {"reviewer_slot": "R2", "cid": "C1", "role": "critic"},
            {"reviewer_slot": "R1", "cid": "C2", "role": "critic"},
        ],
        "aggregation": {"ranking": ["C1", "C2"], "verdict_suggestion": "ACCEPT",
                       "quorum": {"required": 2, "support_for_winner": 2, "met": True}},
        "decision": {"verdict": "ACCEPT", "winner_cid": "C1", "override": None},
        "integrity": {"freeze_ok": True},
        "warnings": [],
    }
    labels = [{"label": "C1", "slot": "A1"}, {"label": "C2", "slot": "A2"}]
    (base / "label_map.json").write_text(json.dumps({"labels": labels}, ensure_ascii=False), encoding="utf-8")
    run["label_map_sha256"] = chk.sha256_canonical(labels)
    return run


def test_check_run_ok(failed):
    """Корректный прогон проходит проверку целостности."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run = build_run(base)
        (base / "run.json").write_text(json.dumps(run, ensure_ascii=False), encoding="utf-8")
        code = run_script("check_run.py", [str(base)], base)
        if code != 0:
            failed.append("check_run: корректный прогон должен проходить")


def test_check_run_detects_tampering(failed):
    """Измененный кандидат и саморевью ловятся как ошибки."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run = build_run(base)
        (base / "run.json").write_text(json.dumps(run, ensure_ascii=False), encoding="utf-8")
        (base / "candidates" / "C1.md").write_text("подмененное решение\n", encoding="utf-8")
        run["reviews"].append({"reviewer_slot": "A1", "cid": "C1", "role": "critic"})
        (base / "run.json").write_text(json.dumps(run, ensure_ascii=False), encoding="utf-8")
        code = run_script("check_run.py", [str(base)], base)
        if code == 0:
            failed.append("check_run: подмена кандидата и саморевью должны давать ненулевой код")


def test_check_run_requires_quorum(failed):
    """Вердикт ACCEPT без кворума — ошибка."""
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        run = build_run(base)
        run["aggregation"]["quorum"] = {"required": 2, "support_for_winner": 0, "met": False}
        (base / "run.json").write_text(json.dumps(run, ensure_ascii=False), encoding="utf-8")
        code = run_script("check_run.py", [str(base)], base)
        if code == 0:
            failed.append("check_run: вердикт без кворума должен давать ненулевой код")


def main() -> int:
    failed = []
    tests = [
        test_aggregate_basic, test_aggregate_excludes_confirmed_critical,
        test_aggregate_single_critical_is_flag_only, test_aggregate_execution_beats_votes,
        test_aggregate_no_quorum, test_aggregate_tie, test_aggregate_reject_all,
        test_aggregate_degraded, test_aggregate_bad_input, test_aggregate_weight_cap,
        test_aggregate_missing_rubric_warns, test_aggregate_custom_weights,
        test_validate_author, test_validate_critic,
        test_validate_json_extraction, test_validate_blind, test_validate_repair,
        test_anonymize, test_dedup, test_check_run_ok,
        test_check_run_detects_tampering, test_check_run_requires_quorum,
    ]
    for test in tests:
        test(failed)
    for message in failed:
        print("FAIL", message)
    status = "FAIL" if failed else "OK"
    print(f"brainstorm tests: {status} ({len(failed)} ошибок, тестов: {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
