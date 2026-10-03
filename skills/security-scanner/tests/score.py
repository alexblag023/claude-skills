#!/usr/bin/env python3
"""Eval-харнесс precision/recall для скилла security-scanner.

Оценивает АРТЕФАКТ (вывод сканера), а не процесс: харнесс берёт декларативный
ground-truth манифест (tests/ground_truth/*.yml) и реальный вывод сканера
(Semgrep JSON или SARIF 2.1.0) и считает TP/FP/FN + precision/recall по КЛАССУ
уязвимости и по строке.

Ключевые свойства (по образцу Trail of Bits score.py):
 - **Защита от дрейфа строк.** Каждый ожидаемый finding в манифесте хранит не
   только `line`, но и `anchor` — подстроку, которая ОБЯЗАНА находиться на этой
   строке в файле корпуса. Перед подсчётом `verify_anchors()` проверяет каждый
   якорь; если строка уехала (anchor нашёлся на другой строке) или исчез —
   харнесс падает с GroundTruthError, а не молча считает мусор.
 - **Оценивается найденное, а не обещанное.** Нет вывода сканера → нечего
   засчитывать (recall 0), а не «успех по умолчанию».
 - **Детерминированность.** Никакого LLM, только данные манифеста и JSON/SARIF
   сканера; пригоден для CI.

Запуск:
    score.py --manifest tests/ground_truth/gaps.yml --scan out.json [--format semgrep|sarif]
    score.py --self-test          # проверка логики скорера на синтетике, без внешних инструментов

Коды возврата: 0 — отработал (или --self-test прошёл); 1 — провал самотеста;
2 — ошибка данных (дрейф якоря, битый манифест/отчёт).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - окружение без pyyaml
    yaml = None

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent

# На Windows консоль по умолчанию cp1251 и падает на маркерах ✗/✓ в отчёте.
# Переводим вывод в UTF-8 без зависимости от переменной PYTHONUTF8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):  # pragma: no cover - нестандартный поток
        pass
# Допуск по строке: сканеры нередко якорят находку на соседнюю строку
# (начало выражения vs вызов). ±LINE_TOLERANCE строк считаем тем же местом.
LINE_TOLERANCE = 2


class GroundTruthError(Exception):
    """Манифест не соответствует корпусу — дрейф якоря или битые данные.

    Это отдельный класс ошибки: «не смогли оценить вообще» принципиально
    отличается от «оценили и получили ноль».
    """


# --------------------------------------------------------------------------- #
# Модель данных
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Expected:
    """Один ожидаемый finding (true-positive локация) из манифеста."""
    file: str
    cwe: str
    line: int
    anchor: str
    rule: str | None = None


@dataclass(frozen=True)
class ScanHit:
    """Одна находка из вывода сканера, нормализованная."""
    file: str          # basename
    line: int
    rule: str | None
    cwe: str | None


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    matched: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    spurious: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


# --------------------------------------------------------------------------- #
# Загрузка манифеста и проверка якорей
# --------------------------------------------------------------------------- #
def load_manifest(path: Path) -> tuple[list[Expected], list[str], Path, Path]:
    if yaml is None:
        raise GroundTruthError("нужен pyyaml: pip install pyyaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # corpus_root/safe_root трактуются ОТНОСИТЕЛЬНО каталога манифеста.
    # Реальная раскладка: манифест в tests/ground_truth/, корпус в tests/vuln_corpus
    # -> в манифесте пишется `corpus_root: ../vuln_corpus`.
    corpus_root = (path.parent / data.get("corpus_root", "vuln_corpus")).resolve()
    safe_root = (path.parent / data.get("safe_root", "vuln_corpus_safe")).resolve()
    expected: list[Expected] = []
    for item in data.get("findings", []):
        if item.get("is_vuln") is False:
            continue
        missing = [k for k in ("file", "cwe", "line", "anchor") if k not in item]
        if missing:
            raise GroundTruthError(f"finding {item.get('file', '?')}: нет полей {missing}")
        expected.append(Expected(
            file=item["file"], cwe=_norm_cwe(item["cwe"]), line=int(item["line"]),
            anchor=item["anchor"], rule=item.get("rule"),
        ))
    safe = list(data.get("safe", []))
    return expected, safe, corpus_root, safe_root


def verify_anchors(expected: list[Expected], corpus_root: Path) -> None:
    """Падает, если якорь не на заявленной строке (дрейф) или исчез из файла."""
    for e in expected:
        fp = corpus_root / e.file
        if not fp.exists():
            raise GroundTruthError(f"{e.file}: файла нет в {corpus_root}")
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        if not 1 <= e.line <= len(lines):
            raise GroundTruthError(
                f"{e.file}: line {e.line} вне диапазона (в файле {len(lines)} строк)")
        if e.anchor in lines[e.line - 1]:
            continue
        # якорь не на заявленной строке — ищем, куда уехал, чтобы сообщение было полезным
        found = [i + 1 for i, ln in enumerate(lines) if e.anchor in ln]
        if found:
            raise GroundTruthError(
                f"{e.file}: ДРЕЙФ СТРОКИ — anchor {e.anchor!r} ожидался на line "
                f"{e.line}, фактически на {found}. Обнови манифест.")
        raise GroundTruthError(
            f"{e.file}: anchor {e.anchor!r} исчез из файла (строка {e.line} = "
            f"{lines[e.line - 1]!r}). Правило/корпус разошлись с манифестом.")


# --------------------------------------------------------------------------- #
# Загрузка вывода сканера
# --------------------------------------------------------------------------- #
def _norm_cwe(raw) -> str:
    """'CWE-79', '79', 'cwe079', 'external/cwe/cwe-079' -> 'CWE-79'."""
    s = str(raw).upper()
    digits = "".join(ch for ch in s.split("CWE")[-1] if ch.isdigit()) if "CWE" in s else \
             "".join(ch for ch in s if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else s


def load_semgrep(path: Path) -> list[ScanHit]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hits: list[ScanHit] = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        cwe_raw = meta.get("cwe")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else None
        hits.append(ScanHit(
            file=Path(r["path"]).name,
            line=int(r.get("start", {}).get("line", 0)),
            rule=str(r.get("check_id", "")).split(".")[-1] or None,
            cwe=_norm_cwe(cwe_raw) if cwe_raw else None,
        ))
    return hits


def load_sarif(path: Path) -> list[ScanHit]:
    data = json.loads(path.read_text(encoding="utf-8"))
    hits: list[ScanHit] = []
    for run in data.get("runs", []):
        # карта ruleId -> CWE из описаний правил (tags вида external/cwe/cwe-079)
        rule_cwe: dict[str, str] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            tags = (rule.get("properties", {}) or {}).get("tags", []) or []
            for t in tags:
                if "cwe" in str(t).lower():
                    rule_cwe[rule.get("id", "")] = _norm_cwe(t)
                    break
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {})
            fname = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            hits.append(ScanHit(
                file=Path(fname).name,
                line=int(line or 0),
                rule=str(rule_id).split(".")[-1] or None,
                cwe=rule_cwe.get(rule_id),
            ))
    return hits


# --------------------------------------------------------------------------- #
# Сопоставление и подсчёт
# --------------------------------------------------------------------------- #
def _hit_matches(e: Expected, h: ScanHit) -> bool:
    if h.file != e.file:
        return False
    if abs(h.line - e.line) > LINE_TOLERANCE:
        return False
    # совпадение по классу: если манифест задаёт rule и сканер его назвал — сверяем rule;
    # иначе сверяем CWE; если сканер не дал ни rule, ни cwe — засчитываем по локации.
    if e.rule and h.rule:
        return h.rule == e.rule
    if h.cwe:
        return h.cwe == e.cwe
    return True


def score(expected: list[Expected], safe_files: list[str], hits: list[ScanHit],
          only_ruled: bool = False) -> Score:
    # only_ruled: оценивать лишь находки с заданным `rule:` (наши gaps-правила);
    # классы без rule покрываются реестром Semgrep и не относятся к gaps-прогону.
    if only_ruled:
        expected = [e for e in expected if e.rule]
    s = Score()
    used: set[int] = set()
    safe_set = set(safe_files)
    for e in expected:
        idx = next((i for i, h in enumerate(hits)
                    if i not in used and _hit_matches(e, h)), None)
        if idx is None:
            s.fn += 1
            s.missed.append(f"{e.file}:{e.line} {e.cwe}{'/' + e.rule if e.rule else ''}")
        else:
            used.add(idx)
            s.tp += 1
            s.matched.append(f"{e.file}:{e.line} {e.cwe}")
    # FP: срабатывание на safe-файле — всегда FP. Срабатывание на gt-файле — FP
    # ТОЛЬКО если оно не со-локализовано ни с одной известной уязвимой строкой
    # (±tolerance): второе правило, подсветившее ту же уязвимую строку (напр.
    # и языковое, и общее правило на один хардкод-секрет), — это дубль TP, а не
    # ложное срабатывание; местоположение реально уязвимо.
    gt_by_file: dict[str, list[Expected]] = {}
    for e in expected:
        gt_by_file.setdefault(e.file, []).append(e)
    for i, h in enumerate(hits):
        if i in used:
            continue
        if h.file in safe_set:
            s.fp += 1
            s.spurious.append(f"{h.file}:{h.line} {h.rule or h.cwe or '?'} [safe-файл]")
            continue
        gts = gt_by_file.get(h.file)
        if gts is None:
            continue  # файл вне разметки — не оцениваем (ни TP, ни FP)
        # дубль того же КЛАССА на известной уязвимой строке (±tol) — не FP:
        # напр. и языковое, и общее правило подсветили один хардкод-секрет.
        near_same = any(abs(h.line - e.line) <= LINE_TOLERANCE
                        and (h.cwe is None or h.cwe == e.cwe) for e in gts)
        if near_same:
            continue
        s.fp += 1
        s.spurious.append(f"{h.file}:{h.line} {h.rule or h.cwe or '?'} [мислейбл/не на уязв. строке]")
    return s


def format_report(s: Score, title: str) -> str:
    out = [f"# Eval: {title}",
           f"TP={s.tp}  FP={s.fp}  FN={s.fn}",
           f"precision={s.precision:.3f}  recall={s.recall:.3f}  f1={s.f1:.3f}"]
    if s.missed:
        out.append("\n## Пропущено (FN):")
        out += [f"  - {m}" for m in s.missed]
    if s.spurious:
        out.append("\n## Лишние срабатывания (FP):")
        out += [f"  - {m}" for m in s.spurious]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Самотест (без внешних инструментов)
# --------------------------------------------------------------------------- #
def _self_test() -> int:
    failures: list[str] = []

    def check(cond: bool, msg: str):
        if not cond:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        corpus = root / "vuln_corpus"
        corpus.mkdir()
        # два уязвимых файла
        (corpus / "cwe089_sqli.py").write_text(
            "q = 'SELECT * FROM t WHERE id=' + uid\ncur.execute(q)\n", encoding="utf-8")
        (corpus / "cwe079_xss.js").write_text(
            "el.innerHTML = location.hash.slice(1)\n", encoding="utf-8")
        manifest = root / "gt.yml"
        manifest.write_text(
            "corpus_root: vuln_corpus\nsafe_root: vuln_corpus_safe\nfindings:\n"
            "  - file: cwe089_sqli.py\n    cwe: CWE-89\n    rule: gap-sqli\n"
            "    line: 2\n    anchor: \"cur.execute(q)\"\n"
            "  - file: cwe079_xss.js\n    cwe: CWE-79\n    line: 1\n"
            "    anchor: \"innerHTML = location.hash\"\nsafe:\n  - safe_x.py\n",
            encoding="utf-8")

        expected, safe, corpus_root, _ = load_manifest(manifest)
        check(len(expected) == 2, "манифест: ожидалось 2 finding")
        check(safe == ["safe_x.py"], "манифест: safe-список не прочитан")

        # 1. якоря валидны
        try:
            verify_anchors(expected, corpus_root)
        except GroundTruthError as ex:  # pragma: no cover
            check(False, f"verify_anchors ложно упал: {ex}")

        # 2. идеальный прогон: обе находки на месте -> P=R=1
        perfect = [ScanHit("cwe089_sqli.py", 2, "gap-sqli", "CWE-89"),
                   ScanHit("cwe079_xss.js", 1, None, "CWE-79")]
        s = score(expected, safe, perfect)
        check((s.tp, s.fp, s.fn) == (2, 0, 0), f"идеал: ожидался 2/0/0, получено {s.tp}/{s.fp}/{s.fn}")
        check(s.precision == 1.0 and s.recall == 1.0, "идеал: P/R должны быть 1.0")

        # 3. допуск по строке (±2): находка на line 3 вместо 2 -> всё ещё TP
        near = [ScanHit("cwe089_sqli.py", 3, "gap-sqli", "CWE-89"),
                ScanHit("cwe079_xss.js", 1, None, "CWE-79")]
        check(score(expected, safe, near).tp == 2, "допуск ±2 строки не работает")

        # 4. промах по классу: тот же файл/строка, но другой CWE -> не TP
        wrong_class = [ScanHit("cwe089_sqli.py", 2, None, "CWE-22")]
        sw = score(expected, safe, wrong_class)
        check(sw.tp == 0, "промах по классу засчитан как TP")
        check(sw.fp == 1 and sw.fn == 2, f"промах по классу: ожидался 0TP/1FP/2FN, {sw.tp}/{sw.fp}/{sw.fn}")

        # 5. ложное срабатывание на safe-файле -> FP
        with_fp = perfect + [ScanHit("safe_x.py", 5, "gap-sqli", "CWE-89")]
        sfp = score(expected, ["safe_x.py"], with_fp)
        check(sfp.fp == 1, f"FP на safe-файле не посчитан: fp={sfp.fp}")
        check(abs(sfp.precision - 2 / 3) < 1e-9, f"precision при 2TP/1FP должно быть 0.667, {sfp.precision}")

        # 6. пропуск находки -> FN, recall падает
        miss = [ScanHit("cwe089_sqli.py", 2, "gap-sqli", "CWE-89")]
        sm = score(expected, safe, miss)
        check((sm.tp, sm.fn) == (1, 1), f"пропуск: ожидался 1TP/1FN, {sm.tp}/{sm.fn}")
        check(sm.recall == 0.5, f"recall при 1/2 должен быть 0.5, {sm.recall}")

        # 7. защита от дрейфа строк: сдвигаем файл вставкой строки сверху
        (corpus / "cwe079_xss.js").write_text(
            "// добавленный комментарий\nel.innerHTML = location.hash.slice(1)\n",
            encoding="utf-8")
        drift_caught = False
        try:
            verify_anchors(expected, corpus_root)
        except GroundTruthError as ex:
            drift_caught = "ДРЕЙФ" in str(ex)
        check(drift_caught, "дрейф строки НЕ пойман verify_anchors")

        # 8. исчезнувший якорь -> тоже GroundTruthError
        (corpus / "cwe079_xss.js").write_text("el.textContent = safe\n", encoding="utf-8")
        gone_caught = False
        try:
            verify_anchors([e for e in expected if e.file == "cwe079_xss.js"], corpus_root)
        except GroundTruthError:
            gone_caught = True
        check(gone_caught, "исчезнувший якорь не пойман")

        # 9. SARIF-загрузчик: CWE подтягивается из tags правила
        sarif = root / "r.sarif"
        sarif.write_text(json.dumps({"runs": [{"tool": {"driver": {"rules": [
            {"id": "gap-sqli", "properties": {"tags": ["security", "external/cwe/cwe-089"]}}]}},
            "results": [{"ruleId": "gap-sqli", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "a/cwe089_sqli.py"},
                "region": {"startLine": 2}}}]}]}]}), encoding="utf-8")
        sh = load_sarif(sarif)
        check(len(sh) == 1 and sh[0].cwe == "CWE-89" and sh[0].file == "cwe089_sqli.py",
              f"SARIF-загрузчик сломан: {sh}")

        # 10. Semgrep-загрузчик
        sj = root / "r.json"
        sj.write_text(json.dumps({"results": [{"check_id": "rules.gap-sqli",
            "path": "x/cwe089_sqli.py", "start": {"line": 2},
            "extra": {"metadata": {"cwe": ["CWE-89: SQL Injection"]}}}]}), encoding="utf-8")
        sg = load_semgrep(sj)
        check(len(sg) == 1 and sg[0].cwe == "CWE-89" and sg[0].rule == "gap-sqli",
              f"Semgrep-загрузчик сломан: {sg}")

    if failures:
        print("SELF-TEST FAILED:")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print("SELF-TEST OK: 10 проверок пройдены "
          "(якоря, допуск строк, класс, FP/FN, дрейф, SARIF, Semgrep)")
    return 0


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Eval precision/recall для security-scanner")
    ap.add_argument("--manifest", type=Path, help="ground-truth YAML (tests/ground_truth/*.yml)")
    ap.add_argument("--scan", type=Path, help="вывод сканера (JSON Semgrep или SARIF)")
    ap.add_argument("--format", choices=["semgrep", "sarif"], default="sarif")
    ap.add_argument("--only-ruled", action="store_true",
                    help="оценивать только находки с rule: (прогон собственных gaps-правил)")
    ap.add_argument("--self-test", action="store_true", help="проверка логики без внешних инструментов")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    if not args.manifest or not args.scan:
        ap.error("нужны --manifest и --scan (или --self-test)")
    try:
        expected, safe, corpus_root, _ = load_manifest(args.manifest)
        verify_anchors(expected, corpus_root)  # падает при дрейфе якоря
        hits = (load_semgrep if args.format == "semgrep" else load_sarif)(args.scan)
    except GroundTruthError as ex:
        print(f"ОШИБКА ДАННЫХ: {ex}", file=sys.stderr)
        return 2
    s = score(expected, safe, hits, only_ruled=args.only_ruled)
    print(format_report(s, args.manifest.stem + (" [only-ruled]" if args.only_ruled else "")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
