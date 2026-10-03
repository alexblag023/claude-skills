#!/usr/bin/env python3
"""CI-раннер eval-харнесса. Не требует внешних сканеров.

Проверяет две вещи, которые должны быть зелёными всегда:
 1. score.py --self-test — логика подсчёта precision/recall и защиты от дрейфа.
 2. verify_anchors на каждом манифесте tests/ground_truth/*.yml — якоря ground-truth
    всё ещё на заявленных строках корпуса (ловит рассинхрон манифеста и корпуса).

Полный прогон precision/recall по реальному выводу Semgrep (нужен установленный
Semgrep) — см. README раздел «Eval-харнесс»: он не входит в этот раннер, потому
что Semgrep в CI ставится отдельно и тянет правила реестра из сети.

Коды: 0 — всё прошло; 1 — провал.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from score import load_manifest, verify_anchors, GroundTruthError  # noqa: E402

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass


def main() -> int:
    failures: list[str] = []

    # 1. самотест скорера
    r = subprocess.run([sys.executable, str(HERE / "score.py"), "--self-test"],
                       capture_output=True, text=True, encoding="utf-8")
    print(r.stdout.strip())
    if r.returncode != 0:
        failures.append("score.py --self-test провалился")
        print(r.stderr.strip())

    # 2. якоря всех манифестов
    gt_dir = HERE / "ground_truth"
    manifests = sorted(gt_dir.glob("*.yml")) if gt_dir.exists() else []
    if not manifests:
        failures.append(f"нет манифестов в {gt_dir}")
    for m in manifests:
        try:
            expected, safe, corpus_root, _ = load_manifest(m)
            verify_anchors(expected, corpus_root)
            print(f"ANCHORS OK: {m.name} — {len(expected)} findings, {len(safe)} safe")
        except GroundTruthError as e:
            failures.append(f"{m.name}: {e}")
            print(f"ANCHORS FAIL: {m.name}: {e}")

    if failures:
        print("\nEVAL TESTS FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nEVAL TESTS OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
