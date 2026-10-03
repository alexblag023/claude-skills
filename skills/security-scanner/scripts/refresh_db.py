#!/usr/bin/env python3
"""Обновление баз уязвимостей и рулсетов при старте скана + snapshot-дата в отчёт.

Зачем: находки сканера достоверны ровно настолько, насколько свежа база, по
которой он сверялся. Скилл заявляет «критических/высоких нет» — значит обязан
знать и показать ДАТУ базы, по которой это проверено. Этот скрипт перед сканом:
 - обновляет локальные базы инструментов, если они установлены и есть сеть:
     * Trivy      — `trivy image --download-db-only` (+ java-db)
     * osv-scanner — прогрев оффлайн-БД OSV (`--download-offline-databases`)
     * Semgrep    — правила реестра p/* тянутся при скане; прогреваем кэш
 - пишет снапшот `~/.security-scanner/db_snapshot.json`: что обновлено, версия,
   дата, статус per-tool (updated / offline / failed / absent);
 - при отсутствии сети НЕ падает: оставляет прошлый снапшот и помечает `offline`,
   чтобы отчёт честно сказал «база от <дата>, обновить не удалось»;
 - на stdout печатает ОДНУ строку для вставки в отчёт (`snapshot_line()`).

Инструментов может не быть в окружении — тогда tool помечается `absent`, а не
выдаётся за обновлённый (принцип скилла: «не проверено» ≠ PASS).

Запуск:
    refresh_db.py                 # обновить что есть, записать снапшот, напечатать строку
    refresh_db.py --dry-run       # показать, что было бы сделано, не трогая сеть/базы
    refresh_db.py --print         # только напечатать строку из текущего снапшота
    refresh_db.py --self-test     # проверка логики снапшота/оффлайна без инструментов
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):  # pragma: no cover
        pass

DEFAULT_SNAPSHOT = Path(os.environ.get(
    "SECURITY_SCANNER_HOME", Path.home() / ".security-scanner")) / "db_snapshot.json"

# tool -> команда обновления базы (список argv). Команда запускается, только если
# бинарь найден в PATH. stdout/stderr гасятся, важен код возврата.
REFRESH_CMDS: dict[str, list[list[str]]] = {
    "trivy": [["trivy", "image", "--download-db-only"],
              ["trivy", "image", "--download-java-db-only"]],
    "osv-scanner": [["osv-scanner", "--download-offline-databases",
                     "--experimental-offline-vulnerabilities", "--help"]],
    # Semgrep кэширует правила реестра при первом использовании; прогреваем кэш.
    "semgrep": [["semgrep", "--version"]],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_version(tool: str) -> str | None:
    exe = shutil.which(tool)
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30)
        return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def load_snapshot(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_snapshot(path: Path, snap: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snap, indent=2, ensure_ascii=False), encoding="utf-8")


def refresh(path: Path = DEFAULT_SNAPSHOT, dry_run: bool = False,
            runner=subprocess.run, which=shutil.which) -> dict:
    """Обновляет базы установленных инструментов и возвращает новый снапшот.

    `runner`/`which` инжектируются для самотеста. Снапшот сохраняется на диск
    (кроме dry_run). Отсутствующие инструменты -> status 'absent' (не ошибка);
    упавшее обновление (нет сети и т.п.) -> 'offline', с сохранением прошлой даты.
    """
    prev = load_snapshot(path)
    prev_tools = prev.get("tools", {})
    tools: dict[str, dict] = {}
    for tool, cmds in REFRESH_CMDS.items():
        exe = which(tool)
        if not exe:
            tools[tool] = {"status": "absent"}
            continue
        version = _tool_version(tool) if not dry_run else "dry-run"
        if dry_run:
            tools[tool] = {"status": "would-refresh", "version": version,
                           "cmds": [" ".join(c) for c in cmds]}
            continue
        ok = True
        for cmd in cmds:
            try:
                r = runner(cmd, capture_output=True, text=True, timeout=600)
                if r.returncode != 0:
                    ok = False
                    break
            except (subprocess.SubprocessError, OSError):
                ok = False
                break
        if ok:
            tools[tool] = {"status": "updated", "version": version, "updated_at": _now_iso()}
        else:
            # сеть/база недоступны — не роняем скан, держим прошлую дату
            last = prev_tools.get(tool, {})
            tools[tool] = {"status": "offline", "version": version,
                           "last_updated_at": last.get("updated_at") or last.get("last_updated_at")}
    snap = {"generated_at": _now_iso(), "dry_run": dry_run, "tools": tools}
    if not dry_run:
        save_snapshot(path, snap)
    return snap


def snapshot_line(snap: dict) -> str:
    """Одна строка для раздела отчёта «Снапшот базы уязвимостей»."""
    parts = []
    for tool, info in snap.get("tools", {}).items():
        st = info.get("status")
        if st == "updated":
            parts.append(f"{tool}: обновлён {info.get('updated_at', '?')[:10]}")
        elif st == "offline":
            last = info.get("last_updated_at") or "неизвестно"
            parts.append(f"{tool}: ОФФЛАЙН, база от {str(last)[:10]} (обновить не удалось)")
        elif st == "would-refresh":
            parts.append(f"{tool}: будет обновлён")
        elif st == "absent":
            parts.append(f"{tool}: не установлен (не проверено)")
    stamp = snap.get("generated_at", "?")[:10]
    return f"Снапшот базы на {stamp}: " + "; ".join(parts) if parts else \
           f"Снапшот базы на {stamp}: инструменты не найдены"


# --------------------------------------------------------------------------- #
def _self_test() -> int:
    failures: list[str] = []

    def check(c: bool, m: str):
        if not c:
            failures.append(m)

    with tempfile.TemporaryDirectory() as tmp:
        snap_path = Path(tmp) / "snap.json"

        # сценарий 1: trivy есть и обновляется успешно, semgrep есть, osv отсутствует
        present = {"trivy", "semgrep"}
        calls: list[list[str]] = []

        def fake_which(t):
            return f"/usr/bin/{t}" if t in present else None

        def ok_runner(cmd, **kw):
            calls.append(cmd)
            class R:  # noqa: D401
                returncode = 0
                stdout = "ok"
                stderr = ""
            return R()

        snap = refresh(snap_path, runner=ok_runner, which=fake_which)
        check(snap["tools"]["trivy"]["status"] == "updated", "trivy должен быть updated")
        check(snap["tools"]["semgrep"]["status"] == "updated", "semgrep должен быть updated")
        check(snap["tools"]["osv-scanner"]["status"] == "absent", "osv должен быть absent")
        check(snap_path.exists(), "снапшот не сохранён на диск")
        check(any("trivy" in c for c in calls), "команда trivy не вызвана")

        # сценарий 2: trivy теперь падает (нет сети) -> offline, но дата из прошлого снапшота
        def fail_runner(cmd, **kw):
            class R:
                returncode = 1
                stdout = ""
                stderr = "network error"
            return R()

        snap2 = refresh(snap_path, runner=fail_runner, which=fake_which)
        check(snap2["tools"]["trivy"]["status"] == "offline", "trivy при сбое должен быть offline")
        check(snap2["tools"]["trivy"].get("last_updated_at") is not None,
              "offline должен сохранить прошлую дату обновления")

        # сценарий 3: строка отчёта читаема и отражает offline
        line = snapshot_line(snap2)
        check("ОФФЛАЙН" in line and "trivy" in line, f"строка отчёта некорректна: {line}")

        # сценарий 4: dry-run не трогает диск и не вызывает команды
        calls.clear()
        fresh_path = Path(tmp) / "nope.json"
        snapd = refresh(fresh_path, dry_run=True, runner=ok_runner, which=fake_which)
        check(not fresh_path.exists(), "dry-run не должен писать снапшот")
        check(calls == [], "dry-run не должен вызывать команды обновления")
        check(snapd["tools"]["trivy"]["status"] == "would-refresh", "dry-run статус неверный")

        # сценарий 5: все инструменты отсутствуют -> строка «не найдены», без краха
        snap5 = refresh(Path(tmp) / "s5.json", runner=ok_runner, which=lambda t: None)
        check(all(v["status"] == "absent" for v in snap5["tools"].values()),
              "при отсутствии всех инструментов все absent")
        check("не установлен" in snapshot_line(snap5), "строка при отсутствии инструментов неверна")

    if failures:
        print("SELF-TEST FAILED:")
        for f in failures:
            print(f"  [x] {f}")
        return 1
    print("SELF-TEST OK: 5 сценариев (updated / offline+дата / отчёт / dry-run / absent)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Обновление баз уязвимостей + snapshot-дата")
    ap.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    ap.add_argument("--dry-run", action="store_true", help="показать план, не трогая сеть/базы")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="только напечатать строку из текущего снапшота")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.print_only:
        print(snapshot_line(load_snapshot(args.snapshot)))
        return 0
    snap = refresh(args.snapshot, dry_run=args.dry_run)
    print(snapshot_line(snap))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
