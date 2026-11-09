"""Verify a Codex delegation smoke test against the checked-in role profiles."""

import argparse
import json
import tomllib
from pathlib import Path

ROLES = {"architecture", "audit", "expert_review"}
PROFILES = Path(__file__).resolve().parents[1] / ".codex" / "agents"


def verify(day: Path, parent: str) -> None:
    verified = set()
    for path in day.glob("rollout-*.jsonl"):
        with path.open(encoding="utf-8") as journal:
            first = json.loads(next(journal, "{}"))
            spawn = (first.get("payload", {}).get("source") or {})
            if not isinstance(spawn, dict):
                continue
            spawn = spawn.get("subagent", {}).get("thread_spawn", {})
            if spawn.get("parent_thread_id") != parent:
                continue
            role = spawn.get("agent_role")
            if role not in ROLES or role in verified:
                raise SystemExit(f"Unexpected or repeated child role: {role}")

            profile = tomllib.loads((PROFILES / f"{role}.toml").read_text(encoding="utf-8"))
            expected = (profile["model"], profile["model_reasoning_effort"])
            observed = set()
            completed = False
            for line in journal:
                event = json.loads(line)
                payload = event["payload"]
                if event["type"] == "turn_context":
                    observed.add((payload.get("model"), payload.get("effort")))
                if event["type"] == "event_msg" and payload.get("type") == "task_complete":
                    completed = payload.get("last_agent_message") == f"ROUTE_SMOKE {role}"
            if observed != {expected} or not completed:
                raise SystemExit(f"{role}: expected {expected}, observed {observed}, completed={completed}")
            print(f"{role}: {expected[0]} / {expected[1]} / completed")
            verified.add(role)
    if verified != ROLES:
        raise SystemExit(f"Missing child roles: {', '.join(sorted(ROLES - verified))}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("day", type=Path, help="Codex sessions YYYY/MM/DD directory")
    parser.add_argument("parent", help="Parent thread ID from the thread.started event")
    args = parser.parse_args()
    verify(args.day, args.parent)
