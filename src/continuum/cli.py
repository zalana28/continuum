"""Continuum CLI — the whole product from a terminal.

Commands:
  continuum generate [--count N] [--seed S] [--out FILE]
      Deterministic synthetic alert corpus (also pre-baked in demo/).

  continuum triage ALERT.json [--db PATH] [--no-memory] [--llm]
      Correlate one alert against institutional memory and decide.
      --no-memory  runs the deletion test: same alert, memory deleted.
      --llm        use LLMTriageAgent (needs LLM_API_KEY).

  continuum resolve ALERT.json [--db PATH]
      Interactive analyst write-back: resolution + root cause fold into
      memory (incident, entity profiles, technique stats, journal).

  continuum demo [--db PATH]
      The scripted fresh-session recall demo. Session 2 is run in a
      SUBPROCESS — a genuinely fresh Python process reading the same
      memory file from disk. No chat history survives; only memory does.

  continuum status [--db PATH]
      What is in the store: incidents, entities, journal events.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .agent.triage_agent import LLMTriageAgent, RuleTriageAgent, correlate
from .feedback.resolve import resolve_alert
from .ingestion.alert_generator import dump_alerts, generate_alerts, load_alerts
from .memory.schema import Alert, RESOLUTIONS
from .memory.sibyl_client import ContinuumMemory, MemoryUnavailable, NullMemory

DEFAULT_DB = "~/.sibyl-memory/continuum.db"


def _open_memory(args: argparse.Namespace) -> ContinuumMemory | None:
    if getattr(args, "no_memory", False):
        return NullMemory()
    return ContinuumMemory(getattr(args, "db", DEFAULT_DB))


def _print_decision(alert: Alert, decision: Any, *, header: str = "") -> None:
    if header:
        print(f"\n=== {header} ===")
    print(f"alert     : {alert.alert_id} [{alert.alert_type} / {alert.mitre_technique}] "
          f"severity={alert.severity} @ {alert.timestamp}")
    print(f"entities  : {json.dumps(alert.entities)}")
    print(f"decision  : {decision.decision}  (confidence {decision.confidence:.2f})")
    print(f"cites     : {', '.join(decision.cited_incidents) or '-'}")
    print(f"reasoning : {decision.reasoning}")


def cmd_generate(args: argparse.Namespace) -> int:
    alerts = generate_alerts(count=args.count, seed=args.seed)
    dump_alerts(alerts, args.out)
    print(f"wrote {len(alerts)} alerts to {args.out} (seed={args.seed})")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    alert = Alert.from_dict(json.loads(Path(args.alert).read_text(encoding="utf-8")))
    memory = _open_memory(args)
    ctx = correlate(alert, memory)
    agent = LLMTriageAgent() if args.llm else RuleTriageAgent()
    decision = agent.triage(alert, ctx)
    print(f"memory    : {memory.db_path}")
    print(f"context   : {ctx.summary}")
    _print_decision(alert, decision)
    return 0


def cmd_resolve(args: argparse.Namespace) -> int:
    alert = Alert.from_dict(json.loads(Path(args.alert).read_text(encoding="utf-8")))
    memory = ContinuumMemory(args.db)

    print(f"Resolving alert {alert.alert_id} ({alert.alert_type})")
    resolution = _prompt_choice("resolution", RESOLUTIONS, default="false_positive")
    root_cause = input("root cause: ").strip()
    notes = input("analyst notes (optional): ").strip()
    severity = input(f"severity assigned ({', '.join(['low', 'medium', 'high'])}): ").strip() or "medium"

    incident = resolve_alert(
        memory,
        alert,
        resolution=resolution,
        root_cause=root_cause or "(not recorded)",
        analyst_notes=notes,
        severity_assigned=severity,
    )
    print(f"\nwritten to memory: {incident.incident_id}")
    print("  -> incident entity (WARM)")
    print("  -> entity profiles for: " + ", ".join(alert.entities.values()))
    print("  -> technique stats " + alert.mitre_technique)
    print("  -> journal event (COLD)")
    return 0


def _prompt_choice(label: str, options: tuple[str, ...], default: str) -> str:
    shown = "/".join(options)
    while True:
        value = input(f"{label} [{shown}]: ").strip().lower() or default
        if value in options:
            return value
        print(f"  invalid; pick one of {shown}")


def cmd_demo(args: argparse.Namespace) -> int:
    db = str(Path(args.db).expanduser().resolve())
    # The demo must start from a truly empty store: a stale db from a
    # previous run would make Session 1 "remember" things it shouldn't.
    # WAL mode leaves -wal/-shm sidecars, so all three must go.
    removed = False
    for suffix in ("", "-wal", "-shm"):
        sidecar = Path(db + suffix)
        if sidecar.exists():
            sidecar.unlink()
            removed = True
    if removed:
        print(f"removed stale store {db} — demo always starts fresh")
    demo_dir = Path(__file__).resolve().parent.parent.parent / "demo"
    print(f"memory db : {db} (fresh store)")
    print("=" * 72)
    print("CONTINUUM — fresh-session recall demo")
    print("=" * 72)

    # --- Session 1: first encounter, empty memory ---------------------
    alert1 = Alert.from_dict(json.loads((demo_dir / "alerts_session1.json").read_text(encoding="utf-8")))
    mem1 = ContinuumMemory(db)
    decision1 = RuleTriageAgent().triage(alert1, correlate(alert1, mem1))
    _print_decision(alert1, decision1, header="SESSION 1 — alert #1 (empty memory, first process)")
    print("\n>> Analyst resolves it as a false positive (contractor VPN), write-back to memory:")
    resolved = resolve_alert(
        mem1,
        alert1,
        resolution="false_positive",
        root_cause="Contractor VPN exit node, pre-approved by IT on 2026-08-20",
        analyst_notes="Recurring pattern for this contractor; consider whitelisting exit range",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )
    print(f">> resolved -> {resolved.incident_id} written. mem1 process exits.")
    del mem1

    # --- Session 2: GENUINELY FRESH PROCESS, same db on disk ----------
    print("\n" + "=" * 72)
    print(">> KILLING the process. Opening a brand-new Python process")
    print(">> reading the same memory file from disk. Zero chat history.")
    print("=" * 72)
    alert2_path = demo_dir / "alerts_session2.json"
    proc = subprocess.run(
        [sys.executable, "-m", "continuum.cli", "triage", str(alert2_path), "--db", db],
        capture_output=True,
        text=True,
        timeout=120,
    )
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
        return proc.returncode

    # --- Session 3: same technique, brand-new user (contrast) ---------
    alert3 = Alert.from_dict(json.loads((demo_dir / "alerts_session3.json").read_text(encoding="utf-8")))
    mem3 = ContinuumMemory(db)
    decision3 = RuleTriageAgent().triage(alert3, correlate(alert3, mem3))
    _print_decision(
        alert3,
        decision3,
        header="SESSION 3 — same technique T1078, NEW user mchen (third process, same db)",
    )
    print("\n>> Session 3 proves correlation reasons over structured memory:")
    print(">> mchen has no entity history, so the contractor's clearance is NOT inherited.")
    mem3.log_event(acted=["completed demo run"], extra={"incident_id": resolved.incident_id})

    print("\n" + "=" * 72)
    print("DEMO COMPLETE — deletion test for the video:")
    print("  continuum triage demo/alerts_session2.json --no-memory")
    print("=" * 72)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    memory = ContinuumMemory(args.db)
    for key, value in memory.status().items():
        print(f"{key:16}: {value}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="continuum", description="SOC triage agent with institutional memory")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gen = sub.add_parser("generate", help="generate a synthetic alert corpus")
    p_gen.add_argument("--count", type=int, default=70)
    p_gen.add_argument("--seed", type=int, default=42)
    p_gen.add_argument("--out", default="demo/alerts_bulk.json")
    p_gen.set_defaults(func=cmd_generate)

    p_tri = sub.add_parser("triage", help="triage one alert against memory")
    p_tri.add_argument("alert", help="path to alert JSON")
    p_tri.add_argument("--db", default=DEFAULT_DB)
    p_tri.add_argument("--no-memory", action="store_true", help="deletion test: run with the memory layer removed")
    p_tri.add_argument("--llm", action="store_true", help="use LLM-backed triage (needs LLM_API_KEY)")
    p_tri.set_defaults(func=cmd_triage)

    p_res = sub.add_parser("resolve", help="resolve an alert and write it back to memory")
    p_res.add_argument("alert", help="path to alert JSON")
    p_res.add_argument("--db", default=DEFAULT_DB)
    p_res.set_defaults(func=cmd_resolve)

    p_demo = sub.add_parser("demo", help="run the scripted fresh-session recall demo")
    p_demo.add_argument("--db", default="demo/demo_memory.db")
    p_demo.set_defaults(func=cmd_demo)

    p_stat = sub.add_parser("status", help="show what is in the store")
    p_stat.add_argument("--db", default=DEFAULT_DB)
    p_stat.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except MemoryUnavailable as exc:
        print(f"memory unavailable: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
