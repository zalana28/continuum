"""End-to-end: the exact demo story, process boundaries included.

Session 2 and 3 run through *fresh* ContinuumMemory instances on the
same db file — the in-process equivalent of killing the process. The
CLI-level demo additionally proves it with a real subprocess
(test_cli_demo_subprocess).
"""

import subprocess
import sys
from pathlib import Path

from continuum.agent.triage_agent import RuleTriageAgent, correlate
from continuum.feedback.resolve import resolve_alert
from continuum.memory.schema import DECISION_AUTO_SUPPRESS, DECISION_ESCALATE
from continuum.memory.sibyl_client import ContinuumMemory


def test_full_demo_story(tmp_path, session1_alert, session2_alert, session3_alert):
    db = tmp_path / "demo.db"

    # --- Session 1: empty memory -> blind escalate -------------------
    mem1 = ContinuumMemory(db)
    d1 = RuleTriageAgent().triage(session1_alert, correlate(session1_alert, mem1))
    assert d1.decision == DECISION_ESCALATE
    assert d1.cited_incidents == []

    # Analyst resolves; write-back folds into memory.
    resolve_alert(
        mem1,
        session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node, pre-approved by IT on 2026-08-20",
        analyst_notes="Recurring pattern for this contractor",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )
    del mem1  # process dies

    # --- Session 2: FRESH client, same db -> auto-suppress -----------
    mem2 = ContinuumMemory(db)
    d2 = RuleTriageAgent().triage(session2_alert, correlate(session2_alert, mem2))
    assert d2.decision == DECISION_AUTO_SUPPRESS
    assert d2.cited_incidents == ["inc_2026_0001"]
    del mem2

    # --- Session 3: FRESH client, same technique, new user -> escalate
    mem3 = ContinuumMemory(db)
    d3 = RuleTriageAgent().triage(session3_alert, correlate(session3_alert, mem3))
    assert d3.decision == DECISION_ESCALATE
    assert d3.cited_incidents == []
    assert "NEW entity" in d3.reasoning

    # The store has exactly one incident and one journal entry + demo log
    assert mem3.count_incidents() == 1


def test_cli_demo_runs_end_to_end(tmp_path):
    """The CLI demo: session 2 runs in a real subprocess (fresh Python)."""
    repo = Path(__file__).resolve().parent.parent
    db = tmp_path / "demo.db"
    proc = subprocess.run(
        [sys.executable, "-m", "continuum.cli", "demo", "--db", str(db)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "SESSION 1" in out
    assert "SESSION 3" in out
    assert "auto_suppress" in out          # session 2, from the subprocess
    assert "inc_2026_0001" in out          # the citation survived the kill
    assert "does not inherit that clearance" in out


def test_cli_demo_wipes_stale_store(tmp_path, session1_alert):
    """A leftover db from a previous run must not leak into Session 1."""
    repo = Path(__file__).resolve().parent.parent
    db = tmp_path / "demo.db"

    # Pre-seed the db with a resolved incident — the exact footgun.
    from continuum.feedback.resolve import resolve_alert

    resolve_alert(
        ContinuumMemory(db), session1_alert,
        resolution="false_positive",
        root_cause="old run",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )

    proc = subprocess.run(
        [sys.executable, "-m", "continuum.cli", "demo", "--db", str(db)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "removed stale store" in out
    # Session 1 must be a blind escalate, not a "remembered" suppression.
    assert "decision  : escalate  (confidence 0.50)" in out
    assert "No prior context" in out
