"""Triage: the three sessions, the deletion test, and fail-closed LLM citations."""

import json

from continuum.agent.triage_agent import LLMTriageAgent, RuleTriageAgent, correlate, triage_alert
from continuum.memory.schema import DECISION_AUTO_SUPPRESS, DECISION_ESCALATE, DECISION_REVIEW_WITH_CONTEXT
from tests.conftest import make_incident


def test_session1_no_memory_escalates_blind(session1_alert, memory):
    decision = triage_alert(session1_alert, memory)
    assert decision.decision == DECISION_ESCALATE
    assert decision.cited_incidents == []
    assert "No prior context" in decision.reasoning


def test_session2_fresh_client_auto_suppresses(session1_alert, session2_alert, memory):
    memory.write_incident(make_incident("inc_2026_0001", session1_alert))
    # A brand-new client on the same db = fresh process semantics.
    from continuum.memory.sibyl_client import ContinuumMemory
    import os

    fresh = ContinuumMemory(os.path.join(os.path.dirname(memory.db_path), "test.db"))
    decision = triage_alert(session2_alert, fresh)
    assert decision.decision == DECISION_AUTO_SUPPRESS
    assert decision.cited_incidents == ["inc_2026_0001"]
    assert "inc_2026_0001" in decision.reasoning
    assert decision.confidence == 0.9


def test_session3_new_user_does_not_inherit_clearance(session1_alert, session3_alert, memory):
    from continuum.feedback.resolve import resolve_alert

    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )
    decision = triage_alert(session3_alert, memory)
    # Same technique as the cleared incident, but NOT auto-suppressed.
    assert decision.decision == DECISION_ESCALATE
    assert decision.cited_incidents == []
    assert "NEW entity" in decision.reasoning
    assert "false-positive rate" in decision.reasoning


def test_review_with_context_when_history_exists_but_nothing_cleared(session1_alert, session2_alert, memory):
    inc = make_incident("inc_2026_0001", session1_alert, resolution="true_positive", root_cause="real compromise")
    memory.write_incident(inc)
    decision = triage_alert(session2_alert, memory)
    assert decision.decision == DECISION_REVIEW_WITH_CONTEXT
    assert decision.cited_incidents == ["inc_2026_0001"]


def test_deletion_test_memory_none(session2_alert):
    decision = triage_alert(session2_alert, None)
    assert decision.decision == DECISION_ESCALATE
    assert decision.cited_incidents == []
    assert "No prior context" in decision.reasoning


def test_deletion_test_null_memory(session2_alert):
    from continuum.memory.sibyl_client import NullMemory

    decision = triage_alert(session2_alert, NullMemory())
    assert decision.decision == DECISION_ESCALATE
    assert "No prior context" in decision.reasoning


class FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_llm_agent_citations_are_fail_closed(session1_alert, session2_alert, memory, monkeypatch):
    from continuum.feedback.resolve import resolve_alert

    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )
    ctx = correlate(session2_alert, memory)
    assert ctx.cited_incident_ids == ["inc_2026_0001"]

    def fake_urlopen(req, timeout=None):
        return FakeResp(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "decision": DECISION_AUTO_SUPPRESS,
                                    "confidence": 0.87,
                                    "reasoning": "same contractor pattern",
                                    # One real id, one hallucinated.
                                    "cited_incidents": ["inc_2026_0001", "inc_9999_9999"],
                                }
                            )
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr("continuum.agent.triage_agent.urllib.request.urlopen", fake_urlopen)
    agent = LLMTriageAgent(api_key="test-key", base_url="http://fake", model="fake")
    decision = agent.triage(session2_alert, ctx)
    assert decision.decision == DECISION_AUTO_SUPPRESS
    assert decision.confidence == 0.87
    # The hallucinated id is dropped; only the retrieved one survives.
    assert decision.cited_incidents == ["inc_2026_0001"]


def test_llm_agent_falls_back_to_rules_on_failure(session1_alert, memory):
    agent = LLMTriageAgent(api_key="test-key", base_url="http://127.0.0.1:1", model="fake")
    # Port 1 refuses connections -> fallback path.
    decision = agent.triage(session1_alert, correlate(session1_alert, memory))
    assert decision.decision == DECISION_ESCALATE
    assert "rule fallback" in decision.reasoning


def test_rule_agent_is_deterministic(session1_alert, memory):
    a = RuleTriageAgent().triage(session1_alert, correlate(session1_alert, memory))
    b = RuleTriageAgent().triage(session1_alert, correlate(session1_alert, memory))
    assert a.to_dict() == b.to_dict()
