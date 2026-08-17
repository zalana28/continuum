"""Correlation: alert -> memory context, with and without memory."""

from continuum.correlation.engine import correlate
from tests.conftest import make_incident


def test_empty_memory_yields_empty_context(session1_alert, memory):
    ctx = correlate(session1_alert, memory)
    assert ctx.is_empty()
    assert "No prior context" in ctx.summary


def test_no_memory_object_yields_deletion_context(session1_alert):
    ctx = correlate(session1_alert, None)
    assert ctx.is_empty()
    assert "NO MEMORY" in ctx.summary


def test_entity_hit_and_cited_ids(session1_alert, session2_alert, memory):
    memory.write_incident(make_incident("inc_2026_0001", session1_alert))
    ctx = correlate(session2_alert, memory)
    assert not ctx.is_empty()
    assert ctx.cited_incident_ids == ["inc_2026_0001"]
    assert any(hit["entity_value"] == "jsmith" for hit in ctx.entity_hits)
    # summary mentions the cleared incident
    assert "inc_2026_0001" in ctx.summary


def test_technique_stats_surface_for_new_entity(session3_alert, session1_alert, memory):
    # Seed memory the production way: an analyst resolved session1.
    from continuum.feedback.resolve import resolve_alert

    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node",
        severity_assigned="low",
        incident_id="inc_2026_0001",
    )
    ctx = correlate(session3_alert, memory)
    assert ctx.technique is not None
    assert ctx.technique.mitre_id == "T1078"
    # mchen has no entity history
    assert ctx.entity_hits == []
    assert not ctx.is_empty()  # technique alone keeps it non-empty
