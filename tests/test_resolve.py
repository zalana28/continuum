"""Feedback loop: resolution folds back into all four memory surfaces."""

from continuum.feedback.resolve import resolve_alert
from continuum.memory.schema import EntityProfile


def test_resolve_writes_incident_and_returns_it(memory, session1_alert):
    inc = resolve_alert(
        memory,
        session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node",
        analyst_notes="recurring",
        severity_assigned="low",
    )
    assert inc.incident_id == "inc_2026_0001"
    assert memory.get_incident("inc_2026_0001") == inc


def test_resolve_updates_entity_profiles(memory, session1_alert):
    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN exit node",
        analyst_notes="recurring",
        severity_assigned="low",
    )
    user = memory.get_entity_profile("user", "user:jsmith")
    assert isinstance(user, EntityProfile)
    assert user.incident_history == ["inc_2026_0001"]
    assert "inc_2026_0001" in user.baseline_notes
    host = memory.get_entity_profile("host", "host:corp-laptop-04")
    assert host is not None
    assert host.incident_history == ["inc_2026_0001"]


def test_resolve_updates_technique_stats(memory, session1_alert):
    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN",
        severity_assigned="low",
    )
    tech = memory.get_technique("T1078")
    assert tech is not None
    assert tech.org_incident_count == 1
    assert tech.org_false_positive_count == 1
    assert tech.org_false_positive_rate == 1.0

    # A true positive on the same technique changes the rate.
    resolve_alert(
        memory, session1_alert,
        resolution="true_positive",
        root_cause="real compromise",
        severity_assigned="high",
    )
    tech = memory.get_technique("T1078")
    assert tech.org_incident_count == 2
    assert tech.org_false_positive_rate == 0.5


def test_resolve_appends_journal(memory, session1_alert):
    resolve_alert(
        memory, session1_alert,
        resolution="false_positive",
        root_cause="Contractor VPN",
        severity_assigned="low",
    )
    events = memory.recent_events(limit=5)
    assert len(events) == 1
    assert "resolved inc_2026_0001 as false_positive" in events[0]["acted"][0]
    assert events[0]["extra"]["incident_id"] == "inc_2026_0001"
