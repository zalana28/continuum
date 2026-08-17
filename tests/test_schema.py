"""Schema validation — typed records reject garbage at the boundary."""

import pytest

from continuum.memory.schema import (
    Alert,
    Incident,
    TriageDecision,
    DECISION_ESCALATE,
)


def test_alert_rejects_unknown_type():
    with pytest.raises(ValueError, match="unknown alert_type"):
        Alert(
            alert_id="alt_1",
            timestamp="2026-09-03T00:00:00Z",
            alert_type="not_a_thing",
            entities={"user": "x"},
            mitre_technique="T1078",
        )


def test_alert_rejects_empty_entities():
    with pytest.raises(ValueError, match="at least one entity"):
        Alert(
            alert_id="alt_1",
            timestamp="2026-09-03T00:00:00Z",
            alert_type="anomalous_login",
            entities={},
            mitre_technique="T1078",
        )


def test_alert_roundtrip():
    a = Alert(
        alert_id="alt_1",
        timestamp="2026-09-03T00:00:00Z",
        alert_type="anomalous_login",
        entities={"user": "jsmith"},
        mitre_technique="T1078",
    )
    assert Alert.from_dict(a.to_dict()) == a
    assert a.entity_values == ["jsmith"]


def test_incident_rejects_bad_id_and_resolution():
    with pytest.raises(ValueError, match="invalid incident_id"):
        Incident(
            incident_id="nope",
            timestamp="2026-09-03T00:00:00Z",
            alert_type="anomalous_login",
            entities={"user": "x"},
            mitre_technique="T1078",
            resolution="false_positive",
            root_cause="x",
        )
    with pytest.raises(ValueError, match="unknown resolution"):
        Incident(
            incident_id="inc_2026_0001",
            timestamp="2026-09-03T00:00:00Z",
            alert_type="anomalous_login",
            entities={"user": "x"},
            mitre_technique="T1078",
            resolution="maybe",
            root_cause="x",
        )


def test_triage_decision_validates_and_dedupes_citations():
    d = TriageDecision(decision=DECISION_ESCALATE, confidence=0.5, reasoning="r", cited_incidents=["b", "a", "b"])
    assert d.cited_incidents == ["a", "b"]
    with pytest.raises(ValueError):
        TriageDecision(decision="nope", confidence=0.5, reasoning="r")
    with pytest.raises(ValueError):
        TriageDecision(decision=DECISION_ESCALATE, confidence=1.5, reasoning="r")
