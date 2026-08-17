"""Shared fixtures: a fresh memory store per test."""

import pytest

from continuum.memory.schema import Alert, Incident
from continuum.memory.sibyl_client import ContinuumMemory


@pytest.fixture()
def memory(tmp_path):
    return ContinuumMemory(tmp_path / "test.db")


@pytest.fixture()
def session1_alert():
    return Alert(
        alert_id="alt_session1",
        timestamp="2026-09-03T14:22:00Z",
        alert_type="anomalous_login",
        entities={"user": "jsmith", "host": "corp-laptop-04", "source_ip": "203.0.113.44"},
        mitre_technique="T1078",
        severity="medium",
    )


@pytest.fixture()
def session2_alert():
    return Alert(
        alert_id="alt_session2",
        timestamp="2026-09-05T09:10:00Z",
        alert_type="anomalous_login",
        entities={"user": "jsmith", "host": "corp-laptop-04", "source_ip": "203.0.113.77"},
        mitre_technique="T1078",
        severity="medium",
    )


@pytest.fixture()
def session3_alert():
    return Alert(
        alert_id="alt_session3",
        timestamp="2026-09-06T11:45:00Z",
        alert_type="anomalous_login",
        entities={"user": "mchen", "host": "corp-laptop-07", "source_ip": "198.51.100.23"},
        mitre_technique="T1078",
        severity="high",
    )


def make_incident(incident_id: str, alert: Alert, resolution: str = "false_positive", root_cause: str = "x"):
    return Incident(
        incident_id=incident_id,
        timestamp="2026-09-04T10:00:00Z",
        alert_type=alert.alert_type,
        entities=dict(alert.entities),
        mitre_technique=alert.mitre_technique,
        resolution=resolution,
        root_cause=root_cause,
        analyst_notes="",
        severity_assigned="low",
    )
