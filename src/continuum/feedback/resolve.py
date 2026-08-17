"""Analyst feedback loop: resolution -> memory write-back.

This is the half of the product that makes memory *compound*. When an
analyst resolves an escalated alert, the outcome folds back into three
places at once:

  1. the incident itself (WARM: category="incident", single source of
     truth enforced by the SDK's UNIQUE (tenant, category, name));
  2. every entity profile involved (WARM: known_locations, incident
     history, baseline notes);
  3. the org technique stats (WARM: count + false-positive rate);
  4. the append-only journal (COLD: one write_event per resolution).

Next time the same user / technique shows up, the triage agent reads
this and decides differently. That is the whole product.
"""

from __future__ import annotations

from typing import Any

from ..memory.schema import (
    MITRE_BY_ALERT_TYPE,
    EntityProfile,
    Incident,
    TechniqueProfile,
    Alert,
    now_iso,
)
from ..memory.sibyl_client import ContinuumMemory


def resolve_alert(
    memory: ContinuumMemory,
    alert: Alert,
    *,
    resolution: str,
    root_cause: str,
    analyst_notes: str = "",
    severity_assigned: str = "medium",
    incident_id: str | None = None,
) -> Incident:
    """Resolve an alert and fold the outcome back into institutional memory."""
    incident = Incident(
        incident_id=incident_id or memory.next_incident_id(),
        timestamp=now_iso(),
        alert_type=alert.alert_type,
        entities=dict(alert.entities),
        mitre_technique=alert.mitre_technique,
        resolution=resolution,
        root_cause=root_cause,
        analyst_notes=analyst_notes,
        severity_assigned=severity_assigned,
    )
    memory.write_incident(incident)
    _update_entity_profiles(memory, alert, incident)
    _update_technique_stats(memory, alert, incident)
    memory.log_event(
        acted=[
            f"resolved {incident.incident_id} as {resolution}",
            f"root cause: {root_cause}",
        ],
        extra={"incident_id": incident.incident_id, "alert_id": alert.alert_id},
    )
    return incident


def _update_entity_profiles(memory: ContinuumMemory, alert: Alert, incident: Incident) -> None:
    for entity_type, value in alert.entities.items():
        entity_id = f"{entity_type}:{value}"
        profile = memory.get_entity_profile(entity_type, entity_id) or EntityProfile(
            entity_id=entity_id, entity_type=entity_type
        )
        if value not in profile.known_locations and entity_type in ("source_ip", "ip"):
            profile.known_locations.append(value)
        if incident.incident_id not in profile.incident_history:
            profile.incident_history.append(incident.incident_id)
        if entity_type == "user":
            profile.baseline_notes = _merge_notes(profile.baseline_notes, _user_note(incident))
        profile.updated_at = now_iso()
        memory.write_entity_profile(profile)


def _update_technique_stats(memory: ContinuumMemory, alert: Alert, incident: Incident) -> None:
    t = memory.get_technique(alert.mitre_technique) or TechniqueProfile(
        mitre_id=alert.mitre_technique, technique_name=_technique_name(alert.mitre_technique)
    )
    t.org_incident_count += 1
    if incident.resolution == "false_positive":
        t.org_false_positive_count += 1
    note = f"inc_{incident.incident_id}: {incident.resolution} — {incident.root_cause[:80]}"
    t.notes = _merge_notes(t.notes, note)
    t.updated_at = now_iso()
    memory.write_technique(t)


def _technique_name(mitre_id: str) -> str:
    return {
        "T1078": "Valid Accounts",
        "T1204": "User Execution",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1068": "Exploitation for Privilege Escalation",
        "T1566": "Phishing",
        "T1496": "Resource Hijacking",
    }.get(mitre_id, mitre_id)


def _user_note(incident: Incident) -> str:
    return f"{incident.incident_id}: {incident.resolution} — {incident.root_cause[:80]}"


def _merge_notes(existing: str, addition: str) -> str:
    if not existing:
        return addition
    if addition in existing:
        return existing
    return f"{existing} | {addition}"
