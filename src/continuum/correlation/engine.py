"""Correlation engine: alert -> memory context.

Takes a raw alert, pulls every piece of institutional memory that could
possibly bear on it, and hands the triage agent a ranked context:

  1. exact entity matches — incidents involving the same user/host/IP;
  2. technique-level pattern — org-wide stats for the MITRE technique;
  3. recent journal — what the team has been doing lately.

This is the "isn't this just a lookup table?" answer: Session 3 of the
demo (same technique, brand-new user) is decided by *structured memory
reasoning* — entity history says nothing, technique stats say "mostly
false positives but don't blind-reuse the contractor's clearance".
"""

from __future__ import annotations

from typing import Any

from ..memory.schema import Alert, Incident, MemoryContext
from ..memory.sibyl_client import ContinuumMemory, MemoryUnavailable


def correlate(alert: Alert, memory: ContinuumMemory | None) -> MemoryContext:
    """Retrieve everything memory knows about this alert.

    ``memory=None`` (or a NullMemory) is the deletion test: the same
    correlation returns an empty context and triage goes blind.
    """
    if memory is None:
        return MemoryContext(summary="NO MEMORY — deletion test: every alert looks identical.")

    entity_hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in alert.entity_values:
        try:
            incidents = memory.incidents_for_entity(value)
        except MemoryUnavailable:
            return MemoryContext(summary="NO MEMORY — deletion test: every alert looks identical.")
        if incidents:
            key = (value, incidents[0].incident_id)
            if key in seen:
                continue
            seen.add(key)
            entity_hits.append(
                {
                    "entity_value": value,
                    "incidents": [i.to_dict() for i in incidents],
                }
            )

    # Technique-level pattern across different entities.
    try:
        technique = memory.get_technique(alert.mitre_technique)
    except MemoryUnavailable:
        technique = None

    recent = []
    try:
        recent = memory.recent_events(limit=20)
    except MemoryUnavailable:
        recent = []

    if entity_hits or technique:
        summary = _summarize(alert, entity_hits, technique)
    else:
        summary = "No prior context found in institutional memory."

    return MemoryContext(
        entity_hits=entity_hits,
        technique=technique,
        recent_events=recent,
        summary=summary,
    )


def _summarize(alert: Alert, entity_hits: list[dict[str, Any]], technique: Any) -> str:
    parts: list[str] = []
    for hit in entity_hits:
        incs = [Incident.from_dict(i) for i in hit["incidents"]]
        cleared = [i for i in incs if i.resolution == "false_positive"]
        if cleared:
            ids = ", ".join(sorted({i.incident_id for i in cleared}))
            parts.append(f"entity '{hit['entity_value']}' has cleared incident(s) {ids}")
        else:
            ids = ", ".join(sorted({i.incident_id for i in incs}))
            parts.append(f"entity '{hit['entity_value']}' has unresolved history {ids}")
    if technique is not None:
        parts.append(
            f"technique {technique.mitre_id} ({technique.technique_name}): "
            f"{technique.org_incident_count} incident(s), "
            f"{technique.org_false_positive_rate:.0%} org false-positive rate"
        )
    return "; ".join(parts)
