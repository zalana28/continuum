"""The ONLY module in the codebase that touches the Sibyl Memory SDK.

Everything else talks to :class:`ContinuumMemory`. Swap the SDK, move to a
managed tier, or run without memory in tests — you touch exactly this file.

Tier mapping (Sibyl Memory 5-tier schema, verified against
sibyl-memory-client 0.6.1):

    WARM  entities/   incidents -> category="incident", name=incident_id
                       profiles -> category="user"|"host"|"ip"|"domain"|"hash",
                                   name=entity_id ("user:jsmith")
                       techniques -> category="technique", name=mitre_id
    COLD  journal/    every triage + resolution, append-only (write_event)
    HOT   state/      org context (industry, analyst count)
    REFERENCE         playbooks / static notes (set_reference)
    ARCHIVE           retired entities (archive_entity)

Uniqueness of (category, name) is enforced by the SDK schema itself
(UNIQUE (tenant_id, category, name)) — a second incident with the same id
is impossible by construction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sibyl_memory_client import MemoryClient, NotFoundError

from .schema import EntityProfile, Incident, TechniqueProfile, now_iso

CAT_INCIDENT = "incident"
CAT_TECHNIQUE = "technique"

DEFAULT_DB_PATH = "~/.sibyl-memory/continuum.db"


class MemoryUnavailable(RuntimeError):
    """Raised when a memory operation is attempted but no store exists.

    The CLI uses this to run the *deletion test*: point the same alert at
    a run with no memory and watch triage go blind.
    """


class ContinuumMemory:
    """Application-level facade over the Sibyl Memory SDK.

    A fresh instance always reads from disk — there is no in-memory
    carryover, which is exactly what makes the fresh-session recall demo
    honest: kill the process, open a new one, the memory is still there.
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = str(Path(db_path).expanduser())
        self._mc = MemoryClient.local(self.db_path)

    # ------------------------------------------------------------------
    # Incidents (WARM tier, category="incident")
    # ------------------------------------------------------------------

    def write_incident(self, incident: Incident) -> None:
        self._mc.set_entity(CAT_INCIDENT, incident.incident_id, incident.to_dict())

    def get_incident(self, incident_id: str) -> Incident | None:
        try:
            row = self._mc.get_entity(CAT_INCIDENT, incident_id)
        except NotFoundError:
            return None
        return Incident.from_dict(row["body"])

    def count_incidents(self) -> int:
        return len(self._mc.list_entities(CAT_INCIDENT, limit=1000))

    def next_incident_id(self) -> str:
        """Sequential, deterministic ids: inc_<year>_<0001>…"""
        year = now_iso()[:4]
        return f"inc_{year}_{self.count_incidents() + 1:04d}"

    # ------------------------------------------------------------------
    # Entity profiles (WARM tier, category = entity_type)
    # ------------------------------------------------------------------

    def write_entity_profile(self, profile: EntityProfile) -> None:
        self._mc.set_entity(profile.entity_type, profile.entity_id, profile.to_dict())

    def get_entity_profile(self, entity_type: str, entity_id: str) -> EntityProfile | None:
        try:
            row = self._mc.get_entity(entity_type, entity_id)
        except NotFoundError:
            return None
        return EntityProfile.from_dict(row["body"])

    # ------------------------------------------------------------------
    # Technique stats (WARM tier, category="technique")
    # ------------------------------------------------------------------

    def write_technique(self, profile: TechniqueProfile) -> None:
        self._mc.set_entity(CAT_TECHNIQUE, profile.mitre_id, profile.to_dict())

    def get_technique(self, mitre_id: str) -> TechniqueProfile | None:
        try:
            row = self._mc.get_entity(CAT_TECHNIQUE, mitre_id)
        except NotFoundError:
            return None
        return TechniqueProfile.from_dict(row["body"])

    # ------------------------------------------------------------------
    # Recall (FTS5 across the WARM tier)
    # ------------------------------------------------------------------

    def incidents_for_entity(self, entity_value: str, limit: int = 25) -> list[Incident]:
        """All incidents mentioning this entity value, newest first.

        This is the recall path the correlation engine lives on: FTS5
        full-text search over incident bodies, filtered to the incident
        category, ranked by recency. No embeddings, no vector index.
        """
        rows = self._mc.search_entities(entity_value, category=CAT_INCIDENT, limit=limit)
        incidents = [Incident.from_dict(r["body"]) for r in rows]
        return sorted(incidents, key=lambda i: i.timestamp, reverse=True)

    # ------------------------------------------------------------------
    # Journal (COLD tier) — the append-only audit log
    # ------------------------------------------------------------------

    def log_event(self, acted: list[str], extra: dict[str, Any] | None = None) -> str:
        return self._mc.write_event(acted=acted, extra=extra)

    def recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._mc.read_events(limit=limit)

    # ------------------------------------------------------------------
    # Org state (HOT tier) + reference (REFERENCE tier)
    # ------------------------------------------------------------------

    def set_org_state(self, key: str, body: dict[str, Any]) -> None:
        self._mc.set_state(key, body)

    def get_org_state(self, key: str) -> dict[str, Any] | None:
        return self._mc.get_state(key)

    def set_reference(self, key: str, body: str | dict[str, Any]) -> None:
        self._mc.set_reference(key, body)

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    def archive_entity(self, entity_type: str, entity_id: str, reason: str | None = None) -> None:
        """Retire an entity: the SDK moves it to the archive table (off the
        active read path — get_entity no longer returns it)."""
        self._mc.archive_entity(entity_type, entity_id, reason=reason)

    def status(self) -> dict[str, Any]:
        return {
            "db_path": self.db_path,
            "tier": self._mc.get_tier(),
            "incidents": self.count_incidents(),
            "entities": len(self._mc.list_entities(limit=1000)),
            "journal_events": len(self._mc.read_events(limit=1000)),
        }


class NullMemory(ContinuumMemory):
    """The deletion test, as a class: every memory read returns nothing.

    Feed the same alert to the same triage agent with this store and the
    core function (institutional triage) visibly breaks — that contrast,
    on camera, is the eligibility gate.
    """

    def __init__(self) -> None:  # noqa: D107 — nothing to open
        self.db_path = "<none>"

    def _unavailable(self) -> None:
        raise MemoryUnavailable("memory layer deleted — this is the deletion test")

    def get_incident(self, incident_id: str) -> Incident | None:
        self._unavailable()

    def incidents_for_entity(self, entity_value: str, limit: int = 25) -> list[Incident]:
        self._unavailable()

    def get_technique(self, mitre_id: str) -> TechniqueProfile | None:
        self._unavailable()

    def recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        self._unavailable()

    def status(self) -> dict[str, Any]:
        return {"db_path": self.db_path, "tier": "none", "memory_present": False}
