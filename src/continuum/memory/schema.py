"""Typed schemas for everything Continuum stores or reasons about.

Single source of truth for record shapes across ingestion, correlation,
triage and feedback. The Sibyl Memory SDK enforces uniqueness at the
(tenant_id, category, name) level; these dataclasses enforce shape at
the application level — no untyped dicts cross module boundaries.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

ALERT_TYPES = (
    "anomalous_login",
    "malware_detected",
    "data_exfil",
    "privilege_escalation",
    "phishing_click",
    "crypto_miner",
)

MITRE_BY_ALERT_TYPE = {
    "anomalous_login": "T1078",
    "malware_detected": "T1204",
    "data_exfil": "T1048",
    "privilege_escalation": "T1068",
    "phishing_click": "T1566",
    "crypto_miner": "T1496",
}

INCIDENT_ID_RE = re.compile(r"^inc_\d{4}_\d{4}$")

RESOLUTIONS = ("true_positive", "false_positive", "duplicate")

DECISION_AUTO_SUPPRESS = "auto_suppress"
DECISION_REVIEW_WITH_CONTEXT = "review_with_context"
DECISION_ESCALATE = "escalate"
DECISIONS = (DECISION_AUTO_SUPPRESS, DECISION_REVIEW_WITH_CONTEXT, DECISION_ESCALATE)


def now_iso() -> str:
    """UTC timestamp in the same shape the Sibyl SDK uses (…Z)."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_identifier(value: str, what: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{what} must be a non-empty string")
    if len(value) > 200:
        raise ValueError(f"{what} too long ({len(value)} chars)")


@dataclass
class Alert:
    """A raw alert from the (simulated) SIEM/EDR source."""

    alert_id: str
    timestamp: str
    alert_type: str
    entities: dict[str, str]
    mitre_technique: str
    severity: str = "medium"

    def __post_init__(self) -> None:
        _validate_identifier(self.alert_id, "alert_id")
        if self.alert_type not in ALERT_TYPES:
            raise ValueError(f"unknown alert_type {self.alert_type!r}; expected one of {ALERT_TYPES}")
        if not self.entities:
            raise ValueError("alert must carry at least one entity")
        _validate_identifier(self.mitre_technique, "mitre_technique")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        return cls(
            alert_id=data["alert_id"],
            timestamp=data["timestamp"],
            alert_type=data["alert_type"],
            entities=dict(data["entities"]),
            mitre_technique=data["mitre_technique"],
            severity=data.get("severity", "medium"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def entity_values(self) -> list[str]:
        return sorted(set(v for v in self.entities.values() if v))


@dataclass
class Incident:
    """A resolved incident — the org's institutional memory of one alert."""

    incident_id: str
    timestamp: str
    alert_type: str
    entities: dict[str, str]
    mitre_technique: str
    resolution: str
    root_cause: str
    analyst_notes: str = ""
    severity_assigned: str = "medium"

    def __post_init__(self) -> None:
        if not INCIDENT_ID_RE.match(self.incident_id):
            raise ValueError(f"invalid incident_id {self.incident_id!r}; expected inc_YYYY_NNNN")
        if self.resolution not in RESOLUTIONS:
            raise ValueError(f"unknown resolution {self.resolution!r}; expected one of {RESOLUTIONS}")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Incident":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntityProfile:
    """WARM-tier profile for a user/host/IP: everything we know about it."""

    entity_id: str  # e.g. "user:jsmith" — the (category, name) for set_entity
    entity_type: str  # "user" | "host" | "ip" | "domain" | "hash"
    known_locations: list[str] = field(default_factory=list)
    incident_history: list[str] = field(default_factory=list)
    baseline_notes: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EntityProfile":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TechniqueProfile:
    """WARM-tier aggregate stats per MITRE technique, org-specific."""

    mitre_id: str  # e.g. "T1078"
    technique_name: str
    org_incident_count: int = 0
    org_false_positive_count: int = 0
    notes: str = ""
    updated_at: str = ""

    @property
    def org_false_positive_rate(self) -> float:
        if self.org_incident_count == 0:
            return 0.0
        return self.org_false_positive_count / self.org_incident_count

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TechniqueProfile":
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MemoryContext:
    """What the correlation engine retrieved from memory for one alert."""

    entity_hits: list[dict[str, Any]] = field(default_factory=list)
    technique: TechniqueProfile | None = None
    recent_events: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    def is_empty(self) -> bool:
        return not self.entity_hits and self.technique is None

    @property
    def cited_incident_ids(self) -> list[str]:
        ids: set[str] = set()
        for hit in self.entity_hits:
            for inc in hit.get("incidents", []):
                ids.add(inc["incident_id"])
        return sorted(ids)


@dataclass
class TriageDecision:
    """Structured output of the triage agent."""

    decision: str
    confidence: float
    reasoning: str
    cited_incidents: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.decision not in DECISIONS:
            raise ValueError(f"unknown decision {self.decision!r}; expected one of {DECISIONS}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")
        self.cited_incidents = sorted(set(self.cited_incidents))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
