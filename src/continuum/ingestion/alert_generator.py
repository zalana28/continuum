"""Synthetic alert generator.

Produces a deterministic corpus of SOC alerts with real recurring
patterns baked in — the same contractor VPN false-positive recurring
for one user, a genuine credential-stuffing incident for another, a
first-timer who appears exactly once (the Session 3 contrast case) —
so repeat patterns actually show up in memory.

Deterministic: same seed, same corpus. Nothing here touches memory;
memory is built by *triage + resolution*, exactly like in production.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..memory.schema import MITRE_BY_ALERT_TYPE, ALERT_TYPES, Alert, now_iso

USERS = [
    "jsmith", "rpatel", "afernandez", "kliu", "tnovak",
    "mchen", "sokafor", "dgarcia", "hkim", "lweber",
    "emoreau", "bali", "fnovikov", "cchen", "jortiz",
]

HOSTS = [
    "corp-laptop-01", "corp-laptop-02", "corp-laptop-03", "corp-laptop-04",
    "corp-laptop-05", "corp-laptop-06", "corp-laptop-07", "corp-laptop-08",
    "server-web-01", "server-db-01",
]

# Contractor VPN exit range — the recurring false-positive source.
VPN_RANGE = "203.0.113."
# Office egress range — boring, usually clean.
OFFICE_RANGE = "198.51.100."
EXTERNAL_RANGES = ["45.130.8.", "91.240.5.", "185.220.101.", "162.142.125."]

DOMAINS = [
    "mega-downloads.top", "invoice-pdf-now.click", "secure-billing-portal.io",
    "cryptofaucet-giveaway.net", "docs-shared-link.ru", "vpn-update-service.com",
]

HASHES = [
    "9f4c1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f",
    "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4",
    "f0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5",
]

# The recurring actor: a contractor whose VPN exit triggers anomalous
# logins that are always false positives.
CONTRACTOR_USER = "jsmith"
CONTRACTOR_NOTE = "Contractor, engineering team, VPN egress varies"

# One genuine credential-stuffing victim, so the org has a true positive.
COMPROMISED_USER = "rpatel"


def _alert_id(seq: int) -> str:
    return f"alt_{seq:04d}"


def _ts(days_ago: int, hour: int) -> str:
    dt = datetime(2026, 9, 3, tzinfo=timezone.utc) - timedelta(days=days_ago, hours=hour % 24)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generate_alerts(count: int = 70, seed: int = 42) -> list[Alert]:
    """Deterministic corpus with structured recurring patterns."""
    rng = random.Random(seed)
    alerts: list[Alert] = []

    def add(alert_type: str, entities: dict[str, str], days_ago: int, hour: int, severity: str = "medium") -> None:
        alerts.append(
            Alert(
                alert_id=_alert_id(len(alerts) + 1),
                timestamp=_ts(days_ago, hour),
                alert_type=alert_type,
                entities=entities,
                mitre_technique=MITRE_BY_ALERT_TYPE[alert_type],
                severity=severity,
            )
        )

    # 1) Contractor VPN recurrences — jsmith, always an FP in the end.
    for i in range(6):
        add(
            "anomalous_login",
            {"user": CONTRACTOR_USER, "host": f"corp-laptop-0{i % 4 + 1}", "source_ip": f"{VPN_RANGE}{40 + i}"},
            days_ago=14 - i, hour=8 + i,
        )

    # 2) The genuine compromise — rpatel, credential stuffing.
    for i in range(3):
        add(
            "anomalous_login",
            {"user": COMPROMISED_USER, "host": "corp-laptop-02", "source_ip": EXTERNAL_RANGES[i % len(EXTERNAL_RANGES)] + "17"},
            days_ago=9 - i, hour=2 + i * 3, severity="high",
        )
    add(
        "privilege_escalation",
        {"user": COMPROMISED_USER, "host": "server-db-01", "source_ip": EXTERNAL_RANGES[0] + "17"},
        days_ago=6, hour=4, severity="high",
    )

    # 3) The Session 3 contrast case — mchen appears exactly ONCE, no history.
    add(
        "anomalous_login",
        {"user": "mchen", "host": "corp-laptop-07", "source_ip": f"{OFFICE_RANGE}23"},
        days_ago=2, hour=11, severity="high",
    )

    # 4) Organic noise — everyone else, once or twice.
    other_users = [u for u in USERS if u not in (CONTRACTOR_USER, COMPROMISED_USER, "mchen")]
    for _ in range(max(0, count - len(alerts))):
        user = rng.choice(other_users)
        alert_type = rng.choice(ALERT_TYPES)
        if alert_type == "anomalous_login":
            entities = {"user": user, "host": rng.choice(HOSTS), "source_ip": f"{OFFICE_RANGE}{rng.randint(10, 90)}"}
        elif alert_type == "malware_detected":
            entities = {"host": rng.choice(HOSTS), "hash": rng.choice(HASHES)}
        elif alert_type == "data_exfil":
            entities = {"user": user, "domain": rng.choice(DOMAINS)}
        elif alert_type == "privilege_escalation":
            entities = {"user": user, "host": rng.choice(HOSTS)}
        elif alert_type == "phishing_click":
            entities = {"user": user, "domain": rng.choice(DOMAINS)}
        else:  # crypto_miner
            entities = {"host": rng.choice(HOSTS)}
        add(alert_type, entities, days_ago=rng.randint(1, 14), hour=rng.randint(0, 23))

    # Deterministic ordering by timestamp, then id.
    alerts.sort(key=lambda a: (a.timestamp, a.alert_id))
    return alerts


def dump_alerts(alerts: list[Alert], path: str | Path) -> None:
    Path(path).write_text(json.dumps([a.to_dict() for a in alerts], indent=2) + "\n", encoding="utf-8")


def load_alerts(path: str | Path) -> list[Alert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Alert.from_dict(d) for d in data]
