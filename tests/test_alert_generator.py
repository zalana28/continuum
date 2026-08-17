"""Alert generator: deterministic, structured recurring patterns."""

from continuum.ingestion.alert_generator import generate_alerts


def test_deterministic_same_seed():
    a = generate_alerts(count=70, seed=42)
    b = generate_alerts(count=70, seed=42)
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]


def test_deterministic_different_seed():
    a = generate_alerts(count=70, seed=42)
    b = generate_alerts(count=70, seed=7)
    assert [x.to_dict() for x in a] != [x.to_dict() for x in b]


def test_count_and_types():
    alerts = generate_alerts(count=70, seed=42)
    assert len(alerts) == 70
    assert all(a.alert_type in ("anomalous_login", "malware_detected", "data_exfil",
                                "privilege_escalation", "phishing_click", "crypto_miner") for a in alerts)
    assert len({a.alert_type for a in alerts}) == 6  # all six types appear


def test_recurring_patterns_are_baked_in():
    alerts = generate_alerts(count=70, seed=42)
    jsmith = [a for a in alerts if a.entities.get("user") == "jsmith"]
    rpatel = [a for a in alerts if a.entities.get("user") == "rpatel"]
    mchen = [a for a in alerts if a.entities.get("user") == "mchen"]
    assert len(jsmith) >= 5          # the recurring contractor pattern
    assert len(rpatel) >= 3          # the genuine compromise
    assert len(mchen) == 1           # the Session 3 contrast: exactly one sighting
    assert all(a.entities["source_ip"].startswith("203.0.113.") for a in jsmith)


def test_timestamps_sorted():
    alerts = generate_alerts(count=70, seed=42)
    stamps = [a.timestamp for a in alerts]
    assert stamps == sorted(stamps)
