"""The SDK facade: write, read, recall, journal, archive."""

from continuum.memory.schema import EntityProfile, TechniqueProfile
from continuum.memory.sibyl_client import ContinuumMemory, MemoryUnavailable, NullMemory
from tests.conftest import make_incident


def test_incident_write_and_read_back(memory, session1_alert):
    inc = make_incident("inc_2026_0001", session1_alert)
    memory.write_incident(inc)
    got = memory.get_incident("inc_2026_0001")
    assert got == inc
    assert memory.get_incident("inc_2026_9999") is None


def test_next_incident_id_is_sequential(memory, session1_alert):
    assert memory.next_incident_id() == "inc_2026_0001"
    memory.write_incident(make_incident("inc_2026_0001", session1_alert))
    assert memory.next_incident_id() == "inc_2026_0002"


def test_fts5_recall_finds_incidents_by_entity_value(memory, session1_alert):
    memory.write_incident(make_incident("inc_2026_0001", session1_alert, root_cause="Contractor VPN"))
    hits = memory.incidents_for_entity("jsmith")
    assert [i.incident_id for i in hits] == ["inc_2026_0001"]
    # FTS5 also matches inside the body, e.g. the root cause.
    hits = memory.incidents_for_entity("Contractor")
    assert [i.incident_id for i in hits] == ["inc_2026_0001"]
    # And an unknown value matches nothing.
    assert memory.incidents_for_entity("mchen") == []


def test_recall_returns_newest_first(memory, session1_alert, session2_alert):
    old = make_incident("inc_2026_0001", session1_alert)
    old.timestamp = "2026-09-03T00:00:00Z"
    new = make_incident("inc_2026_0002", session2_alert)
    new.timestamp = "2026-09-05T00:00:00Z"
    memory.write_incident(old)
    memory.write_incident(new)
    hits = memory.incidents_for_entity("jsmith")
    assert [i.incident_id for i in hits] == ["inc_2026_0002", "inc_2026_0001"]


def test_entity_profiles_and_technique_roundtrip(memory):
    profile = EntityProfile(
        entity_id="user:jsmith",
        entity_type="user",
        known_locations=["203.0.113.44"],
        incident_history=["inc_2026_0001"],
        baseline_notes="Contractor",
    )
    memory.write_entity_profile(profile)
    assert memory.get_entity_profile("user", "user:jsmith") == profile
    assert memory.get_entity_profile("user", "user:nobody") is None

    tech = TechniqueProfile(mitre_id="T1078", technique_name="Valid Accounts", org_incident_count=4)
    memory.write_technique(tech)
    got = memory.get_technique("T1078")
    assert got == tech
    assert got.org_false_positive_rate == 0.0
    assert memory.get_technique("T9999") is None


def test_journal_is_append_only(memory):
    id1 = memory.log_event(acted=["triaged alt_x"], extra={"incident_id": "inc_1"})
    id2 = memory.log_event(acted=["resolved inc_1"], extra={"incident_id": "inc_1"})
    events = memory.recent_events(limit=10)
    assert [e["id"] for e in events] == [id2, id1]  # newest first
    assert events[1]["acted"] == ["triaged alt_x"]
    assert events[1]["extra"]["incident_id"] == "inc_1"


def test_archive_moves_entity_out_of_active_set(memory, session1_alert):
    memory.write_incident(make_incident("inc_2026_0001", session1_alert))
    assert memory.count_incidents() == 1
    memory.archive_entity("incident", "inc_2026_0001", reason="demo")
    # Out of the active set: no longer counted or retrievable via get_entity
    # (the SDK moves the row to the archive table, off the read path).
    assert memory.count_incidents() == 0
    assert memory.get_incident("inc_2026_0001") is None


def test_null_memory_is_the_deletion_test():
    null = NullMemory()
    with __import__("pytest").raises(MemoryUnavailable):
        null.incidents_for_entity("jsmith")
    with __import__("pytest").raises(MemoryUnavailable):
        null.get_technique("T1078")
    assert null.status()["memory_present"] is False


def test_status_shape(memory):
    status = memory.status()
    assert status["db_path"].endswith("test.db")
    assert status["tier"] == "free"
    assert status["incidents"] == 0
    assert status["entities"] == 0
    assert status["journal_events"] == 0
