# Continuum demo — the script (2–5 minute video)

Judges are told to look for three things, in order:
**persist → recall in a genuinely fresh session → change a decision.**
This script makes all three unmistakable. One continuous, unedited
segment — no cuts between the two sessions. Keep an on-screen timestamp
or commit hash visible during the recall beat (e.g. run `date` in the
terminal, or keep the terminal prompt with its timestamp on screen).

---

## 0. Preparation (before recording)

```bash
cd continuum
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
date                              # on-screen timestamp for the recall beat
```

`continuum demo` wipes its own store first, so the demo always starts
from a truly empty memory (a stale db would make Session 1 "remember"
things it shouldn't).

## 1. Session 1 — first encounter, memory is empty (00:00–01:00)

```bash
continuum demo
```

Actually no — run the demo step by step so the script stays honest:

```bash
continuum triage demo/alerts_session1.json --db demo/demo_memory.db
```

Expected output:

```
decision  : escalate  (confidence 0.50)
reasoning : No prior context for this anomalous_login alert (T1078).
            Novel pattern — escalate for manual review.
```

Narrate: *"First alert for user jsmith from a new IP. Continuum has no
history for this org yet — blind escalate, exactly like a generic SIEM."*

Now the analyst resolves it — the write-back that creates institutional
memory:

```bash
continuum resolve demo/alerts_session1.json --db demo/demo_memory.db
# resolution: false_positive
# root cause: Contractor VPN exit node, pre-approved by IT on 2026-08-20
# notes:      Recurring pattern for this contractor
# severity:   low
```

Expected output: `written to memory: inc_2026_0001` plus the four
write-backs (incident entity, entity profiles, technique stats, journal).

## 2. KILL THE PROCESS — the honest fresh-session beat (01:00–01:30)

```bash
exit          # or Cmd-Q the terminal. The process is GONE.
```

Open a brand-new terminal. Zero chat history, zero in-context carryover.
Prove it on camera: new shell, `date` visible, no scrollback.

## 3. Session 2 — fresh process, same disk (01:30–02:30)

```bash
cd continuum && source .venv/bin/activate
date
continuum triage demo/alerts_session2.json --db demo/demo_memory.db
```

Expected output:

```
decision  : auto_suppress  (confidence 0.90)
cites     : inc_2026_0001
reasoning : Matches cleared incident(s) inc_2026_0001 — same
            anomalous_login pattern for a known entity.
            Auto-suppressing; logged for audit.
```

Narrate: *"Same user, similar login anomaly, different day. The process
was killed and restarted. The only thing that survived is the memory
file on disk — and because of it, this alert is auto-suppressed and the
analyst never sees it. This is the load-bearing moment."*

## 4. Session 3 — the contrast case (02:30–03:30)

```bash
continuum triage demo/alerts_session3.json --db demo/demo_memory.db
```

Expected output:

```
decision  : escalate  (confidence 0.60)
reasoning : No entity history for this alert's entities. Org-wide T1078
            (Valid Accounts) shows 1 incident(s), 100% org false-positive
            rate — but this is a NEW entity for this pattern, so it does
            not inherit that clearance. Escalate for review.
```

Narrate: *"Same technique, brand-new user. The org has a 100%
false-positive rate on T1078 — but mchen has no history, so Continuum
does NOT blind-reuse jsmith's clearance. It escalates, with context.
This is structured memory reasoning, not a lookup table."*

## 5. The deletion test — the eligibility gate (03:30–04:30)

```bash
continuum triage demo/alerts_session2.json --no-memory
```

Expected output:

```
decision  : escalate  (confidence 0.50)
reasoning : No prior context for this anomalous_login alert (T1078).
            Novel pattern — escalate for manual review.
```

Narrate: *"Same alert that was auto-suppressed a minute ago. Delete the
memory layer — the core function breaks. Every alert looks identical
again. That is the gate."*

Then show where the memory calls live (under two minutes for a judge):

```bash
grep -rn "search_entities\|set_entity\|write_event" src/continuum/memory/sibyl_client.py
```

## 6. Close (04:30–05:00)

- What it is: SOC triage that remembers the org's own history.
- Why memory is load-bearing: the deletion test you just watched.
- Where: `src/continuum/memory/sibyl_client.py` is the only file that
  touches the SDK; the correlation engine (`src/continuum/correlation/engine.py`)
  reads it; the triage agent (`src/continuum/agent/triage_agent.py`)
  decides with it.
- The team problem it solves: analyst turnover — the three-year
  analyst's tacit knowledge, made persistent and queryable.
