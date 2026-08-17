# Continuum — SOC triage agent with institutional memory

**One-liner:** Continuum doesn't just score today's alert — it remembers
every incident this organization has ever resolved, and that memory
changes what it does with the next one.

Built for the Sibyl Labs Hackathon (build window Sep 1–10, 2026) on
[Sibyl Memory](https://docs.sibyllabs.org/memory/) — a local-first,
file-based agentic memory (SQLite + FTS5, zero embeddings).

---

## The problem

SIEM/EDR tools score alerts against generic rules or global threat
feeds. They have no memory of *this organization's* history. A
three-year analyst knows *"we've seen this from this laptop before — it
was a VPN misconfig."* That tacit knowledge lives in people's heads and
walks out the door when they leave.

Continuum makes that knowledge persistent and queryable:

- Every alert is triaged against the org's **own incident history**, not
  a generic feed.
- Every resolved incident (true/false positive + root cause) is written
  back to memory.
- In a **totally fresh session** — no chat history, no in-context
  carryover — a new alert gets matched against that memory and triaged
  *differently because of* what happened before.

## How it works

```
alert ──▶ correlation engine ──▶ Sibyl Memory (5 tiers)
              │                        ▲
              ▼                        │
         triage agent ──▶ decision     │
              │                        │
         auto_suppress / review / escalate
              │                        │
         analyst resolution ──────────┘  (write-back: incident,
                                           entity profiles, technique
                                           stats, journal)
```

Sibyl Memory tier mapping:

| Tier    | Continuum use                                                    |
|---------|-------------------------------------------------------------------|
| WARM    | incidents (`category="incident"`), entity profiles (`user`/`host`/`ip`), org technique stats (`category="technique"`) |
| COLD    | append-only journal: every triage + every resolution              |
| HOT     | org context (industry, analyst count)                             |
| REFERENCE | playbooks / static notes                                        |
| ARCHIVE | retired entities, recoverable                                     |

## The gate: memory is load-bearing

Delete the Sibyl Memory layer and Continuum's core function — triaging
against institutional history — breaks. Same alert, same agent:

```bash
# with memory (after one prior cleared incident for this user):
$ continuum triage demo/alerts_session2.json --db demo/demo_memory.db
decision  : auto_suppress  (confidence 0.90)
cites     : inc_2026_0001
reasoning : Matches cleared incident(s) inc_2026_0001 — same
            anomalous_login pattern for a known entity.
            Auto-suppressing; logged for audit.

# memory deleted (--no-memory = the deletion test):
$ continuum triage demo/alerts_session2.json --no-memory
decision  : escalate  (confidence 0.50)
reasoning : No prior context for this anomalous_login alert (T1078).
            Novel pattern — escalate for manual review.
```

Every alert looks identical again. That contrast, on camera, is the
eligibility gate. Where the memory calls live (a judge can find these in
under two minutes):

- `src/continuum/memory/sibyl_client.py` — the **only** file that
  touches the SDK (`set_entity`, `search_entities`, `write_event`).
- `src/continuum/correlation/engine.py` — FTS5 entity recall +
  technique stats → `MemoryContext`.
- `src/continuum/agent/triage_agent.py` — decides *from* the retrieved
  context; citations are fail-closed (only real incident ids).
- `src/continuum/feedback/resolve.py` — resolution write-back that makes
  memory compound.

The Session 3 contrast (`demo/alerts_session3.json`): same technique
(T1078) as the cleared contractor incidents, but a **new user** with no
history — Continuum does not inherit jsmith's clearance for mchen. That
is structured memory reasoning, not a lookup table.

## How memory made this possible

Without durable memory, Continuum is a blind rule engine that escalates
everything — indistinguishable from the generic SIEM it replaces. The
product *is* the memory: persistence across sessions, entity-level
recall via FTS5, technique-level org statistics, and an append-only
journal. Sibyl Memory's single-source-of-truth constraint
(`UNIQUE (tenant_id, category, name)`) means an incident id can never
drift into duplicates — retrieval stays clean as the store grows.

## Partner stacks

**None claimed.** Base and Virtuals integrations were considered but not
exercised in this build, so the partner multiplier is honestly declared
as x1.00. The eligibility gate does not require a partner stack.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Python 3.10+.

## Usage

```bash
continuum generate --count 70 --seed 42 --out demo/alerts_bulk.json   # synthetic corpus
continuum triage demo/alerts_session1.json --db demo/demo_memory.db   # triage against memory
continuum triage demo/alerts_session2.json --no-memory                # deletion test
continuum resolve demo/alerts_session1.json --db demo/demo_memory.db  # analyst write-back
continuum demo                                                        # scripted fresh-session demo
continuum status --db demo/demo_memory.db                             # what is in the store
```

LLM-backed triage (any OpenAI-compatible endpoint):

```bash
export LLM_API_KEY=...        # required
export LLM_BASE_URL=...       # default https://api.openai.com/v1
export LLM_MODEL=...          # default gpt-4o-mini
continuum triage demo/alerts_session3.json --db demo/demo_memory.db --llm
```

Run the tests: `pytest`

## Repo layout

```
src/continuum/
├── cli.py                 # terminal interface
├── ingestion/             # synthetic alert generator
├── memory/                # schema.py (typed records) + sibyl_client.py (SDK facade)
├── correlation/           # alert -> MemoryContext
├── agent/                 # triage (rule + LLM backends)
└── feedback/              # resolution write-back
demo/                      # session alerts + the video script
docs/architecture.md
tests/
```

## Prior Work declaration

The build plan for this submission started from a public blueprint
(`continuum-soc-blueprint.md`), which defined the product concept, the
three-session demo narrative and the high-level repo shape. All code in
this repository was written for this submission; no third-party code is
incorporated beyond the Sibyl Memory SDK and the Python standard
library. The blueprint's tier count was corrected from "six" to the
actual five-tier schema of the Sibyl Memory SDK during implementation.

## License

MIT — see [LICENSE](LICENSE).
