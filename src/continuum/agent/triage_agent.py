"""Triage agent: alert + retrieved memory context -> structured decision.

Two interchangeable backends behind one interface:

  RuleTriageAgent  — deterministic, zero-cost, zero-keys. Used by tests,
                     CI, and the --no-memory deletion-test contrast. The
                     reasoning is transparent: every decision cites real
                     incident ids read from memory.

  LLMTriageAgent   — the production path. Any OpenAI-compatible chat
                     completions endpoint (env: LLM_API_KEY / LLM_BASE_URL
                     / LLM_MODEL). Fail-closed on citations: the model may
                     ONLY cite incident ids that were actually retrieved
                     from memory; anything else is dropped, and a JSON
                     parse failure falls back to the rule agent.

The load-bearing moment: remove the memory layer (NullMemory) and the
same agent degrades to blind "no context, escalate" — the deletion test.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from ..correlation.engine import correlate
from ..memory.schema import (
    DECISION_AUTO_SUPPRESS,
    DECISION_ESCALATE,
    DECISION_REVIEW_WITH_CONTEXT,
    Alert,
    MemoryContext,
    TriageDecision,
)
from ..memory.sibyl_client import ContinuumMemory, NullMemory

SYSTEM_PROMPT = """You are Continuum, a SOC triage agent for one specific organization.
You triage alerts against the organization's OWN institutional memory (incident history),
never against generic rules.

You are given:
- the incoming alert (JSON)
- memory context: entity history (incidents involving the same user/host/ip), org-level
  technique statistics, and a summary.

Rules:
1. You may cite ONLY incident ids present in the provided memory context. Never invent ids.
2. Decisions: "auto_suppress" (cleared pattern for a known entity), "review_with_context"
   (history exists but nothing cleared for this alert type), "escalate" (novel pattern).
3. Do NOT blind-reuse one entity's clearance for another entity. A new user with no history
   is NOT auto-suppressed, even if the technique is usually a false positive.
4. Respond with JSON only: {"decision": str, "confidence": float, "reasoning": str,
   "cited_incidents": [str]}."""


class RuleTriageAgent:
    """Deterministic triage over retrieved memory. Transparent and testable."""

    def triage(self, alert: Alert, ctx: MemoryContext) -> TriageDecision:
        if ctx.is_empty():
            return TriageDecision(
                decision=DECISION_ESCALATE,
                confidence=0.5,
                reasoning=(
                    f"No prior context for this {alert.alert_type} alert "
                    f"({alert.mitre_technique}). Novel pattern — escalate for manual review."
                ),
                cited_incidents=[],
            )

        # 1) Known entity, same alert type previously cleared -> suppress.
        cleared: list[str] = []
        for hit in ctx.entity_hits:
            for inc in hit["incidents"]:
                if inc["alert_type"] == alert.alert_type and inc["resolution"] == "false_positive":
                    cleared.append(inc["incident_id"])
        if cleared:
            ids = sorted(set(cleared))
            return TriageDecision(
                decision=DECISION_AUTO_SUPPRESS,
                confidence=0.9,
                reasoning=(
                    f"Matches cleared incident(s) {', '.join(ids)} — same "
                    f"{alert.alert_type} pattern for a known entity. "
                    "Auto-suppressing; logged for audit."
                ),
                cited_incidents=ids,
            )

        # 2) Entity history exists but nothing cleared for this type -> review.
        if ctx.entity_hits:
            ids = ctx.cited_incident_ids
            return TriageDecision(
                decision=DECISION_REVIEW_WITH_CONTEXT,
                confidence=0.6,
                reasoning=(
                    f"Entity history exists ({', '.join(ids)}) but no cleared match for "
                    f"{alert.alert_type}. Review with context."
                ),
                cited_incidents=ids,
            )

        # 3) No entity history, technique stats only -> escalate with context.
        t = ctx.technique
        if t is not None:
            return TriageDecision(
                decision=DECISION_ESCALATE,
                confidence=0.6,
                reasoning=(
                    f"No entity history for this alert's entities. Org-wide {t.mitre_id} "
                    f"({t.technique_name}) shows {t.org_incident_count} incident(s), "
                    f"{t.org_false_positive_rate:.0%} org false-positive rate — but this is "
                    "a NEW entity for this pattern, so it does not inherit that clearance. "
                    "Escalate for review."
                ),
                cited_incidents=[],
            )

        return TriageDecision(
            decision=DECISION_ESCALATE,
            confidence=0.5,
            reasoning="No usable context. Escalate for manual review.",
            cited_incidents=[],
        )


class LLMTriageAgent:
    """LLM-backed triage against any OpenAI-compatible endpoint."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout_s: int = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("LLM_API_KEY")
        self.base_url = (base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.timeout_s = timeout_s
        self.fallback = RuleTriageAgent()

    def triage(self, alert: Alert, ctx: MemoryContext) -> TriageDecision:
        if not self.api_key:
            return self._fallback(alert, ctx, "no LLM_API_KEY set")
        try:
            return self._call_llm(alert, ctx)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, ValueError) as exc:
            return self._fallback(alert, ctx, f"LLM call failed ({exc.__class__.__name__}), rule fallback used")

    # ------------------------------------------------------------------

    def _call_llm(self, alert: Alert, ctx: MemoryContext) -> TriageDecision:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"ALERT:\n{json.dumps(alert.to_dict(), indent=2)}\n\n"
                        f"MEMORY CONTEXT:\n{json.dumps(self._context_payload(ctx), indent=2)}"
                    ),
                },
            ],
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            body = json.loads(resp.read().decode())

        raw = body["choices"][0]["message"]["content"]
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("LLM response is not a JSON object")

        decision = parsed.get("decision")
        confidence = float(parsed.get("confidence", 0.5))
        reasoning = str(parsed.get("reasoning", ""))
        cited = [str(i) for i in parsed.get("cited_incidents", [])]

        # Fail-closed citations: only ids that actually came from memory.
        allowed = set(ctx.cited_incident_ids)
        cited = sorted(set(c for c in cited if c in allowed))

        if decision not in (DECISION_AUTO_SUPPRESS, DECISION_REVIEW_WITH_CONTEXT, DECISION_ESCALATE):
            raise ValueError(f"unknown decision from LLM: {decision!r}")
        return TriageDecision(decision=decision, confidence=confidence, reasoning=reasoning, cited_incidents=cited)

    @staticmethod
    def _context_payload(ctx: MemoryContext) -> dict[str, Any]:
        return {
            "summary": ctx.summary,
            "entity_hits": ctx.entity_hits,
            "technique": ctx.technique.to_dict() if ctx.technique else None,
            "recent_journal": ctx.recent_events[-5:],
        }

    def _fallback(self, alert: Alert, ctx: MemoryContext, why: str) -> TriageDecision:
        decision = self.fallback.triage(alert, ctx)
        decision.reasoning = f"[{why}] " + decision.reasoning
        return decision


def triage_alert(alert: Alert, memory: ContinuumMemory | None, agent: Any = None) -> TriageDecision:
    """One-shot convenience: correlate then decide.

    ``agent=None`` uses the rule agent; pass an LLMTriageAgent for the
    production path. ``memory=None`` runs the deletion test.
    """
    ctx = correlate(alert, memory)
    if agent is None:
        agent = RuleTriageAgent()
    return agent.triage(alert, ctx)
