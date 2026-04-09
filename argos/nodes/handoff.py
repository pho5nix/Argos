"""Handoff node — the final step in every investigation.

Responsibilities
----------------
- Write the complete investigation record to the append-only audit log.
- Hand the recommendation off to the case management system.
- Annotate cases that hit the hard sanctions override path.

This node is the boundary between Argos and the outside world. After this
node runs, Argos has no further influence on the case — the human analyst
has the ball.

Security notes
--------------
- The audit log is append-only and hash-chained (see argos/audit.py in Batch
  3). Tampering with historical entries breaks the chain and is detectable.
- The case management connector is the only piece of Argos that gets to write
  to an external system, and it writes only structured records — never the
  raw model output.
- When the hard sanctions override was triggered upstream, the handoff node
  rewrites the recommendation to reflect that fact clearly so analysts can't
  mistake a short-circuited case for a reasoned one.
"""

from __future__ import annotations

from typing import Any, Callable, Coroutine

from argos.schemas import (
    ArgosState,
    Disposition,
    DispositionCitation,
    DispositionRecommendation,
    NodeResult,
)

# Typed loosely until Batch 3 ships the real audit log and connectors.
AuditLog = Any
CaseConnector = Any


def make_handoff_node(
    audit_log: AuditLog | None = None,
    case_connector: CaseConnector | None = None,
) -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node closing over audit log and case connector.

    Both dependencies are optional in Batch 2 so the graph can run end-to-end
    before those components ship. Batch 3 adds the real implementations.
    """

    async def handoff(state: ArgosState) -> NodeResult:
        recommendation = state.recommendation

        # If we got here via the hard-sanctions short-circuit, the reason node
        # was skipped entirely and state.recommendation is None. Build a
        # deterministic "sanctions override" recommendation instead.
        if state.hard_sanctions_override and recommendation is None:
            recommendation = _sanctions_override_recommendation(state)

        # Defense in depth: if we somehow arrive here with no recommendation
        # at all, force escalation rather than dropping the case silently.
        if recommendation is None:
            recommendation = DispositionRecommendation(
                disposition=Disposition.ESCALATE_TO_CASE,
                confidence=0.0,
                key_findings=[
                    DispositionCitation(
                        claim=(
                            "No recommendation was produced. This is a bug — "
                            "investigate how this case reached handoff without "
                            "going through the reasoning node or the sanctions "
                            "override path."
                        ),
                        evidence_path="alert.alert_id",
                    )
                ],
                draft_narrative=None,
                analyst_notes="Automatic escalation: missing recommendation at handoff",
            )

        # Write the full investigation record to the audit log.
        if audit_log is not None:
            audit_log.append(
                alert_id=state.alert.alert_id,
                recommendation=recommendation,
                provenance_chain=state.provenance_chain,
                errors=state.errors,
                hard_sanctions_override=state.hard_sanctions_override,
            )

        # Push to case management.
        if case_connector is not None:
            case_connector.create_case(
                alert=state.alert,
                recommendation=recommendation,
                evidence_package=state.evidence_package,
            )

        return {"recommendation": recommendation}

    return handoff


def _sanctions_override_recommendation(state: ArgosState) -> DispositionRecommendation:
    """Build the deterministic recommendation for a short-circuited sanctions case."""
    hits = ", ".join(state.sanctions.hit_details) if state.sanctions else "unknown"
    # Keep hits string short enough that the full claim stays under 200 chars.
    if len(hits) > 80:
        hits = hits[:77] + "..."
    return DispositionRecommendation(
        disposition=Disposition.ESCALATE_TO_CASE,
        confidence=1.0,
        key_findings=[
            DispositionCitation(
                claim=f"Hard sanctions hit on: {hits}. Routed to human review per sanctions override policy.",
                evidence_path="sanctions.primary_hit",
            ),
            DispositionCitation(
                claim="Reasoning LLM bypassed by graph policy. No AI judgment applied to sanctioned status.",
                evidence_path="sanctions.hit_details",
            ),
        ],
        draft_narrative=None,
        analyst_notes=(
            "SANCTIONS OVERRIDE: reasoning node bypassed by graph policy. "
            "Review the sanctions list hits directly — do not treat the absence "
            "of an AI narrative as absence of risk."
        ),
    )
