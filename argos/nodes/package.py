"""Package evidence node — assembles the final EvidencePackage.

Responsibilities
----------------
Take everything the previous deterministic nodes produced and bundle it into
a single EvidencePackage. This is the LAST step before the reasoning node
sees anything, and it is the boundary at which the "what the LLM is allowed
to see" contract is enforced.

This node does NOT add new data. It only aggregates what previous nodes
already collected. If you find yourself wanting to add a new external lookup
here, add a new dedicated node instead — the single-responsibility principle
for investigation nodes is a security property.

Security notes
--------------
Pseudonymization (via Presidio) happens in the reasoning node right before
the prompt is built, NOT here. The EvidencePackage on state still contains
real values so the handoff node can later de-pseudonymize the narrative for
human review. This is intentional — see docs/THREAT_MODEL.md#asi01-goal-hijack.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Coroutine

from argos.schemas import ArgosState, EvidencePackage, NodeResult


def make_package_node() -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node.

    No dependencies — pure state aggregation.
    """

    async def package_evidence(state: ArgosState) -> NodeResult:
        assert state.customer_baseline is not None, "intake must run first"
        assert state.sanctions is not None, "sanctions_check must run before package"
        assert state.behavioral_delta is not None, "behavioral must run before package"
        assert state.prior_alerts_count_90d is not None, "intake must set prior alerts"

        package = EvidencePackage(
            alert=state.alert,
            customer_baseline=state.customer_baseline,
            sanctions=state.sanctions,
            behavioral_delta=state.behavioral_delta,
            related_transactions=state.related_transactions,
            prior_alerts_count_90d=state.prior_alerts_count_90d,
            assembled_at=datetime.now(timezone.utc),
            provenance_chain=state.provenance_chain,
        )

        return {"evidence_package": package}

    return package_evidence
