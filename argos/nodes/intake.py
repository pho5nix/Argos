"""Intake node — the first step in every investigation.

Responsibilities
----------------
- Validate the incoming Alert (already typed via Pydantic, so this is just a
  sanity check that the required pieces exist).
- Fetch the 90-day customer baseline from the data source.
- Fetch the count of prior alerts on the same customer in the last 90 days.
- Record provenance for each external query.

Does NOT do
-----------
- Any LLM calls (no node other than `reason` ever does)
- Any sanctions checking (that's the next node)
- Any behavioral scoring (that's the node after that)

Security notes
--------------
The intake node holds credentials to query the core banking system for the
customer baseline. Those credentials are scoped per-investigation and
short-lived — see the governance policies in policies/argos.rego.
"""

from __future__ import annotations

from typing import Callable, Coroutine

from argos.data import DataSource
from argos.schemas import ArgosState, NodeResult


def make_intake_node(
    data_source: DataSource,
) -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node closing over the given data source."""

    async def intake(state: ArgosState) -> NodeResult:
        alert = state.alert
        customer_id = alert.customer_id

        baseline = data_source.get_customer_baseline(customer_id)
        prior_alerts = data_source.count_prior_alerts(customer_id, window_days=90)

        return {
            "customer_baseline": baseline,
            "prior_alerts_count_90d": prior_alerts,
            "provenance_chain": [
                *state.provenance_chain,
                baseline.provenance,
            ],
        }

    return intake
