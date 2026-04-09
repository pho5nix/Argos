"""Sanctions check node — deterministic, always runs before reasoning.

Responsibilities
----------------
- Screen the beneficiary and counterparty against configured sanctions lists.
- Populate SanctionsCheckResult on the state.
- Record provenance.

Security properties
-------------------
1. **Deterministic, no LLM.** Sanctions checking is a pure data lookup. The
   LLM never reasons over "is this person sanctioned?" — that's a compliance
   question with a yes/no answer that must not be subject to model judgment.

2. **Hard hits short-circuit the graph.** When a primary sanctions hit occurs
   (OFAC SDN, EU consolidated list, UN 1267, etc.), the graph router in
   argos/graph.py detects this and routes DIRECTLY to the handoff node,
   completely bypassing the reasoning LLM. The LLM never sees the evidence
   of sanctioned parties.

   This is a deliberate OWASP ASI01 (Goal Hijack) defense: if an attacker
   managed to manipulate the evidence package to make a sanctioned party
   look legitimate, the LLM would never be asked to make that judgment in
   the first place.
"""

from __future__ import annotations

from typing import Callable, Coroutine

from argos.data import DataSource
from argos.schemas import ArgosState, NodeResult


def make_sanctions_node(
    data_source: DataSource,
) -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node closing over the given data source."""

    async def sanctions_check(state: ArgosState) -> NodeResult:
        tx = state.alert.transaction

        # The beneficiary name is an UntrustedText — we extract the raw content
        # ONLY for the deterministic string match against the sanctions list.
        # The raw string never flows to the LLM; only the structured
        # SanctionsCheckResult does.
        beneficiary_name = tx.beneficiary_name.content if tx.beneficiary_name else None

        result = data_source.check_sanctions(
            name=beneficiary_name,
            account=tx.beneficiary_account,
            country=tx.counterparty_country,
        )

        return {
            "sanctions": result,
            "provenance_chain": [*state.provenance_chain, result.provenance],
            # Flag the override so the handoff node knows this case bypassed
            # the reasoning step deliberately and can annotate accordingly.
            "hard_sanctions_override": result.primary_hit,
        }

    return sanctions_check
