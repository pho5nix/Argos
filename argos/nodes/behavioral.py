"""Behavioral delta node — pure Python, no external calls, no LLM.

Responsibilities
----------------
Compute explicit numeric features comparing the alerting transaction against
the customer's 90-day baseline. These features are what the reasoning node
actually uses to judge "is this anomalous?" — the LLM does NOT see the raw
90-day transaction stream.

Why we compute these in Python and not let the LLM do it
--------------------------------------------------------
Two reasons:
1. Determinism. An auditor can replay the exact same arithmetic six months
   later and get the same result. An LLM computing z-scores cannot be
   replayed.
2. Prompt economy. Sending 90 days of transactions to the LLM would be
   expensive, slow, and would expose far more customer data than necessary.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Callable, Coroutine

from argos.data import DataSource
from argos.schemas import ArgosState, BehavioralDelta, NodeResult


def _estimate_stdev(mean: float, p95: float) -> float:
    """Rough stdev estimate from mean and p95.

    For a log-normal-ish spending distribution, p95 ≈ mean + 1.645 * stdev.
    Inverting: stdev ≈ (p95 - mean) / 1.645. This is approximate but
    sufficient for anomaly flagging in the demo. Production deployments
    should store real stdev in the baseline and use it directly.
    """
    if p95 <= mean:
        return max(mean * 0.5, 1.0)  # safe floor
    return (p95 - mean) / 1.645


def make_behavioral_node(
    data_source: DataSource,
) -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node closing over the given data source."""

    async def behavioral_delta(state: ArgosState) -> NodeResult:
        alert = state.alert
        tx = alert.transaction
        baseline = state.customer_baseline
        assert baseline is not None, "intake node must run before behavioral_delta"

        # Amount deltas
        amount_f = float(tx.amount)
        mean_f = float(baseline.avg_transaction_amount)
        p95_f = float(baseline.p95_transaction_amount)
        stdev = _estimate_stdev(mean_f, p95_f)
        amount_zscore = (amount_f - mean_f) / stdev if stdev > 0 else 0.0
        amount_vs_p95 = amount_f / p95_f if p95_f > 0 else float("inf")

        # Counterparty / geo novelty. Compute against recent history.
        recent_tx = data_source.get_recent_transactions(
            alert.customer_id,
            since=tx.timestamp - timedelta(days=90),
        )
        known_counterparties = {t.beneficiary_account for t in recent_tx}
        known_countries = {t.counterparty_country for t in recent_tx if t.counterparty_country}

        is_new_counterparty = tx.beneficiary_account not in known_counterparties
        is_new_country = bool(
            tx.counterparty_country and tx.counterparty_country not in known_countries
        )

        # Out-of-hours check
        tx_hour = tx.timestamp.hour
        is_out_of_hours = bool(
            baseline.typical_hours_utc and tx_hour not in baseline.typical_hours_utc
        )

        # Velocity: how many transactions in the prior 1h and 24h
        one_hour_ago = tx.timestamp - timedelta(hours=1)
        one_day_ago = tx.timestamp - timedelta(hours=24)
        velocity_1h = sum(1 for t in recent_tx if t.timestamp >= one_hour_ago)
        velocity_24h = sum(1 for t in recent_tx if t.timestamp >= one_day_ago)

        delta = BehavioralDelta(
            amount_zscore=round(amount_zscore, 2),
            amount_vs_p95_ratio=round(amount_vs_p95, 2),
            is_new_counterparty=is_new_counterparty,
            is_new_country=is_new_country,
            is_out_of_hours=is_out_of_hours,
            velocity_1h=velocity_1h,
            velocity_24h=velocity_24h,
        )

        return {
            "behavioral_delta": delta,
            "related_transactions": recent_tx[:20],  # cap at 20 per schema
        }

    return behavioral_delta
