"""Data-source abstraction for Argos nodes.

Nodes never talk to external systems directly. Instead they call a DataSource
passed in at graph-build time. This keeps nodes pure-functional of state and
dependencies, which makes them trivially unit-testable and lets us swap the
backend between demo, test, and production without touching node code.

In production, implementations of DataSource will hit:
  - core banking for baselines and transaction history
  - OFAC / EU / UN / UK OFSI APIs for sanctions
  - the case management system for prior alerts

In the demo, StubDataSource serves pre-generated synthetic fixtures so the
whole graph runs offline.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Protocol

from argos.schemas import (
    CustomerBaseline,
    ProvenanceEntry,
    SanctionsCheckResult,
    TransactionRecord,
)


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


class DataSource(Protocol):
    """The contract every data backend must implement.

    These are the only external queries Argos nodes are allowed to make.
    Adding a method here is a security-review-triggering change because it
    expands the set of systems nodes can touch — see docs/THREAT_MODEL.md.
    """

    def get_customer_baseline(self, customer_id: str) -> CustomerBaseline: ...

    def get_recent_transactions(
        self, customer_id: str, since: datetime
    ) -> list[TransactionRecord]: ...

    def check_sanctions(
        self, name: str | None, account: str, country: str | None
    ) -> SanctionsCheckResult: ...

    def count_prior_alerts(self, customer_id: str, window_days: int) -> int: ...


# ---------------------------------------------------------------------------
# StubDataSource — the demo and test backend
# ---------------------------------------------------------------------------

# Tiny hard-coded sanctions list for the demo. Real deployments hit OFAC APIs.
# These are fabricated names chosen to be obviously fake.
_DEMO_SANCTIONS_LIST = {
    "ACME HOLDINGS KP",
    "REDACTED SHIPPING LTD",
    "BLOCKLIST EXAMPLE CORP",
}
_DEMO_HIGH_RISK_COUNTRIES = {"KP", "IR", "SY"}


class StubDataSource:
    """In-memory data source for the demo and test suite.

    Accepts pre-loaded fixtures in its constructor. Never makes network calls.
    Suitable for the docker-compose demo and for unit tests. NOT suitable for
    any deployment with real customer data.
    """

    def __init__(
        self,
        baselines: dict[str, CustomerBaseline] | None = None,
        transactions: dict[str, list[TransactionRecord]] | None = None,
        prior_alert_counts: dict[str, int] | None = None,
    ) -> None:
        self._baselines = baselines or {}
        self._transactions = transactions or {}
        self._prior_alerts = prior_alert_counts or {}

    def get_customer_baseline(self, customer_id: str) -> CustomerBaseline:
        if customer_id in self._baselines:
            return self._baselines[customer_id]
        # Fallback: generate a "thin-file" baseline so the demo still runs
        # for customers with no history. Real deployments should raise here.
        return CustomerBaseline(
            customer_id=customer_id,
            window_days=90,
            total_transactions=0,
            total_volume=Decimal("0"),
            avg_transaction_amount=Decimal("0"),
            median_transaction_amount=Decimal("0"),
            p95_transaction_amount=Decimal("0"),
            distinct_counterparties=0,
            distinct_countries=0,
            typical_hours_utc=[],
            typical_channels=[],
            provenance=ProvenanceEntry(
                source="stub_data_source",
                retrieved_at=datetime.now(timezone.utc),
                credential_id="stub",
                response_hash=_hash(f"thin:{customer_id}"),
                query_summary=f"thin-file baseline for {customer_id}",
            ),
        )

    def get_recent_transactions(
        self, customer_id: str, since: datetime
    ) -> list[TransactionRecord]:
        txs = self._transactions.get(customer_id, [])
        return [t for t in txs if t.timestamp >= since]

    def check_sanctions(
        self, name: str | None, account: str, country: str | None
    ) -> SanctionsCheckResult:
        hit_details: list[str] = []
        primary_hit = False
        secondary_hit = False

        if name and name.strip().upper() in _DEMO_SANCTIONS_LIST:
            primary_hit = True
            hit_details.append("DEMO_SDN_LIST")

        if country and country.upper() in _DEMO_HIGH_RISK_COUNTRIES:
            secondary_hit = True
            hit_details.append("DEMO_HIGH_RISK_JURISDICTIONS")

        return SanctionsCheckResult(
            checked_lists=["DEMO_SDN_LIST", "DEMO_HIGH_RISK_JURISDICTIONS"],
            primary_hit=primary_hit,
            secondary_hit=secondary_hit,
            hit_details=hit_details,
            provenance=ProvenanceEntry(
                source="stub_sanctions_api",
                retrieved_at=datetime.now(timezone.utc),
                credential_id="stub",
                response_hash=_hash(f"{name}|{account}|{country}"),
                query_summary="sanctions screening (demo stub)",
            ),
        )

    def count_prior_alerts(self, customer_id: str, window_days: int) -> int:
        return self._prior_alerts.get(customer_id, 0)


def default_since(window_days: int = 90) -> datetime:
    """Helper: UTC cutoff for a backward-looking window."""
    return datetime.now(timezone.utc) - timedelta(days=window_days)
