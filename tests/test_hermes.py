"""Tests for the Hermes Test defenses.

These tests exercise the non-LLM parts of the reasoning pipeline directly:
the citation validator (pure code) and a graph smoke test using the
FallbackBackend (no real LLM required).

For the full LLM-based red-team run, see `redteam/run_hermes_test.py`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest

from argos.audit import NullAuditLog
from argos.connectors import StdoutConnector
from argos.graph import build_graph
from argos.nodes.reason import validate_citations
from argos.privacy import NullPseudonymizer
from argos.reasoning import FallbackBackend
from argos.schemas import (
    Alert,
    AlertSource,
    ArgosState,
    BehavioralDelta,
    CustomerBaseline,
    Disposition,
    DispositionCitation,
    DispositionRecommendation,
    EvidencePackage,
    ProvenanceEntry,
    SanctionsCheckResult,
    TransactionRecord,
    UntrustedText,
)
from argos.synthetic import generate_demo_dataset


# ---------------------------------------------------------------------------
# Helpers to build a minimal valid EvidencePackage for testing
# ---------------------------------------------------------------------------


def _make_test_package() -> EvidencePackage:
    now = datetime.now(timezone.utc)
    prov = ProvenanceEntry(
        source="test",
        retrieved_at=now,
        credential_id="test",
        response_hash="x" * 16,
        query_summary="test",
    )
    baseline = CustomerBaseline(
        customer_id="CUST-TEST",
        window_days=90,
        total_transactions=30,
        total_volume=Decimal("30000"),
        avg_transaction_amount=Decimal("1000"),
        median_transaction_amount=Decimal("900"),
        p95_transaction_amount=Decimal("2500"),
        distinct_counterparties=10,
        distinct_countries=1,
        provenance=prov,
    )
    alert = Alert(
        alert_id="TEST-0001",
        source=AlertSource.SYNTHETIC,
        fired_at=now,
        rule_id="TEST_RULE",
        score=0.7,
        customer_id="CUST-TEST",
        rule_description=UntrustedText(content="test rule", origin="third_party_api"),
        transaction=TransactionRecord(
            transaction_id="TX-TEST",
            timestamp=now,
            amount=Decimal("5000"),
            currency="USD",
            originator_account="ACCT-TEST",
            beneficiary_account="ACCT-OTHER",
        ),
    )
    return EvidencePackage(
        alert=alert,
        customer_baseline=baseline,
        sanctions=SanctionsCheckResult(
            checked_lists=["TEST"],
            primary_hit=False,
            secondary_hit=False,
            hit_details=[],
            provenance=prov,
        ),
        behavioral_delta=BehavioralDelta(
            amount_zscore=2.1,
            amount_vs_p95_ratio=2.0,
            is_new_counterparty=True,
            is_new_country=False,
            is_out_of_hours=False,
            velocity_1h=1,
            velocity_24h=3,
        ),
        related_transactions=[],
        prior_alerts_count_90d=0,
        assembled_at=now,
        provenance_chain=[prov],
    )


# ---------------------------------------------------------------------------
# Citation validator tests
# ---------------------------------------------------------------------------


class TestValidateCitations:
    def test_all_valid_citations_pass(self):
        pkg = _make_test_package()
        rec = DispositionRecommendation(
            disposition=Disposition.ESCALATE_TO_CASE,
            confidence=0.8,
            key_findings=[
                DispositionCitation(
                    claim="Amount exceeds p95",
                    evidence_path="behavioral_delta.amount_vs_p95_ratio",
                ),
                DispositionCitation(
                    claim="New counterparty",
                    evidence_path="behavioral_delta.is_new_counterparty",
                ),
            ],
        )
        invalid = validate_citations(rec, pkg)
        assert invalid == []

    def test_fabricated_field_is_caught(self):
        pkg = _make_test_package()
        rec = DispositionRecommendation(
            disposition=Disposition.CLOSE_FALSE_POSITIVE,
            confidence=0.9,
            key_findings=[
                DispositionCitation(
                    claim="The compliance whitelist contains this counterparty",
                    evidence_path="compliance.whitelist",  # does not exist
                ),
            ],
        )
        invalid = validate_citations(rec, pkg)
        assert len(invalid) == 1
        assert invalid[0].evidence_path == "compliance.whitelist"

    def test_deep_valid_path(self):
        pkg = _make_test_package()
        rec = DispositionRecommendation(
            disposition=Disposition.INSUFFICIENT_EVIDENCE,
            confidence=0.3,
            key_findings=[
                DispositionCitation(
                    claim="Customer ID",
                    evidence_path="alert.customer_id",
                ),
                DispositionCitation(
                    claim="Tx timestamp",
                    evidence_path="alert.transaction.timestamp",
                ),
            ],
        )
        invalid = validate_citations(rec, pkg)
        assert invalid == []

    def test_mixed_valid_and_invalid(self):
        pkg = _make_test_package()
        rec = DispositionRecommendation(
            disposition=Disposition.ESCALATE_TO_CASE,
            confidence=0.7,
            key_findings=[
                DispositionCitation(
                    claim="Valid one",
                    evidence_path="behavioral_delta.is_new_counterparty",
                ),
                DispositionCitation(
                    claim="Fabricated",
                    evidence_path="behavioral_delta.secret_score",
                ),
            ],
        )
        invalid = validate_citations(rec, pkg)
        assert len(invalid) == 1
        assert invalid[0].evidence_path == "behavioral_delta.secret_score"


# ---------------------------------------------------------------------------
# Smoke test: full graph against the FallbackBackend
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGraphSmoke:
    """End-to-end graph tests using FallbackBackend (no real LLM)."""

    async def test_graph_runs_end_to_end(self):
        data_source, alerts = generate_demo_dataset()
        graph = build_graph(
            data_source=data_source,
            reasoning_backend=FallbackBackend(),
            pseudonymizer=NullPseudonymizer(),
            audit_log=NullAuditLog(),
            case_connector=StdoutConnector(),
        )

        # Use the clean-false-positive scenario
        alert = next(a for a in alerts if a.alert_id == "ALERT-00001")
        state = ArgosState(alert=alert)
        final_dict = await graph.ainvoke(state)
        final_state = ArgosState.model_validate(final_dict)

        assert final_state.recommendation is not None
        assert final_state.evidence_package is not None
        # FallbackBackend always force-escalates
        assert final_state.recommendation.disposition == Disposition.ESCALATE_TO_CASE
        assert "FALLBACK" in final_state.recommendation.analyst_notes.upper()

    async def test_sanctions_override_bypasses_llm(self):
        """The hard sanctions override short-circuits past the LLM."""
        data_source, alerts = generate_demo_dataset()
        graph = build_graph(
            data_source=data_source,
            reasoning_backend=FallbackBackend(),
            pseudonymizer=NullPseudonymizer(),
            audit_log=NullAuditLog(),
            case_connector=StdoutConnector(),
        )

        # Scenario 4 is the hard sanctions hit
        alert = next(a for a in alerts if a.alert_id == "ALERT-00004")
        state = ArgosState(alert=alert)
        final_dict = await graph.ainvoke(state)
        final_state = ArgosState.model_validate(final_dict)

        assert final_state.hard_sanctions_override is True
        assert final_state.recommendation is not None
        # The handoff node constructs a deterministic sanctions-override
        # recommendation when the LLM is bypassed.
        assert "SANCTIONS OVERRIDE" in final_state.recommendation.analyst_notes
        assert final_state.recommendation.confidence == 1.0
