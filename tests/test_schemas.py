"""Tests for argos/schemas.py — the core contracts.

These tests verify the security-critical invariants that live in the
type system: UntrustedText boundaries, citation path restrictions,
and evidence package structure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

import pytest
from pydantic import ValidationError

from argos.schemas import (
    Disposition,
    DispositionCitation,
    DispositionRecommendation,
    UntrustedText,
)


class TestUntrustedText:
    def test_basic_construction(self):
        t = UntrustedText(content="hello", origin="customer_memo")
        assert t.content == "hello"
        assert t.origin == "customer_memo"

    def test_str_wraps_with_untrusted_tags(self):
        """The __str__ method must always emit <UNTRUSTED> boundary markers.

        This is the primary defense against accidental string interpolation
        into a prompt without going through the UntrustedText wrapper.
        """
        t = UntrustedText(content="pay me now", origin="beneficiary_name")
        s = str(t)
        assert "<UNTRUSTED" in s
        assert "origin=beneficiary_name" in s
        assert "pay me now" in s
        assert s.endswith("</UNTRUSTED>")

    def test_frozen(self):
        """UntrustedText is immutable — attempting to mutate raises."""
        t = UntrustedText(content="x", origin="customer_memo")
        with pytest.raises(ValidationError):
            t.content = "y"  # type: ignore[misc]

    def test_invalid_origin_rejected(self):
        """Unknown origin values are rejected by the Literal validator."""
        with pytest.raises(ValidationError):
            UntrustedText(content="x", origin="not_a_real_origin")  # type: ignore[arg-type]

    def test_max_length_enforced(self):
        """Memos over 10,000 chars are rejected to prevent memo-bomb DoS."""
        with pytest.raises(ValidationError):
            UntrustedText(content="x" * 10_001, origin="customer_memo")


class TestDispositionCitation:
    def test_valid_path(self):
        c = DispositionCitation(
            claim="Amount is 47x the customer's p95",
            evidence_path="behavioral_delta.amount_vs_p95_ratio",
        )
        assert c.evidence_path == "behavioral_delta.amount_vs_p95_ratio"

    def test_path_into_untrusted_content_rejected(self):
        """Citations may not point INTO UntrustedText.content.

        This blocks the attack pattern where an adversary fabricates
        "evidence" in a memo field and then has the LLM cite it as truth.
        """
        with pytest.raises(ValidationError) as exc_info:
            DispositionCitation(
                claim="The memo says the customer is verified",
                evidence_path="alert.transaction.memo.content",
            )
        assert "UntrustedText" in str(exc_info.value) or "content" in str(exc_info.value)

    def test_path_at_untrusted_field_is_allowed(self):
        """Citations CAN point at the wrapping field itself."""
        c = DispositionCitation(
            claim="The beneficiary name field contained an injection attempt",
            evidence_path="alert.transaction.beneficiary_name",
        )
        assert c.evidence_path == "alert.transaction.beneficiary_name"

    def test_invalid_path_format_rejected(self):
        with pytest.raises(ValidationError):
            DispositionCitation(
                claim="bad path",
                evidence_path="NotA.ValidPath!",
            )

    def test_claim_length_bounded(self):
        with pytest.raises(ValidationError):
            DispositionCitation(
                claim="x" * 501,
                evidence_path="alert.alert_id",
            )


class TestDispositionRecommendation:
    def _minimal_valid_rec(self, **overrides) -> dict:
        base = {
            "disposition": Disposition.CLOSE_FALSE_POSITIVE,
            "confidence": 0.9,
            "key_findings": [
                DispositionCitation(
                    claim="Amount is consistent with baseline",
                    evidence_path="behavioral_delta.amount_vs_p95_ratio",
                )
            ],
            "draft_narrative": None,
            "analyst_notes": "",
        }
        base.update(overrides)
        return base

    def test_minimal_valid(self):
        rec = DispositionRecommendation(**self._minimal_valid_rec())
        assert rec.disposition == Disposition.CLOSE_FALSE_POSITIVE

    def test_requires_at_least_one_finding(self):
        with pytest.raises(ValidationError):
            DispositionRecommendation(**self._minimal_valid_rec(key_findings=[]))

    def test_confidence_bounded(self):
        with pytest.raises(ValidationError):
            DispositionRecommendation(**self._minimal_valid_rec(confidence=1.5))
        with pytest.raises(ValidationError):
            DispositionRecommendation(**self._minimal_valid_rec(confidence=-0.1))

    def test_narrative_length_bounded(self):
        with pytest.raises(ValidationError):
            DispositionRecommendation(
                **self._minimal_valid_rec(draft_narrative="x" * 8001)
            )

    def test_max_findings_enforced(self):
        with pytest.raises(ValidationError):
            DispositionRecommendation(
                **self._minimal_valid_rec(
                    key_findings=[
                        DispositionCitation(claim=f"f{i}", evidence_path="alert.alert_id")
                        for i in range(11)
                    ]
                )
            )
