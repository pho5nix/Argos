"""Tests for argos/privacy.py — pseudonymization and TokenMap.

These tests focus on the round-trip correctness of the TokenMap and the
regex fallbacks. They do NOT require Presidio to be running; Presidio
integration is exercised by the end-to-end tests when the full demo
stack is up.
"""

from __future__ import annotations

from argos.privacy import NullPseudonymizer, TokenMap


class TestTokenMap:
    def test_token_for_returns_stable_token(self):
        tmap = TokenMap()
        a = tmap.token_for("customer", "CUST-100001")
        b = tmap.token_for("customer", "CUST-100001")
        assert a == b

    def test_different_values_get_different_tokens(self):
        tmap = TokenMap()
        a = tmap.token_for("customer", "CUST-100001")
        b = tmap.token_for("customer", "CUST-100002")
        assert a != b

    def test_token_format(self):
        tmap = TokenMap()
        token = tmap.token_for("account", "ACCT-100001")
        # Tokens look like [ACCOUNT_001]
        assert token.startswith("[ACCOUNT_")
        assert token.endswith("]")

    def test_category_prefixes_are_separate(self):
        tmap = TokenMap()
        cust_token = tmap.token_for("customer", "100001")
        acct_token = tmap.token_for("account", "100001")
        assert cust_token != acct_token
        assert "CUSTOMER" in cust_token
        assert "ACCOUNT" in acct_token

    def test_counters_increment_per_category(self):
        tmap = TokenMap()
        t1 = tmap.token_for("person", "Alice")
        t2 = tmap.token_for("person", "Bob")
        t3 = tmap.token_for("person", "Carol")
        assert "_001]" in t1
        assert "_002]" in t2
        assert "_003]" in t3

    def test_depseudonymize_restores_original(self):
        tmap = TokenMap()
        token = tmap.token_for("person", "Alice Smith")
        text = f"The customer {token} made a transfer."
        restored = tmap.depseudonymize(text)
        assert "Alice Smith" in restored
        assert token not in restored

    def test_depseudonymize_handles_multiple_tokens(self):
        tmap = TokenMap()
        t_alice = tmap.token_for("person", "Alice")
        t_bob = tmap.token_for("person", "Bob")
        text = f"{t_alice} sent money to {t_bob}."
        restored = tmap.depseudonymize(text)
        assert restored == "Alice sent money to Bob."

    def test_depseudonymize_prefers_longer_tokens(self):
        """When one token is a substring of another, longer tokens replace first.

        This matters because [ACCOUNT_10] is a substring of [ACCOUNT_100].
        """
        tmap = TokenMap()
        # Force a specific ordering by calling token_for 10 times
        for i in range(10):
            tmap.token_for("account", f"acct{i}")
        token_10 = tmap.token_for("account", "acct10")

        text = f"The account is {token_10}."
        restored = tmap.depseudonymize(text)
        assert "acct10" in restored

    def test_empty_map_is_noop(self):
        tmap = TokenMap()
        text = "No tokens here at all."
        assert tmap.depseudonymize(text) == text


class TestNullPseudonymizer:
    """The no-op pseudonymizer used when Presidio is unavailable."""

    def test_depseudonymize_is_identity(self):
        null = NullPseudonymizer()
        tmap = TokenMap()
        text = "hello world"
        assert null.depseudonymize(text, tmap) == text
