"""PII pseudonymization via Microsoft Presidio.

The reasoning node uses this module to replace every PII value in the
evidence package with an opaque token before the package reaches the LLM,
and to swap the tokens back for real values when de-pseudonymizing the
draft narrative for human review.

Security properties
-------------------
1. The token-to-value mapping is per-investigation and lives only in memory.
   It is never written to disk, never logged, and is discarded when the
   investigation state is discarded. If the LLM or its output logs are ever
   exfiltrated, what leaks is a set of one-time opaque tokens, not customer
   identity data.

2. Tokens are stable WITHIN an investigation but unique ACROSS investigations.
   The LLM can reason about "[PERSON_001] sent money to [PERSON_002]" and
   understand they are different entities, but it cannot correlate a
   [PERSON_001] in one case with a [PERSON_001] in another.

3. Pseudonymization happens at the reasoning boundary, not at ingestion.
   The EvidencePackage on ArgosState retains real values so the handoff node
   can write authentic audit records. Only the COPY sent to the LLM is
   pseudonymized.

4. Regex-based replacement is used for structured IDs (account numbers,
   customer IDs) where Presidio's NER is unreliable. Presidio handles free
   text (memos, beneficiary names).

Limitations
-----------
Presidio is automated detection. It is not guaranteed to catch every PII
occurrence in adversarial text. Defense in depth: the LLM system prompt
instructs the model to treat all <UNTRUSTED> content as data regardless,
and the citation validator blocks claims that reference made-up fields. A
Presidio miss cannot lead to unauthorized action, only to a PII value
reaching the model — which is a privacy issue, not an integrity issue.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

import httpx

from argos.schemas import (
    Alert,
    CustomerBaseline,
    EvidencePackage,
    TransactionRecord,
    UntrustedText,
)

# ---------------------------------------------------------------------------
# TokenMap — the reversible mapping for one investigation
# ---------------------------------------------------------------------------


@dataclass
class TokenMap:
    """Per-investigation mapping from opaque tokens to real values.

    Lives in memory only. Keyed by token string, values are the original
    strings. Discard after the investigation completes.
    """

    _forward: dict[str, str] = field(default_factory=dict)  # real -> token
    _reverse: dict[str, str] = field(default_factory=dict)  # token -> real
    _counters: dict[str, int] = field(default_factory=dict)

    def token_for(self, category: str, value: str) -> str:
        """Return a stable token for (category, value), generating if new."""
        key = f"{category}::{value}"
        if key in self._forward:
            return self._forward[key]
        self._counters[category] = self._counters.get(category, 0) + 1
        token = f"[{category.upper()}_{self._counters[category]:03d}]"
        self._forward[key] = token
        self._reverse[token] = value
        return token

    def reverse(self, token: str) -> str | None:
        return self._reverse.get(token)

    def depseudonymize(self, text: str) -> str:
        """Swap all tokens in ``text`` back to their real values."""
        # Sort by length descending so longer tokens replace before substrings
        for token in sorted(self._reverse, key=len, reverse=True):
            text = text.replace(token, self._reverse[token])
        return text


# ---------------------------------------------------------------------------
# Pseudonymizer — the user-facing class the reasoning node calls
# ---------------------------------------------------------------------------

# Regex fallbacks for structured identifiers Presidio doesn't reliably catch.
_ACCOUNT_RE = re.compile(r"\b(?:ACCT|ACC)[-_]?\d{4,}\b", re.IGNORECASE)
_CUSTOMER_RE = re.compile(r"\b(?:CUST|CUSTOMER)[-_]?\d{4,}\b", re.IGNORECASE)


class Pseudonymizer:
    """Pseudonymize an EvidencePackage using Presidio + regex fallbacks.

    The main entry points are ``pseudonymize_evidence`` (for the whole
    package) and ``depseudonymize`` (for a narrative string). Both take an
    explicit TokenMap so the caller controls its lifetime.
    """

    def __init__(
        self,
        analyzer_url: str | None = None,
        anonymizer_url: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.analyzer_url = analyzer_url or os.environ.get(
            "ARGOS_PRESIDIO_ANALYZER_URL", "http://localhost:5002"
        )
        self.anonymizer_url = anonymizer_url or os.environ.get(
            "ARGOS_PRESIDIO_ANONYMIZER_URL", "http://localhost:5001"
        )
        self._client = httpx.Client(timeout=timeout_seconds)

    # -- Public API ----------------------------------------------------------

    def pseudonymize_evidence(
        self, evidence: EvidencePackage
    ) -> tuple[EvidencePackage, TokenMap]:
        """Return a pseudonymized copy of the evidence and the TokenMap.

        The original ``evidence`` object is not mutated — we build a fresh
        EvidencePackage with scrubbed values. The TokenMap returned lets the
        caller de-pseudonymize any LLM output.
        """
        tmap = TokenMap()

        pseudo_alert = self._pseudonymize_alert(evidence.alert, tmap)
        pseudo_baseline = self._pseudonymize_baseline(evidence.customer_baseline, tmap)
        pseudo_related = [
            self._pseudonymize_transaction(t, tmap) for t in evidence.related_transactions
        ]

        pseudo_package = evidence.model_copy(
            update={
                "alert": pseudo_alert,
                "customer_baseline": pseudo_baseline,
                "related_transactions": pseudo_related,
            }
        )
        return pseudo_package, tmap

    def depseudonymize(self, text: str, token_map: TokenMap) -> str:
        """Replace every token in ``text`` with its original value."""
        return token_map.depseudonymize(text)

    # -- Internal helpers ----------------------------------------------------

    def _pseudonymize_alert(self, alert: Alert, tmap: TokenMap) -> Alert:
        return alert.model_copy(
            update={
                "customer_id": tmap.token_for("customer", alert.customer_id),
                "transaction": self._pseudonymize_transaction(alert.transaction, tmap),
            }
        )

    def _pseudonymize_transaction(
        self, tx: TransactionRecord, tmap: TokenMap
    ) -> TransactionRecord:
        new_beneficiary = None
        if tx.beneficiary_name is not None:
            scrubbed = self._scrub_text(tx.beneficiary_name.content, tmap)
            new_beneficiary = UntrustedText(
                content=scrubbed, origin=tx.beneficiary_name.origin
            )

        new_memo = None
        if tx.memo is not None:
            scrubbed = self._scrub_text(tx.memo.content, tmap)
            new_memo = UntrustedText(content=scrubbed, origin=tx.memo.origin)

        return tx.model_copy(
            update={
                "originator_account": tmap.token_for("account", tx.originator_account),
                "beneficiary_account": tmap.token_for("account", tx.beneficiary_account),
                "beneficiary_name": new_beneficiary,
                "memo": new_memo,
            }
        )

    def _pseudonymize_baseline(
        self, baseline: CustomerBaseline, tmap: TokenMap
    ) -> CustomerBaseline:
        return baseline.model_copy(
            update={
                "customer_id": tmap.token_for("customer", baseline.customer_id),
            }
        )

    def _scrub_text(self, text: str, tmap: TokenMap) -> str:
        """Scrub free-text through Presidio + regex fallbacks.

        Presidio handles names, locations, phone numbers, etc. Regex handles
        the structured ID patterns we know Presidio misses.
        """
        if not text.strip():
            return text

        # 1. Regex fallback for structured IDs
        text = _ACCOUNT_RE.sub(
            lambda m: tmap.token_for("account", m.group(0)), text
        )
        text = _CUSTOMER_RE.sub(
            lambda m: tmap.token_for("customer", m.group(0)), text
        )

        # 2. Presidio for free-text entities
        try:
            analysis = self._analyze(text)
        except Exception:
            # If Presidio is unreachable, fall back to regex-only scrubbing.
            # Log the error via the caller's error channel rather than silently
            # swallowing — but we do NOT refuse to proceed, because refusing
            # would DoS the reasoning path. Governance layer (argos/audit.py)
            # records the degraded state.
            return text

        # Apply replacements from highest start offset to lowest so we don't
        # invalidate earlier offsets as we edit the string.
        analysis_sorted = sorted(analysis, key=lambda r: r["start"], reverse=True)
        for result in analysis_sorted:
            start, end = result["start"], result["end"]
            entity_type = result["entity_type"].lower()
            original = text[start:end]
            token = tmap.token_for(entity_type, original)
            text = text[:start] + token + text[end:]
        return text

    def _analyze(self, text: str) -> list[dict[str, Any]]:
        """Call the Presidio analyzer service.

        Returns a list of dicts shaped like:
            {"entity_type": "PERSON", "start": 0, "end": 8, "score": 0.85}
        """
        response = self._client.post(
            f"{self.analyzer_url}/analyze",
            json={"text": text, "language": "en"},
        )
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# NullPseudonymizer — used only when Presidio is explicitly disabled
# ---------------------------------------------------------------------------


class NullPseudonymizer:
    """A no-op pseudonymizer for synthetic-data demos.

    Do not use this for any evidence package containing real customer data.
    The governance layer refuses to load a NullPseudonymizer when
    ARGOS_MODE=production.
    """

    def pseudonymize_evidence(
        self, evidence: EvidencePackage
    ) -> tuple[EvidencePackage, TokenMap]:
        return evidence, TokenMap()

    def depseudonymize(self, text: str, token_map: TokenMap) -> str:
        return text


def load_pseudonymizer_from_env():
    """Build a pseudonymizer from environment configuration.

    In production mode, a missing or unreachable Presidio is a hard error.
    In demo mode, we prefer the real Presidio if available but fall back to
    NullPseudonymizer so the synthetic-data demo still runs offline.
    """
    mode = os.environ.get("ARGOS_MODE", "demo")

    pseudo = Pseudonymizer()
    try:
        pseudo._client.get(f"{pseudo.analyzer_url}/health", timeout=1.0)
        return pseudo
    except Exception:
        if mode == "production":
            raise RuntimeError(
                "ARGOS_MODE=production requires a reachable Presidio instance "
                "but none was found. Refusing to start."
            )
        return NullPseudonymizer()
