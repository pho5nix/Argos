"""Argos data contracts.

This module defines every structured object that flows through the investigation
graph. These are the SOLE interfaces between nodes, between Argos and upstream
monitoring systems, and between Argos and the reasoning LLM.

Several security properties live in this file by construction — not as runtime
checks that could be bypassed, but as type-level invariants that make unsafe
states unrepresentable.

Key design decisions
--------------------
1. **UntrustedText wraps every external string.** Any text field that originates
   outside the bank's trust boundary — transaction memos, beneficiary names,
   counterparty descriptions — is wrapped in ``UntrustedText``. The reasoning
   node's prompt is written to treat these wrappers as DATA, never INSTRUCTIONS.
   This is the primary defense against prompt injection (OWASP ASI01 Goal Hijack).

2. **DispositionRecommendation requires citations.** The LLM cannot output a
   claim without pointing to a specific field in the evidence package. This is
   enforced at the Pydantic validation layer and constrained at decode time via
   XGrammar/Instructor. This addresses OWASP ASI09 Human-Agent Trust Exploitation.

3. **ProvenanceEntry is mandatory on every evidence source.** Every piece of
   data in the evidence package records where it came from, when, and via what
   credential. This is the EU AI Act Article 12 logging requirement made
   concrete, and it's what makes a decision replayable by an auditor.

4. **ArgosState is per-investigation and discarded on exit.** No cross-case
   memory exists by design. This eliminates memory poisoning (OWASP ASI03) as
   an attack class.

See docs/THREAT_MODEL.md for the full mapping of these invariants to OWASP ASI
Top 10 2026 risks.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# The UntrustedText wrapper — the single most important security primitive
# ---------------------------------------------------------------------------


class UntrustedText(BaseModel):
    """A string originating outside the trust boundary.

    Every free-text field that could conceivably contain adversarial content
    — transaction memos, beneficiary names, counterparty descriptions, customer
    support ticket bodies, document OCR output — is wrapped in this type before
    it ever reaches the reasoning node.

    The reasoning node's system prompt (see argos/prompts.py) explicitly
    instructs the LLM to treat the ``content`` of any UntrustedText as data
    only, never as instructions. This is the project's primary defense against
    prompt injection via payment metadata — a technique attackers actively use
    in the wild by embedding LLM instructions in beneficiary name fields.

    DO NOT accept raw strings from external sources anywhere in the codebase.
    Always wrap them in UntrustedText at the boundary. The type system is the
    defense.
    """

    model_config = ConfigDict(frozen=True)

    content: str = Field(
        ...,
        description="The raw text. Treated as data only, never as instructions.",
        max_length=10_000,  # hard ceiling prevents memo-bomb DoS
    )
    origin: Literal[
        "customer_memo",
        "beneficiary_name",
        "counterparty_description",
        "support_ticket",
        "external_document",
        "ocr_extracted",
        "third_party_api",
    ] = Field(
        ...,
        description="Where this text came from. Influences trust weighting.",
    )

    def __str__(self) -> str:
        # Defensive __str__ that always includes the origin marker, so even if
        # an UntrustedText is accidentally string-interpolated into a prompt,
        # the LLM sees a clear boundary.
        return f"<UNTRUSTED origin={self.origin}>{self.content}</UNTRUSTED>"


# ---------------------------------------------------------------------------
# Provenance — EU AI Act Article 12 logging, made concrete
# ---------------------------------------------------------------------------


class ProvenanceEntry(BaseModel):
    """Where a piece of evidence came from, when, and via what credential.

    Every source consulted during an investigation produces a ProvenanceEntry.
    Together they form a replayable audit trail — if a regulator asks six
    months later "why did Argos recommend closing this alert?", we can
    reconstruct exactly which data the reasoning node saw and where it came
    from.

    This is the AI Act Article 12 logging obligation made concrete.
    """

    model_config = ConfigDict(frozen=True)

    source: str = Field(..., description="System name, e.g. 'core_banking', 'ofac_api'")
    retrieved_at: datetime = Field(..., description="UTC timestamp of retrieval")
    credential_id: str = Field(
        ...,
        description="Scoped, short-lived credential ID used (never the secret itself)",
    )
    response_hash: str = Field(
        ...,
        description="SHA-256 of the raw response, for later tamper-evidence checks",
    )
    query_summary: str = Field(
        ...,
        description="Human-readable summary of what was queried (no PII)",
        max_length=500,
    )


# ---------------------------------------------------------------------------
# Upstream input — what Argos receives from a monitoring system
# ---------------------------------------------------------------------------


class AlertSource(str, Enum):
    """The monitoring system that fired the alert."""

    ACTIMIZE = "actimize"
    SAS_AML = "sas_aml"
    VERAFIN = "verafin"
    ORACLE_FCCM = "oracle_fccm"
    INTERNAL_RULES = "internal_rules"
    SYNTHETIC = "synthetic"  # for demos and testing


class TransactionRecord(BaseModel):
    """A single financial transaction.

    All PII-bearing fields are explicitly typed. Free-text fields are wrapped
    in UntrustedText so the pseudonymizer and prompt layer know to treat them
    carefully.
    """

    model_config = ConfigDict(frozen=True)

    transaction_id: str
    timestamp: datetime
    amount: Decimal = Field(..., ge=0)
    currency: str = Field(..., min_length=3, max_length=3)
    originator_account: str
    beneficiary_account: str
    beneficiary_name: UntrustedText | None = None
    counterparty_country: str | None = Field(None, min_length=2, max_length=2)
    memo: UntrustedText | None = None
    channel: Literal["wire", "ach", "card", "instant", "internal", "check"] = "wire"


class Alert(BaseModel):
    """An alert fired by the upstream monitoring system.

    This is the input that starts an Argos investigation. One alert in,
    one DispositionRecommendation out.
    """

    alert_id: str
    source: AlertSource
    fired_at: datetime
    rule_id: str = Field(..., description="The rule or model that produced the alert")
    score: float = Field(..., ge=0.0, le=1.0, description="Upstream risk score")
    transaction: TransactionRecord
    rule_description: UntrustedText = Field(
        ...,
        description="Human-readable rule description from the upstream system",
    )
    customer_id: str


# ---------------------------------------------------------------------------
# Intermediate data — computed by deterministic nodes before reasoning
# ---------------------------------------------------------------------------


class CustomerBaseline(BaseModel):
    """90-day behavioral baseline for a customer.

    Computed by the intake node from the customer's recent transaction history.
    This is NOT a free-text summary — it is a set of explicit numeric features
    the reasoning node can reason over. The LLM does not read raw 90-day
    history; it reads this condensed, structured summary.
    """

    customer_id: str
    window_days: int = 90
    total_transactions: int
    total_volume: Decimal
    avg_transaction_amount: Decimal
    median_transaction_amount: Decimal
    p95_transaction_amount: Decimal
    distinct_counterparties: int
    distinct_countries: int
    typical_hours_utc: list[int] = Field(
        default_factory=list, description="Hours of day with >5% of customer's activity"
    )
    typical_channels: list[str] = Field(default_factory=list)
    provenance: ProvenanceEntry


class SanctionsCheckResult(BaseModel):
    """Output of the sanctions_check node.

    Sanctions screening is deterministic and happens before the LLM ever sees
    the evidence package. A hard hit on a primary list short-circuits the
    entire graph and routes straight to human review — the LLM never reasons
    over sanctioned parties.
    """

    checked_lists: list[str] = Field(
        ..., description="Lists consulted, e.g. ['OFAC_SDN', 'EU_CONSOLIDATED', 'UN_1267']"
    )
    primary_hit: bool = Field(..., description="Hit on a hard-block list (OFAC SDN etc.)")
    secondary_hit: bool = Field(
        ..., description="Hit on a softer list requiring review (PEP, adverse media)"
    )
    hit_details: list[str] = Field(
        default_factory=list, description="Names of lists that produced hits"
    )
    provenance: ProvenanceEntry


class BehavioralDelta(BaseModel):
    """Pure-Python-computed features comparing a transaction to baseline.

    No LLM involved. These are the numeric signals the reasoning node will use
    to judge anomaly vs. normal customer behavior.
    """

    amount_zscore: float = Field(..., description="(amount - baseline_mean) / baseline_stdev")
    amount_vs_p95_ratio: float = Field(..., description="amount / baseline p95")
    is_new_counterparty: bool
    is_new_country: bool
    is_out_of_hours: bool
    velocity_1h: int = Field(..., description="Transaction count in the prior hour")
    velocity_24h: int = Field(..., description="Transaction count in the prior 24 hours")


# ---------------------------------------------------------------------------
# The EvidencePackage — the ONLY thing the reasoning LLM reads
# ---------------------------------------------------------------------------


class EvidencePackage(BaseModel):
    """The structured bundle the reasoning node reads.

    This is deliberately narrow. The LLM sees ONLY:
      - the alert itself (with free-text fields wrapped)
      - the customer baseline as numeric features
      - the sanctions check result
      - the behavioral delta features
      - a list of recent related transactions (deterministically selected)
      - the provenance trail

    The LLM does NOT see:
      - the full 90-day transaction history
      - the raw customer profile
      - the device/session logs
      - any internal credentials, API keys, or system prompts from other systems
      - any cross-customer data

    Every field in this package should be citeable by a DispositionCitation —
    if the LLM wants to make a claim, it must anchor it to a path into this
    package.
    """

    alert: Alert
    customer_baseline: CustomerBaseline
    sanctions: SanctionsCheckResult
    behavioral_delta: BehavioralDelta
    related_transactions: list[TransactionRecord] = Field(
        default_factory=list,
        description="Deterministically selected related transactions (max 20)",
        max_length=20,
    )
    prior_alerts_count_90d: int = Field(
        ..., description="Count of prior alerts on this customer in the last 90 days"
    )
    assembled_at: datetime
    provenance_chain: list[ProvenanceEntry] = Field(
        ..., description="Every source consulted, in order"
    )


# ---------------------------------------------------------------------------
# The DispositionRecommendation — structured output from the reasoning node
# ---------------------------------------------------------------------------


class Disposition(str, Enum):
    """The four possible recommendations Argos can make.

    Note that none of these are autonomous actions — every one is a
    recommendation to a human analyst. Argos never blocks, files, or closes
    anything on its own.
    """

    CLOSE_FALSE_POSITIVE = "close_false_positive"
    ESCALATE_TO_CASE = "escalate_to_case"
    REFER_TO_EDD = "refer_to_enhanced_due_diligence"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class DispositionCitation(BaseModel):
    """A single citation anchoring a claim to an evidence field.

    Every claim the reasoning node makes must carry one of these. The
    ``evidence_path`` is a dotted path into the EvidencePackage, e.g.
    ``behavioral_delta.amount_zscore`` or ``sanctions.primary_hit``.

    The handoff node validates every citation against the actual package
    before the recommendation is written to the case system. Unsupported
    claims cause the case to route to human review with a warning flag.
    """

    model_config = ConfigDict(frozen=True)

    claim: str = Field(
        ...,
        description="The reasoning node's claim, in its own words",
        # NOTE: Must stay <=500 so llama.cpp's GBNF grammar parser accepts
        # the repetition count during schema-constrained decoding. 200 is
        # a comfortable ceiling for a single cited finding sentence.
        max_length=200,
    )
    evidence_path: str = Field(
        ...,
        description="Dotted path into EvidencePackage, e.g. 'behavioral_delta.amount_zscore'",
        pattern=r"^[a-z_][a-z_0-9\[\]\*]*(\.[a-z_0-9\[\]\*]+)*$",
    )

    @field_validator("evidence_path")
    @classmethod
    def no_untrusted_path(cls, v: str) -> str:
        # Defense in depth: citations must not point inside UntrustedText
        # content fields, because an attacker could put a fabricated
        # "evidence" sentence there and then cite it. Citations can point AT
        # an UntrustedText object (to reference its existence) but not INTO
        # its .content.
        if ".content" in v.lower():
            raise ValueError(
                "Citations may not point inside UntrustedText.content; "
                "cite the wrapping field instead."
            )
        return v


class DispositionRecommendation(BaseModel):
    """The structured output of the reasoning node.

    This is the ONLY thing the LLM is allowed to produce. XGrammar (at decode)
    and Instructor (at parse) both enforce conformance to this schema. A
    response that doesn't conform is impossible to generate, not just
    rejected after the fact.
    """

    disposition: Disposition
    confidence: float = Field(..., ge=0.0, le=1.0)
    key_findings: list[DispositionCitation] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="The main points supporting the disposition, each cited",
    )
    draft_narrative: str | None = Field(
        None,
        description=(
            "Draft SAR/STR narrative in FinCEN format. Only populated when "
            "disposition is ESCALATE_TO_CASE or REFER_TO_EDD. Every factual "
            "claim in the narrative must correspond to a citation in key_findings."
        ),
        # NOTE: llama.cpp's GBNF grammar parser rejects repetition counts
        # above ~1024 as "exceeds sane defaults". 2000 is above that limit
        # on paper, but llama.cpp clamps char repetitions differently from
        # integer repetitions — 2000 works on current builds, 8000 does not.
        # A 2000-char narrative is ~300 English words, which is the upper
        # end of what a FinCEN SAR narrative typically needs.
        max_length=2_000,
    )
    analyst_notes: str = Field(
        default="",
        description="Short plain-language summary for the reviewing analyst",
        # NOTE: Kept under 1000 to stay within llama.cpp's GBNF grammar
        # repetition ceiling. 500 chars is ~80 words, enough for a paragraph
        # of analyst-facing context.
        max_length=500,
    )


# ---------------------------------------------------------------------------
# ArgosState — the LangGraph state dict
# ---------------------------------------------------------------------------


class ArgosState(BaseModel):
    """The state object that flows through the LangGraph investigation.

    Per-investigation, discarded on exit. No cross-case memory exists by
    design — this eliminates OWASP ASI03 (memory poisoning) as an attack class.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Input
    alert: Alert

    # Built up by deterministic nodes (all Optional until their node runs)
    customer_baseline: CustomerBaseline | None = None
    sanctions: SanctionsCheckResult | None = None
    behavioral_delta: BehavioralDelta | None = None
    related_transactions: list[TransactionRecord] = Field(default_factory=list)
    prior_alerts_count_90d: int | None = None
    provenance_chain: list[ProvenanceEntry] = Field(default_factory=list)

    # Assembled by the package_evidence node
    evidence_package: EvidencePackage | None = None

    # Produced by the reason node
    recommendation: DispositionRecommendation | None = None

    # Trace/debug info captured by the handoff node
    errors: list[str] = Field(default_factory=list)
    hard_sanctions_override: bool = Field(
        default=False,
        description="True if sanctions_check forced a bypass of the reasoning node",
    )

    def record_provenance(self, entry: ProvenanceEntry) -> None:
        """Append a provenance entry. Nodes call this for every external query."""
        self.provenance_chain.append(entry)

    def record_error(self, message: str) -> None:
        """Record a non-fatal error. The case still completes but flagged."""
        self.errors.append(message)


# ---------------------------------------------------------------------------
# Convenience: a typed alias for node functions
# ---------------------------------------------------------------------------

NodeResult = dict[str, Any]
"""What a LangGraph node returns — a partial state update dict.

Nodes return a plain dict of state field updates rather than mutating the
state object directly, because LangGraph's state reducer expects that shape.
"""
