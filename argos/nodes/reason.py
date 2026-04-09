"""Reasoning node — the single LLM invocation in the entire Argos graph.

This is THE security-critical node. Everything about it is designed to keep
the LLM's influence bounded, auditable, and recoverable when things go wrong.

What it does
------------
1. Pseudonymizes PII in the evidence package (via Presidio) so the LLM sees
   opaque tokens, not real names or accounts.
2. Builds a structured user prompt from the pseudonymized package.
3. Calls the reasoning backend (Ollama in demo, vLLM + XGrammar in production)
   with the locked system prompt from argos/prompts.py.
4. Validates every citation in the returned recommendation against the actual
   evidence package — claims pointing to non-existent fields cause the case
   to be flagged for human review rather than blindly accepted.
5. De-pseudonymizes the draft narrative so analysts see real names.

What it does NOT do
-------------------
- Call any external API other than the LLM backend.
- Access any filesystem path other than through pseudonymizer fixtures.
- Persist state anywhere — per-investigation only.
- Retry on reasoning errors (those flow to human review; see handoff node).

Security notes
--------------
The pseudonymization in this node is in-memory per-investigation. The
token-to-value mapping does not cross investigation boundaries and does not
persist. If the LLM or its logs are ever compromised, what leaks is a set of
one-time opaque tokens, not customer identity data.
"""

from __future__ import annotations

from typing import Callable, Coroutine

from argos.prompts import SYSTEM_PROMPT, build_user_prompt
from argos.reasoning import ReasoningBackend, ReasoningBackendError
from argos.schemas import (
    ArgosState,
    Disposition,
    DispositionCitation,
    DispositionRecommendation,
    EvidencePackage,
    NodeResult,
)

# ---------------------------------------------------------------------------
# Citation validation
# ---------------------------------------------------------------------------


def _field_exists_at_path(obj: object, path: str) -> bool:
    """Check whether a dotted path resolves to an actual field on a Pydantic
    model or dict-like object.

    Handles simple dotted access and ``list[n]`` index syntax. Missing fields
    return False — this is the validator that catches made-up citations.
    """
    current: object = obj
    for segment in path.split("."):
        # Support list[n] indexing
        if "[" in segment and segment.endswith("]"):
            name, idx_str = segment[:-1].split("[", 1)
            try:
                idx = int(idx_str)
            except ValueError:
                return False
            current = getattr(current, name, None)
            if current is None:
                return False
            try:
                current = current[idx]
            except (IndexError, TypeError):
                return False
            continue

        if hasattr(current, segment):
            current = getattr(current, segment)
        elif isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return False
    return True


def validate_citations(
    recommendation: DispositionRecommendation,
    evidence: EvidencePackage,
) -> list[DispositionCitation]:
    """Return the subset of citations whose evidence_path does NOT resolve.

    An empty return value means every citation checks out. A non-empty return
    value means the recommendation is making claims about fields that don't
    exist — possibly a hallucination, possibly an injection attempt, either
    way a reason to force human review.
    """
    invalid = []
    for citation in recommendation.key_findings:
        if not _field_exists_at_path(evidence, citation.evidence_path):
            invalid.append(citation)
    return invalid


# ---------------------------------------------------------------------------
# The node factory
# ---------------------------------------------------------------------------


def make_reason_node(
    backend: ReasoningBackend,
    pseudonymizer=None,  # argos.privacy.Pseudonymizer, typed loosely until Batch 3
) -> Callable[[ArgosState], Coroutine[None, None, NodeResult]]:
    """Return an async LangGraph node closing over backend and pseudonymizer.

    The pseudonymizer argument is optional in Batch 2 (the real Presidio
    wrapper ships in Batch 3). When None, the raw evidence package is sent
    to the LLM — acceptable for the synthetic demo data but NEVER acceptable
    for real customer data. The governance layer (Batch 3) will refuse to
    start in production mode if the pseudonymizer is not configured.
    """

    async def reason(state: ArgosState) -> NodeResult:
        assert state.evidence_package is not None, "package_evidence must run first"

        evidence = state.evidence_package

        # Pseudonymize the package if a pseudonymizer is provided.
        if pseudonymizer is not None:
            pseudo_evidence, token_map = pseudonymizer.pseudonymize_evidence(evidence)
        else:
            pseudo_evidence, token_map = evidence, {}

        user_prompt = build_user_prompt(pseudo_evidence)

        try:
            recommendation = await backend.reason(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt,
            )
        except ReasoningBackendError as e:
            # Reasoning failure is NOT fatal to the investigation — we just
            # route to human review with an error flag. Never guess.
            return {
                "recommendation": _force_review("Reasoning backend error", str(e)),
                "errors": [*state.errors, f"reason_node: {e}"],
            }

        # Validate every citation against the real (non-pseudonymized) package.
        # Both packages have the same field paths — pseudonymization replaces
        # values, not structure.
        invalid_citations = validate_citations(recommendation, evidence)
        if invalid_citations:
            bad_paths = ", ".join(c.evidence_path for c in invalid_citations)
            return {
                "recommendation": _force_review(
                    "Invalid citations",
                    f"Model cited non-existent evidence fields: {bad_paths}",
                ),
                "errors": [
                    *state.errors,
                    f"reason_node: invalid citations: {bad_paths}",
                ],
            }

        # De-pseudonymize the narrative so the reviewing analyst sees real names.
        if pseudonymizer is not None and recommendation.draft_narrative:
            clear_narrative = pseudonymizer.depseudonymize(
                recommendation.draft_narrative, token_map
            )
            recommendation = recommendation.model_copy(
                update={"draft_narrative": clear_narrative}
            )

        return {"recommendation": recommendation}

    return reason


def _force_review(reason_short: str, reason_detail: str) -> DispositionRecommendation:
    """Build a safe fallback recommendation when reasoning fails or is untrusted.

    Uses only short, hard-coded strings. The error detail is deliberately NOT
    embedded in any field because exception messages can be arbitrarily long
    (full tracebacks, repeated validation errors, etc.) and would risk the
    fallback itself failing schema validation. The detail is logged instead.
    """
    import sys

    # Log the detail so we don't lose it, but don't put it in the recommendation.
    print(
        f"[argos:reason] force-escalation: {reason_short} | detail: {reason_detail}",
        file=sys.stderr,
        flush=True,
    )

    return DispositionRecommendation(
        disposition=Disposition.ESCALATE_TO_CASE,
        confidence=0.0,
        key_findings=[
            DispositionCitation(
                claim="Automatic escalation: automated reasoning step could not be trusted. Full human review required.",
                evidence_path="alert.alert_id",
            )
        ],
        draft_narrative=None,
        analyst_notes="Forced escalation by Argos reason node. See server logs for details.",
    )
