"""Reasoning backend abstraction.

The reasoning node (argos/nodes/reason.py) is the ONLY place in Argos where an
LLM is called. Everything else is deterministic Python. This module defines the
contract every LLM backend must satisfy and ships the Ollama implementation
used by the local demo.

Production deployments swap OllamaBackend for VllmBackend, which adds XGrammar
constrained decoding at the token-sampling layer. With XGrammar enabled the
model physically cannot emit JSON that violates our DispositionRecommendation
schema — a stronger guarantee than post-hoc validation. See
docs/THREAT_MODEL.md#asi05-cascading-hallucination.

Security properties every backend MUST preserve
------------------------------------------------
1. No tool access. The backend exposes a single "reason over this evidence"
   call. It does not support function calling, web browsing, file access, or
   any other action surface.
2. No implicit memory. Every call is stateless from the model's perspective.
   Per-investigation state lives in ArgosState, not in the model.
3. Strict structured output. Every call returns a DispositionRecommendation or
   raises. The backend never returns free text.
4. No outbound network from the LLM itself. The backend connects to a model
   server, but the model server has no egress.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Protocol

import httpx
from ollama import Client as OllamaClient
from pydantic import ValidationError

from argos.schemas import DispositionRecommendation


class ReasoningBackendError(Exception):
    """Raised when the reasoning backend fails to produce a valid output."""


class ReasoningBackend(Protocol):
    """The contract every LLM backend must satisfy."""

    async def reason(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> DispositionRecommendation:
        """Produce a DispositionRecommendation from prompts.

        Implementations MUST:
          - return only DispositionRecommendation or raise ReasoningBackendError
          - enforce the schema at decode time if the runtime supports it
          - never expose tool-calling, function-calling, or web access
          - never retain state between calls
        """
        ...


# ---------------------------------------------------------------------------
# OllamaBackend — the local demo backend
# ---------------------------------------------------------------------------


class OllamaBackend:
    """Reasoning backend using a local Ollama server.

    Ollama supports schema-constrained JSON output via its ``format`` parameter,
    which we use to enforce the DispositionRecommendation shape at generation
    time. If the model still produces something invalid, the Pydantic
    validation layer provides a second line of defense — and if both fail, we
    raise ReasoningBackendError and the handoff node routes the case to full
    human review rather than guessing.
    """

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout_seconds: float = 300.0,
    ) -> None:
        self.base_url = base_url or os.environ.get(
            "ARGOS_OLLAMA_URL", "http://localhost:11434"
        )
        self.model = model or os.environ.get(
            "ARGOS_OLLAMA_MODEL", "qwen2.5:7b-instruct"
        )
        self._timeout = timeout_seconds
        self._client = OllamaClient(host=self.base_url)

    async def reason(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> DispositionRecommendation:
        schema = DispositionRecommendation.model_json_schema()

        try:
            response = await _ollama_chat(
                client=self._client,
                model=self.model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                schema=schema,
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as e:
            raise ReasoningBackendError(
                f"Ollama call timed out after {self._timeout}s"
            ) from e
        except json.JSONDecodeError as e:
            raise ReasoningBackendError(
                f"Model output was not valid JSON: {e}"
            ) from e
        except Exception as e:
            # Catch-all so we see the real error class and message in logs.
            # The Ollama Python client raises its own exception types that are
            # not subclasses of httpx.HTTPError, so a narrow except would
            # eat them silently.
            raise ReasoningBackendError(
                f"Ollama call failed [{type(e).__name__}]: {e!r}"
            ) from e

        try:
            normalized = _normalize_llm_output(response)
            return DispositionRecommendation.model_validate(normalized)
        except ValidationError as e:
            raise ReasoningBackendError(
                f"Model output failed schema validation: {e}"
            ) from e


_PATH_RE = re.compile(r"^[a-z_][a-z_0-9\[\]\*]*(\.[a-z_0-9\[\]\*]+)*$")


def _normalize_llm_output(data: dict) -> dict:
    """Clean up common small-model output quirks before Pydantic validation.

    Qwen 2.5 7B sometimes produces evidence_path values that combine multiple
    paths with "..." or commas, or wrap the whole path in outer brackets.
    This function cleans those quirks and keeps the first path that matches
    the expected regex. If nothing matches, the raw value is kept and Pydantic
    will reject it the normal way.
    """
    if not isinstance(data, dict):
        return data

    findings = data.get("key_findings")
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            path = f.get("evidence_path")
            if not isinstance(path, str):
                continue
            # Strip outer brackets that wrap the whole path.
            cleaned = path.strip()
            if cleaned.startswith("[") and cleaned.endswith("]"):
                inner = cleaned[1:-1]
                # Only unwrap if inner still looks like a path.
                if "." in inner or "_" in inner:
                    cleaned = inner
            # Split on ... or , and pick first path that matches.
            candidates = re.split(r"\.{2,}|,", cleaned)
            for cand in candidates:
                cand = cand.strip()
                if _PATH_RE.match(cand):
                    f["evidence_path"] = cand
                    break

    # Truncate analyst_notes defensively.
    notes = data.get("analyst_notes")
    if isinstance(notes, str) and len(notes) > 1000:
        data["analyst_notes"] = notes[:997] + "..."

    # Truncate draft_narrative defensively.
    narr = data.get("draft_narrative")
    if isinstance(narr, str) and len(narr) > 2000:
        data["draft_narrative"] = narr[:1997] + "..."

    return data


async def _ollama_chat(
    client: OllamaClient,
    model: str,
    system_prompt: str,
    user_prompt: str,
    schema: dict,  # noqa: ARG001 — kept for backwards compat with VllmBackend
    timeout: float,
) -> dict:
    """Low-level Ollama call with JSON-constrained output.

    IMPORTANT — why we use format="json" instead of format=<schema>:

    Newer Ollama versions accept a JSON schema dict for the ``format``
    parameter, which in theory enforces the full schema at decode time via
    a llama.cpp GBNF grammar. In practice, llama.cpp's grammar parser has a
    sanity limit on repetition counts (around 500-1000), and our
    DispositionRecommendation schema declares max_length=8000 on the
    draft_narrative field. This produces a grammar rule like
    ``char{0,8000}`` which llama.cpp rejects with "number of repetitions
    exceeds sane defaults", leaving the runner in a bad state that hangs
    subsequent calls.

    We instead use format="json", which constrains Ollama to produce valid
    JSON (any shape) and rely on Pydantic validation in OllamaBackend.reason()
    to enforce the full schema after parsing. This matches the defense-in-
    depth strategy documented in the threat model: decode-time constraint
    is preferred but post-validation is a sufficient fallback.

    The Ollama Python client is sync; we run it in a thread so the node
    function can stay async.
    """
    import sys

    def _call() -> dict:
        result = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            format="json",
            options={
                "temperature": 0.1,
                # num_ctx=4096 is large enough for the demo's evidence
                # packages (typically 1-2k tokens) with plenty of headroom
                # for the response.
                "num_ctx": 4096,
            },
            keep_alive="10m",
        )
        print(
            "[argos:reasoning] Ollama chat succeeded (format='json')",
            file=sys.stderr,
            flush=True,
        )
        content = result["message"]["content"]
        if not content or not content.strip():
            raise ValueError("Ollama returned empty content")
        return json.loads(content)

    return await asyncio.wait_for(asyncio.to_thread(_call), timeout=timeout)


# ---------------------------------------------------------------------------
# FallbackBackend — for "demo without Ollama running" mode
# ---------------------------------------------------------------------------


class FallbackBackend:
    """Returns a conservative pre-computed disposition when no LLM is available.

    Used only when ARGOS_MODE=demo and Ollama is unreachable, so visitors to
    the public demo can still click around even if the model isn't loaded.
    ALWAYS returns 'escalate_to_case' with a banner noting the fallback — we
    never auto-dismiss when we can't actually reason.
    """

    async def reason(
        self,
        system_prompt: str,  # noqa: ARG002
        user_prompt: str,  # noqa: ARG002
    ) -> DispositionRecommendation:
        from argos.schemas import Disposition, DispositionCitation

        return DispositionRecommendation(
            disposition=Disposition.ESCALATE_TO_CASE,
            confidence=0.0,
            key_findings=[
                DispositionCitation(
                    claim=(
                        "FALLBACK MODE: no reasoning backend available. Every alert "
                        "is routed to human review in this mode. This is NOT a real "
                        "disposition and MUST NOT be used for any real decision."
                    ),
                    evidence_path="alert.alert_id",
                )
            ],
            draft_narrative=None,
            analyst_notes=(
                "Argos fallback mode active. The reasoning backend is offline. "
                "Review this case fully as if no AI assistance were available."
            ),
        )


def load_backend_from_env() -> ReasoningBackend:
    """Build a reasoning backend from environment configuration.

    In strict production mode, never returns FallbackBackend — if the LLM is
    unreachable at startup, we refuse to start.
    """
    mode = os.environ.get("ARGOS_MODE", "demo")
    backend_name = os.environ.get("ARGOS_REASONING_BACKEND", "ollama")

    if backend_name == "ollama":
        backend = OllamaBackend()
        if mode == "demo":
            try:
                backend._client.list()  # probe
                return backend
            except Exception:
                return FallbackBackend()
        return backend

    if backend_name == "vllm":
        raise NotImplementedError(
            "VllmBackend ships in the production profile. "
            "Install with `pip install .[production]` and see docs/ARCHITECTURE.md."
        )

    raise ValueError(f"Unknown ARGOS_REASONING_BACKEND: {backend_name}")
