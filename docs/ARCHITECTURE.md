# Argos Architecture

This document explains how Argos works end-to-end for developers who want to
extend it, integrate with it, or audit it. For the security argument, see
`THREAT_MODEL.md`. For what's in and out of scope, see `ROADMAP.md`.

## The one-minute overview

Argos is a middleware layer between a transaction monitoring system and a
case management system. It takes a flagged alert, gathers the evidence an
analyst would otherwise gather by hand, runs one LLM call to produce a
disposition recommendation with cited evidence, and hands the complete
package to a human reviewer.

```
┌──────────────────────┐     ┌─────────┐     ┌──────────────────────┐
│  Monitoring system   │────▶│  Argos  │────▶│  Case management    │
│  (Actimize, SAS,     │     │         │     │  (TheHive, custom,   │
│   Verafin, homegrown)│     │         │     │   etc.)              │
└──────────────────────┘     └─────────┘     └──────────────────────┘
       Alert in                                 Recommendation out
```

Argos is **not** on the authorization hot path. Transactions are authorized
by whatever system the bank already uses, with sub-100ms latency. Argos
operates after the alert has fired, in the seconds-to-minutes range, and
produces a recommendation for a human to review.

## The investigation graph

Every investigation is a single pass through a LangGraph state machine
with exactly six nodes and one conditional edge.

```
              START
                │
                ▼
           ┌─────────┐    Fetches customer baseline, prior alert count.
           │ intake  │    Deterministic. No LLM.
           └─────────┘
                │
                ▼
       ┌────────────────┐ Screens beneficiary and counterparty against
       │ sanctions_check│ OFAC / EU / UN / UK OFSI lists. Deterministic.
       └────────────────┘
            │        │
            │        │ (primary hit)
  (continue)│        └──────────────┐
            ▼                       │
     ┌──────────────────┐           │  Routed directly to handoff.
     │ behavioral_delta │           │  LLM is bypassed entirely on
     └──────────────────┘           │  hard sanctions hits.
            │                       │
            ▼                       │
    ┌───────────────────┐           │
    │ package_evidence  │           │
    └───────────────────┘           │
            │                       │
            ▼                       │
       ┌─────────┐                  │
       │ reason  │  ← THE ONLY LLM  │
       └─────────┘                  │
            │                       │
            ▼                       │
       ┌─────────┐ ◀────── ─────────┘
       │ handoff │
       └─────────┘
            │
            ▼
           END
```

The nodes live in `argos/nodes/`. The wiring lives in `argos/graph.py`. The
conditional edge after `sanctions_check` is the only branching logic in the
entire graph — it exists because hard sanctions hits must never reach the
reasoning LLM.

### Node responsibilities

**`intake`** (`argos/nodes/intake.py`) — fetches the 90-day customer
baseline and the count of prior alerts on this customer. Deterministic,
records provenance.

**`sanctions_check`** (`argos/nodes/sanctions.py`) — runs sanctions
screening on the beneficiary and counterparty. A primary hit sets
`hard_sanctions_override` on the state, which the graph router uses to
bypass the reasoning node.

**`behavioral_delta`** (`argos/nodes/behavioral.py`) — computes explicit
numeric features comparing the alerted transaction to the baseline: amount
z-score, amount vs p95 ratio, new-counterparty flag, new-country flag,
out-of-hours flag, velocity in 1h and 24h windows. Pure Python, no LLM.

**`package_evidence`** (`argos/nodes/package.py`) — assembles the final
`EvidencePackage` the reasoning node will read. This is an aggregation
node; it does not add new data. The `EvidencePackage` is the complete and
sole input to the LLM.

**`reason`** (`argos/nodes/reason.py`) — the only node that calls an LLM.
Pseudonymizes PII via Presidio, builds the user prompt, calls the
reasoning backend, validates every citation in the result against the
actual evidence package, and de-pseudonymizes the draft narrative.
Reasoning failures force-escalate the case rather than retry.

**`handoff`** (`argos/nodes/handoff.py`) — writes the final investigation
to the append-only audit log and pushes the recommendation to the case
management connector. Also handles the hard-sanctions-override path where
the recommendation is constructed deterministically without the LLM.

## The three layers of schema enforcement

The reasoning LLM produces output that passes through three independent
layers before anything downstream trusts it:

1. **Decode-time constraint.** In production, vLLM + XGrammar enforces the
   `DispositionRecommendation` schema at the token-sampling layer. The
   model physically cannot emit schema-violating output. In the demo,
   Ollama's `format` parameter provides a weaker form of this.

2. **Pydantic validation.** `OllamaBackend.reason()` validates the parsed
   JSON against the Pydantic model. If validation fails, it raises
   `ReasoningBackendError` and the node routes to human review.

3. **Citation validation.** After schema validation passes, the
   `validate_citations` function in `reason.py` walks every citation in
   the recommendation and checks that its `evidence_path` actually
   resolves to a field in the evidence package. Unsupported citations
   force escalation.

Only output that survives all three layers is written to the audit log
and sent to the case management system.

## Data sources and dependency injection

Nodes never talk directly to external systems. They call a `DataSource`
that is injected at graph-build time. This makes nodes trivially unit-
testable — swap in a `StubDataSource` and the whole graph runs offline.

See `argos/data.py` for the `DataSource` protocol and the `StubDataSource`
used by the demo and tests.

Production implementations of `DataSource` will typically wrap:
- The core banking system or data warehouse (for customer baselines and
  recent transactions)
- The sanctions screening APIs (OFAC, EU, UN, UK OFSI, OpenSanctions, etc.)
- The existing case management system (for prior alert counts)

Adding a new method to the `DataSource` protocol is a security-review event
— it expands the set of systems nodes can touch.

## Reasoning backend abstraction

The reasoning node calls a `ReasoningBackend` protocol, not a specific LLM
client. This keeps the LLM swappable.

Ships in v0.1.0:
- **`OllamaBackend`** (`argos/reasoning.py`) — local Ollama hosting Qwen 2.5
  7B. Used by the docker-compose demo. Runs on modest hardware.
- **`FallbackBackend`** — returns a fixed force-escalation recommendation
  when no real LLM is available. Demo mode only.

Coming in v0.2.0:
- **`VllmBackend`** — production backend using vLLM + XGrammar with
  Qwen 2.5 32B. Requires CUDA. See the `production` install extra.

To add a new backend, implement the single `reason()` method in the
`ReasoningBackend` protocol. The contract is narrow on purpose:
one call in, one `DispositionRecommendation` out, no tools, no memory.

## Privacy layer

`argos/privacy.py` wraps Microsoft Presidio to pseudonymize PII in the
evidence package before the reasoning node sees it, and to de-pseudonymize
the draft narrative for human review.

Pseudonymization is **reversible and per-investigation**. The token-to-value
map lives in a `TokenMap` object on the local call stack and is discarded
when the investigation completes. If the LLM or its logs are ever leaked,
what leaks is a set of one-time opaque tokens, not customer identity data.

Regex fallbacks handle structured identifiers (account numbers, customer
IDs) that Presidio's NER does not reliably detect. Presidio handles free
text (names, locations, phone numbers, etc.) in memos and beneficiary
names.

## Audit and governance

**The audit log** (`argos/audit.py`) is an append-only JSONL file where
each entry contains the full decision record and is hash-chained to the
previous entry. Tampering is detectable by running `FileAuditLog.verify()`.
Production deployments should back this with WORM storage or a signed
append-only log service.

**The policy layer** (`policies/argos.rego`) contains OPA Rego policies
enforced by the Microsoft Agent Governance Toolkit at runtime. The
policies encode:
- Per-node tool allow-lists (the reasoning node has an empty allow-list)
- Network egress restrictions on the reasoning node
- Credential TTL limits
- Circuit breaker conditions
- Sanctions override enforcement

Policy violations are denied at sub-millisecond latency and logged as
security events.

## Running it

**Local demo (laptop):**
```bash
docker compose up
# Open http://localhost:8080
```

The first run pulls Ollama's qwen2.5:7b-instruct model (~4.4 GB). Subsequent
runs are instant.

**Unit tests:**
```bash
make test
```

**Red-team corpus (Hermes Test):**
```bash
make hermes
```

**Production deployment:**

Not yet documented. The shape of a production deployment is:
- vLLM hosting Qwen 2.5 32B on a GPU node (A100 or similar)
- Presidio analyzer and anonymizer services
- Argos engine behind a REST gateway
- Hash-chained audit log backed by WORM storage
- Real `DataSource` implementations hitting core banking + sanctions APIs
- Case connector pointing at the target organization's case tool

A Helm chart for Kubernetes deployment is on the v0.2.0 roadmap.

## Where to start reading the code

In rough order of architectural importance:

1. `argos/schemas.py` — the contracts. Every other file builds on these.
2. `argos/graph.py` — the wiring. Fits on one screen.
3. `argos/prompts.py` — the system prompt. Read the comment tags.
4. `argos/nodes/reason.py` — the security-critical LLM node.
5. `docs/THREAT_MODEL.md` — why everything above is shaped the way it is.
