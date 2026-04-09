# Argos Roadmap

This document describes what ships in v0.1.0, what is explicitly out of
scope, and what is planned for future versions.

## v0.1.0 — what ships today

**The investigation engine.**
- Six-node LangGraph flow (intake → sanctions → behavioral → package → reason → handoff)
- Single LLM call per investigation via the `ReasoningBackend` abstraction
- `OllamaBackend` for local demos (Qwen 2.5 7B)
- `FallbackBackend` for when Ollama is unavailable in demo mode

**Security architecture.**
- `UntrustedText` wrapping for all externally-sourced free text
- Citation validation against the evidence package
- Reversible PII pseudonymization via Microsoft Presidio
- Append-only hash-chained audit log
- OPA Rego policies for runtime governance (per-node allow-lists, TTL
  checks, circuit breaker)

**FinCEN SAR narrative drafting.**
- System prompt includes FinCEN narrative structure guidance
- Draft narratives with inline citations anchored to evidence fields
- De-pseudonymization of narratives before human review

**Demo and public showcase.**
- Docker Compose local stack (Ollama + Presidio + Argos)
- Three-pane web UI with clickable citation highlighting
- Synthetic FinCEN-typology dataset with eight scenarios
- The Hermes Test red-team corpus

**Connectors.**
- `StdoutConnector` (demo)
- `TheHiveConnector` (open-source SOAR, suitable for real fraud ops)
- `RestConnector` (generic webhook)

**Documentation.**
- Threat model mapped to OWASP ASI Top 10 2026
- Architecture guide
- "Why publishing the prompt is safe" essay
- This roadmap

## Explicitly out of scope for v0.1.0

These are deliberate non-goals. They are not missing because we ran out of
time; they are missing because adding them to v0.1.0 would compromise the
discipline of the MVP.

- **Hot-path real-time scoring.** Argos is post-alert only. Sub-100ms
  transaction authorization is a different product.

- **Graph neural networks for mule-ring detection.** Valuable and on the
  v0.3.0 roadmap, but v0.1.0 ships without them. The `EvidencePackage`
  schema can accept graph-derived features later without re-architecture.

- **Federated learning across institutions.** Strong long-term
  differentiator. Not relevant until multiple paying customers.

- **Customer-facing APP scam interception.** Fundamentally different
  product (pre-authorization, customer-in-session). Argos is an analyst
  copilot, not a customer intervention.

- **Deepfake voice or image detection.** Out of scope. There are purpose-
  built products for this and Argos does not try to duplicate them.

- **Multi-agent orchestration.** Deliberately single-agent. See
  `THREAT_MODEL.md` ASI07 for the reasoning.

- **Autonomous decision-making at any level.** Every Argos output is a
  recommendation to a human. This is a permanent design commitment, not
  a v0.1.0 limitation.

- **Jurisdiction-specific narrative templates beyond FinCEN.** EU goAML
  is planned for v0.2.0. UK NCA, MAS STRO, AUSTRAC are post-v0.2.0.

## v0.2.0 — planned

- **`VllmBackend`** with XGrammar constrained decoding for production
  deployments. Qwen 2.5 32B as the default model.
- **EU goAML narrative templates** targeted at the AMLR Single Rulebook
  (effective July 2027).
- **Kubernetes Helm chart** for production deployment.
- **Real `DataSource` reference implementations** for at least one common
  data warehouse shape.
- **Agent Governance Toolkit integration** fully wired (Batch 5 ships
  the Rego policies; Batch 6 wires them to the Toolkit runtime).
- **Production-hardened audit log backend.** S3 with object lock as the
  first cloud target.

## v0.3.0 and beyond

- **Graph features for mule-ring and APP-scam detection.** Precomputed as
  batch features, surfaced in the `EvidencePackage`.
- **EU AI Act conformity assessment bundle.** Technical documentation
  templates, logging evidence, human oversight documentation. Designed to
  shorten regulatory review for deploying organizations.
- **Additional jurisdiction templates.** UK NCA, MAS STRO, AUSTRAC,
  Hong Kong JFIU.
- **Benchmark harness against IBM AMLSim and SynthAML.** Published
  precision/recall numbers against reproducible datasets.
- **Federated learning via Flower framework.** Allows multiple institutions
  to improve shared models without sharing raw data.
- **Multi-model consensus (optional).** An optional mode where two
  different LLM backends vote and disagreements force human review. Not
  the default because it doubles cost.

## How to propose a roadmap change

Open a GitHub issue tagged `roadmap`. The criteria for adding something
to v0.2.0 are, in order:

1. **Does it earn its place?** The simplicity discipline is a feature.
   Adding something to the core must remove more complexity than it adds.
2. **Does it maintain the security properties?** Any change must preserve
   or improve the OWASP ASI Top 10 mitigations documented in the threat
   model.
3. **Is there a clear user need?** A design partner asking for it is the
   strongest signal.
4. **Can it be a plugin instead of a core change?** The connector pattern,
   the data source pattern, and the reasoning backend pattern all exist
   so third parties can extend Argos without forking.
