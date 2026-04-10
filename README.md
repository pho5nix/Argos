# Argos

<img width="1376" height="768" alt="Argos_1" src="https://github.com/user-attachments/assets/3404d8c7-fb1f-4c0d-a8d2-f1b48c47fb27" />

---
**Argos is an open-source Alert Investigation Copilot for financial crime teams.**
It sits between your existing transaction-monitoring system and your case
management tool, dispositions false positives in minutes instead of days and
drafts regulator-ready SAR narratives with cited evidence, entirely self-hosted,
entirely inspectable.

Argos is deliberately narrow. It does one thing: it turns a flagged alert into a
structured investigation with a disposition recommendation and a draft narrative
and it hands the result to a human analyst. It does not make autonomous
decisions, it does not touch the authorization path and it does not add new
fraud detection rules to your stack. It removes the four-day manual
investigation bottleneck. That's the entire product.

---

## Why this exists

Legacy transaction-monitoring systems run at roughly 95% false-positive rates.
A major bank might investigate 50,000 alerts a year, 47,500 of them false, at
$500–$1,500 per investigation. The average investigation time has ballooned to
over four days. FinCEN data shows large institutions average **166 days** to
file a SAR against a **30-day** regulatory requirement.

That is not a tuning problem. It is a structural failure. Analysts spend most
of their time gathering the same data from the same six systems and then
writing narratives from scratch, for cases that 90%+ of the time turn out to be
nothing. Argos eliminates the gather-and-draft work so analysts only touch the
cases that actually need human judgment.

## The three numbers

If Argos does not move these three numbers in your pilot, it has failed:

1. **Cost per alert** - target: $15–$40 (from the industry baseline of $500–$1,500)
2. **Time to disposition** - target: under 30 min for escalations, under 2 min for dismissals (from ~4 days)
3. **Time to SAR filing** - target: within the 30-day statutory ceiling (from the 166-day average)

---

## Quickstart (under 5 minutes)

You need: Docker, Docker Compose, 16GB of free RAM, and about 10GB of disk for
the local LLM.

```bash
git clone https://github.com/pho5nix/argos.git
cd argos
cp .env.example .env
docker compose up
```

Then open http://localhost:8080 in your browser. You'll see the Argos demo
running against a synthetic FinCEN-typology dataset. Click any alert in the
left pane to watch the investigation graph execute in real time.

On the first run, Docker Compose will pull the Ollama image and download the
`qwen2.5:7b-instruct` model (~4.4GB). Subsequent runs are instant. If you don't
have Ollama/GPU capacity, the demo falls back to pre-computed dispositions so
the UI still works, clearly labeled as fallback mode.

For production (vLLM + Qwen 2.5 32B on a real GPU), see `docs/ARCHITECTURE.md`.

---

## What's in the box

```
argos/
├── argos/              # The engine — LangGraph flow, nodes, schemas
├── policies/           # OPA Rego policies enforced by Agent Governance Toolkit
├── redteam/            # The Hermes Test — our standing prompt-injection corpus
├── demo/               # The public demo UI and synthetic fixtures
├── docs/               # Threat model, architecture, roadmap
└── tests/              # Unit tests including red-team regression
```

The investigation graph has exactly six nodes:

```
intake → sanctions_check → behavioral_delta → package_evidence → reason → handoff
                                                      │
                                                      └─(hard sanctions hit)─→ handoff
```

The **reason** node is the only node that calls an LLM. It has no tool access,
no network access, no memory beyond the current investigation. It reads a
structured evidence package and produces a structured disposition, nothing
else. Everything else is deterministic Python you can read in an afternoon.

## The trust play

This repository is the same code a bank would deploy inside their VPC. There is
no hidden commercial version with different behavior. The open-source core is
Apache 2.0 and the commercial offering (if any) is limited to support,
enterprise connectors and managed deployments.

**Read the threat model before the code.** It is at `docs/THREAT_MODEL.md` and
it maps every one of the OWASP Top 10 for Agentic Applications 2026 risks to a
concrete architectural mitigation with line-number references. If you find a
gap, open an issue, that's exactly the kind of review asking for.

**Try to break the reasoning node.** The `redteam/` directory contains our
standing corpus of prompt-injection payloads (the "Hermes Test", named after
the trickster who killed Argos in the myth by lulling him to sleep with a
story). Run it with `make hermes`. Submit new payloads via pull request.

## What Argos is NOT

Explicit non-goals for v1, so expectations are clear:

- **Not a replacement for your transaction monitoring system.** Argos consumes
  alerts from whatever you already have (Actimize, SAS, Verafin, Oracle FCCM,
  homegrown rules, whatever).
- **Not on the authorization hot path.** Argos operates post-alert, in the
  seconds-to-minutes range, never in the sub-100ms authorization window.
- **Not an autonomous decision-maker.** Every Argos output is a recommendation
  to a human analyst. The analyst clicks the button.
- **Not a graph-neural-network mule detector.** That's valuable, and it's on
  the v2 roadmap, but it's not what ships in v1.
- **Not a customer-facing APP scam interceptor.** That's a different product.

See `docs/ROADMAP.md` for what's next.

## Security status

| OWASP ASI Top 10 2026 Risk           | Argos Mitigation                                    |
|--------------------------------------|-----------------------------------------------------|
| ASI01 Goal Hijack                    | LLM sees only structured evidence, no raw memos     |
| ASI02 Tool Misuse                    | Reasoning node has zero tool access                 |
| ASI03 Memory Poisoning               | Per-investigation state, discarded on exit          |
| ASI04 Privilege Compromise           | Scoped short-lived credentials per node             |
| ASI05 Cascading Hallucination        | XGrammar constrained decoding + Instructor retry    |
| ASI06 Supply Chain                   | Pinned deps, SBOM generated, signed releases        |
| ASI07 Insecure Inter-Agent Comms     | N/A, single-agent architecture by design           |
| ASI08 Cascading Failures             | Kill switch + circuit breakers, per-case isolation  |
| ASI09 Human-Agent Trust Exploitation | Every claim cites evidence field; unsupported claims flagged in UI |
| ASI10 Rogue Agents                   | No autonomous actions, append-only audit trail      |

Full details with code references: `docs/THREAT_MODEL.md`.

## Dashboard and Alerts
---

### Possibe Structuring
---
<img width="1919" height="916" alt="{5C6F6AEE-0F8B-4999-9CA9-45CA8D0BD74B}" src="https://github.com/user-attachments/assets/6b0e1ad4-85af-4c54-af27-4948d893263d" />

### Velocity Anomaly
---
<img width="1917" height="918" alt="{108E0A6A-82D3-409B-90A0-42A3543B57F6}" src="https://github.com/user-attachments/assets/fea7a91d-76e4-4895-87d9-f2687ae67773" />

### Prompt Injection in Alert
---
<img width="1916" height="918" alt="{DA611F9E-DC99-4DD0-8F87-3B05F18EB72B}" src="https://github.com/user-attachments/assets/6f1679fd-4596-40e1-a285-6ce14ae4a3cf" />


## Narrative
Argos had a hundred eyes. Some slept while others watched. He was eventually
killed by Hermes, the messenger and patron of thieves, who told him a long
story until every eye closed. The entire security architecture of this project
assumes attackers will try exactly that trick, which is why the reasoning node
cannot act on anything it reads, only reason about it.


## Contributing

The fastest way to help right now: run the Hermes Test with your own payloads
and submit the ones that break us. Second fastest: read `docs/THREAT_MODEL.md`
and tell us what we missed.

## License

Apache 2.0. See `LICENSE`.

---

