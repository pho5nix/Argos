"""LangGraph wiring for the Argos investigation flow.

The graph has exactly six nodes and one conditional edge. Everything about
this file should be boringly explicit — the shape of the graph is a security
property, and any reviewer should be able to understand the full flow in one
screen of code.

    START
      │
      ▼
    intake
      │
      ▼
    sanctions_check
      │
      ├─(primary hit)─────────────┐
      │                           ▼
      ▼                        handoff
    behavioral_delta              │
      │                           ▼
      ▼                          END
    package_evidence
      │
      ▼
    reason
      │
      ▼
    handoff
      │
      ▼
     END

The conditional edge after sanctions_check is the ONLY branching logic in
the graph. It exists so that hard sanctions hits never reach the reasoning
LLM — see docs/THREAT_MODEL.md for the rationale.
"""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from argos.data import DataSource
from argos.nodes.behavioral import make_behavioral_node
from argos.nodes.handoff import make_handoff_node
from argos.nodes.intake import make_intake_node
from argos.nodes.package import make_package_node
from argos.nodes.reason import make_reason_node
from argos.nodes.sanctions import make_sanctions_node
from argos.reasoning import ReasoningBackend
from argos.schemas import ArgosState


def build_graph(
    data_source: DataSource,
    reasoning_backend: ReasoningBackend,
    pseudonymizer: Any | None = None,
    audit_log: Any | None = None,
    case_connector: Any | None = None,
):
    """Build and compile the Argos investigation graph.

    All dependencies are injected, which makes the graph trivially
    unit-testable — swap in a StubDataSource and a FallbackBackend and you
    can run end-to-end investigations with zero network.
    """
    graph = StateGraph(ArgosState)

    # Register nodes. Node names are prefixed with ``n_`` so they cannot
    # collide with ArgosState field names — LangGraph rejects nodes whose
    # names match state keys.
    graph.add_node("n_intake", make_intake_node(data_source))
    graph.add_node("n_sanctions", make_sanctions_node(data_source))
    graph.add_node("n_behavioral", make_behavioral_node(data_source))
    graph.add_node("n_package", make_package_node())
    graph.add_node(
        "n_reason",
        make_reason_node(reasoning_backend, pseudonymizer=pseudonymizer),
    )
    graph.add_node(
        "n_handoff",
        make_handoff_node(audit_log=audit_log, case_connector=case_connector),
    )

    # Linear edges
    graph.add_edge(START, "n_intake")
    graph.add_edge("n_intake", "n_sanctions")

    # THE conditional edge: hard sanctions hits skip reasoning entirely.
    graph.add_conditional_edges(
        "n_sanctions",
        _route_after_sanctions,
        {
            "continue": "n_behavioral",
            "override": "n_handoff",
        },
    )

    graph.add_edge("n_behavioral", "n_package")
    graph.add_edge("n_package", "n_reason")
    graph.add_edge("n_reason", "n_handoff")
    graph.add_edge("n_handoff", END)

    return graph.compile()


def _route_after_sanctions(state: ArgosState) -> str:
    """Conditional router: primary sanctions hits skip the reasoning node.

    This is intentionally simple — one boolean check, no LLM judgment, no
    soft thresholds. A primary hit means OFAC SDN or equivalent; the law
    does not let the LLM opine on whether a sanctioned party is legitimate.
    """
    if state.hard_sanctions_override:
        return "override"
    return "continue"
