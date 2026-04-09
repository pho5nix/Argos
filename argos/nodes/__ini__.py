"""LangGraph nodes for the Argos investigation flow.

Each node is a factory that closes over its dependencies (DataSource,
ReasoningBackend, etc.) and returns an async callable compatible with
LangGraph's state-dict interface.

The full flow:

    intake → sanctions_check → behavioral_delta → package_evidence → reason → handoff
                                                            │
                                                            └─(hard hit)→ handoff

See argos/graph.py for wiring and docs/ARCHITECTURE.md for the overview.
"""
