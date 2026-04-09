"""Case management connectors.

The handoff node delivers completed investigations to whatever case
management system the organization uses. This module defines the connector
protocol and ships three implementations:

- **StdoutConnector**: prints cases to stdout. For the demo only.
- **TheHiveConnector**: posts cases to a TheHive instance. TheHive is an
  open-source SOAR platform that works well for fraud case management.
- **RestConnector**: POSTs cases to an arbitrary webhook URL. The escape
  hatch for any system that doesn't have a dedicated connector yet.

Security notes
--------------
- Connectors are the only part of Argos that WRITE to external systems.
  Their credentials are scoped per-investigation and short-lived.
- Every connector call is logged to the audit log by the handoff node
  before the connector is invoked — if the external system rejects the
  case, we still have a record of what we tried to send.
- Connectors never transmit raw LLM output. They transmit the validated,
  citation-checked DispositionRecommendation — if the citation validator
  force-escalated the case, that's what the case system sees.
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol

import httpx

from argos.schemas import Alert, DispositionRecommendation, EvidencePackage


class CaseConnector(Protocol):
    """The contract every case management connector must implement."""

    def create_case(
        self,
        alert: Alert,
        recommendation: DispositionRecommendation,
        evidence_package: EvidencePackage | None,
    ) -> str:
        """Create a case and return the connector's case ID."""
        ...


# ---------------------------------------------------------------------------
# StdoutConnector — the demo backend
# ---------------------------------------------------------------------------


class StdoutConnector:
    """Writes cases to stdout. Used for the local demo and unit tests."""

    def create_case(
        self,
        alert: Alert,
        recommendation: DispositionRecommendation,
        evidence_package: EvidencePackage | None,  # noqa: ARG002
    ) -> str:
        payload = {
            "alert_id": alert.alert_id,
            "disposition": recommendation.disposition.value,
            "confidence": recommendation.confidence,
            "analyst_notes": recommendation.analyst_notes,
            "key_findings": [
                {"claim": c.claim, "evidence_path": c.evidence_path}
                for c in recommendation.key_findings
            ],
            "has_narrative": recommendation.draft_narrative is not None,
        }
        print(f"[argos:case] {json.dumps(payload, separators=(',', ':'))}")
        return f"stdout:{alert.alert_id}"


# ---------------------------------------------------------------------------
# TheHiveConnector — open-source SOAR, good fit for fraud ops
# ---------------------------------------------------------------------------


class TheHiveConnector:
    """Create cases in TheHive via its REST API.

    Keeps the body intentionally small: title, severity, tags, and a
    description containing the cited key findings. The full evidence package
    is NOT uploaded — analysts drill into it through the Argos audit log if
    they need the full trail.
    """

    SEVERITY_MAP = {
        "close_false_positive": 1,
        "insufficient_evidence": 2,
        "refer_to_enhanced_due_diligence": 3,
        "escalate_to_case": 3,
    }

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("ARGOS_THEHIVE_URL", "")
        self.api_key = api_key or os.environ.get("ARGOS_THEHIVE_API_KEY", "")
        if not self.base_url or not self.api_key:
            raise ValueError(
                "TheHiveConnector requires ARGOS_THEHIVE_URL and ARGOS_THEHIVE_API_KEY"
            )
        self._client = httpx.Client(
            timeout=timeout_seconds,
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

    def create_case(
        self,
        alert: Alert,
        recommendation: DispositionRecommendation,
        evidence_package: EvidencePackage | None,  # noqa: ARG002
    ) -> str:
        findings_md = "\n".join(
            f"- {c.claim}  _(evidence: `{c.evidence_path}`)_"
            for c in recommendation.key_findings
        )
        description_parts = [
            f"**Disposition:** {recommendation.disposition.value}",
            f"**Confidence:** {recommendation.confidence:.2f}",
            "",
            "**Key findings:**",
            findings_md,
            "",
            f"**Analyst notes:** {recommendation.analyst_notes}",
        ]
        if recommendation.draft_narrative:
            description_parts.extend(["", "**Draft narrative:**", recommendation.draft_narrative])

        body = {
            "title": f"Argos: alert {alert.alert_id} ({alert.rule_id})",
            "description": "\n".join(description_parts),
            "severity": self.SEVERITY_MAP.get(recommendation.disposition.value, 2),
            "tags": ["argos", f"source:{alert.source.value}", f"rule:{alert.rule_id}"],
        }
        response = self._client.post(f"{self.base_url}/api/case", json=body)
        response.raise_for_status()
        case_id = response.json().get("id", "")
        return f"thehive:{case_id}"


# ---------------------------------------------------------------------------
# RestConnector — generic webhook for any other system
# ---------------------------------------------------------------------------


class RestConnector:
    """Generic REST webhook connector.

    POSTs a standard Argos case payload to a configured URL. The receiving
    system is responsible for translating it into whatever shape its case
    management expects. Suitable for lightweight integrations and for
    bridging to systems that don't have a dedicated Argos connector.
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        auth_header: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.webhook_url = webhook_url or os.environ.get("ARGOS_REST_WEBHOOK_URL", "")
        if not self.webhook_url:
            raise ValueError("RestConnector requires ARGOS_REST_WEBHOOK_URL")
        headers = {}
        auth = auth_header or os.environ.get("ARGOS_REST_AUTH_HEADER")
        if auth:
            headers["Authorization"] = auth
        self._client = httpx.Client(timeout=timeout_seconds, headers=headers)

    def create_case(
        self,
        alert: Alert,
        recommendation: DispositionRecommendation,
        evidence_package: EvidencePackage | None,  # noqa: ARG002
    ) -> str:
        payload: dict[str, Any] = {
            "version": 1,
            "source": "argos",
            "alert": json.loads(alert.model_dump_json()),
            "recommendation": json.loads(recommendation.model_dump_json()),
        }
        response = self._client.post(self.webhook_url, json=payload)
        response.raise_for_status()
        return f"rest:{alert.alert_id}"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def load_connector_from_env() -> CaseConnector:
    name = os.environ.get("ARGOS_CASE_CONNECTOR", "stdout")
    if name == "stdout":
        return StdoutConnector()
    if name == "thehive":
        return TheHiveConnector()
    if name == "rest":
        return RestConnector()
    raise ValueError(f"Unknown ARGOS_CASE_CONNECTOR: {name}")
