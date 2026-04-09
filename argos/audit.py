"""Append-only hash-chained audit log — the Peacock's Tail.

Every investigation produces exactly one entry in this log, containing the
full decision record: the alert ID, the recommendation, the provenance
chain of every external query, any errors encountered, and the hash of the
previous entry. Together the entries form a chain where tampering with any
historical record breaks every subsequent hash, which is detectable by
running ``verify()``.

This is the EU AI Act Article 12 "automatic recording of events" obligation
made concrete, and it's also the artifact a regulator asks for when they
want to know "why did Argos recommend closing this alert six months ago?".

Storage
-------
The demo backend is a local JSONL file. Production deployments should use:
  - WORM (write-once-read-many) storage, or
  - S3 with object lock, or
  - A signed append-only stream like AWS CloudTrail Lake

The interface is the same; only the persistence layer changes. Swap the
``FileAuditLog`` for a cloud-backed implementation by implementing the
``AuditLog`` protocol.

Why hash-chained instead of just "append-only"
----------------------------------------------
Append-only on a filesystem is a convention, not a guarantee — a sufficiently
privileged attacker can rewrite the file. Hash-chaining makes silent edits
impossible: any modification to entry N invalidates the hash of entry N+1,
which invalidates N+2, and so on. An auditor running ``verify()`` detects
the break immediately.

This does NOT protect against append-only-plus-rewrite attacks (where the
attacker rewrites the entire file from the tampered point forward). For
that, production deployments additionally sign the chain head to an
external timestamping authority or external log service. The demo does not.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from argos.schemas import DispositionRecommendation, ProvenanceEntry

GENESIS_HASH = "0" * 64
"""The previous-hash used for the first entry in the chain."""


# ---------------------------------------------------------------------------
# AuditLog protocol
# ---------------------------------------------------------------------------


class AuditLog(Protocol):
    """The contract every audit log backend must implement."""

    def append(
        self,
        alert_id: str,
        recommendation: DispositionRecommendation,
        provenance_chain: list[ProvenanceEntry],
        errors: list[str],
        hard_sanctions_override: bool,
    ) -> str:
        """Append one entry and return the new chain-head hash."""
        ...

    def verify(self) -> tuple[bool, str | None]:
        """Walk the chain and verify every hash link.

        Returns ``(ok, error_message)``. A healthy chain returns
        ``(True, None)``. A broken chain returns ``(False, "...")`` with a
        description of the first broken link.
        """
        ...


# ---------------------------------------------------------------------------
# AuditEntry — the record shape
# ---------------------------------------------------------------------------


@dataclass
class AuditEntry:
    sequence: int
    timestamp: str
    alert_id: str
    recommendation: dict[str, Any]
    provenance: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    hard_sanctions_override: bool = False
    prev_hash: str = GENESIS_HASH
    this_hash: str = ""

    def compute_hash(self) -> str:
        """Compute this entry's hash from its canonicalized body."""
        body = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "recommendation": self.recommendation,
            "provenance": self.provenance,
            "errors": self.errors,
            "hard_sanctions_override": self.hard_sanctions_override,
            "prev_hash": self.prev_hash,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_json_line(self) -> str:
        d = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "recommendation": self.recommendation,
            "provenance": self.provenance,
            "errors": self.errors,
            "hard_sanctions_override": self.hard_sanctions_override,
            "prev_hash": self.prev_hash,
            "this_hash": self.this_hash,
        }
        return json.dumps(d, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AuditEntry:
        return cls(
            sequence=d["sequence"],
            timestamp=d["timestamp"],
            alert_id=d["alert_id"],
            recommendation=d["recommendation"],
            provenance=d.get("provenance", []),
            errors=d.get("errors", []),
            hard_sanctions_override=d.get("hard_sanctions_override", False),
            prev_hash=d["prev_hash"],
            this_hash=d["this_hash"],
        )


# ---------------------------------------------------------------------------
# FileAuditLog — the demo backend
# ---------------------------------------------------------------------------


class FileAuditLog:
    """File-backed JSONL audit log.

    Each line is one AuditEntry. Appending is append-only. Verifying reads
    the whole file and checks every hash link.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(
            path or os.environ.get("ARGOS_AUDIT_LOG_PATH", "./data/audit.log")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(
        self,
        alert_id: str,
        recommendation: DispositionRecommendation,
        provenance_chain: list[ProvenanceEntry],
        errors: list[str],
        hard_sanctions_override: bool,
    ) -> str:
        prev_hash, prev_sequence = self._read_tail()

        entry = AuditEntry(
            sequence=prev_sequence + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            alert_id=alert_id,
            recommendation=json.loads(recommendation.model_dump_json()),
            provenance=[json.loads(p.model_dump_json()) for p in provenance_chain],
            errors=list(errors),
            hard_sanctions_override=hard_sanctions_override,
            prev_hash=prev_hash,
        )
        entry.this_hash = entry.compute_hash()

        with self.path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json_line() + "\n")

        return entry.this_hash

    def verify(self) -> tuple[bool, str | None]:
        expected_prev = GENESIS_HASH
        expected_seq = 0

        with self.path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = AuditEntry.from_dict(data)
                except (json.JSONDecodeError, KeyError) as e:
                    return False, f"line {line_num}: malformed entry: {e}"

                expected_seq += 1
                if entry.sequence != expected_seq:
                    return (
                        False,
                        f"line {line_num}: sequence {entry.sequence} "
                        f"expected {expected_seq}",
                    )

                if entry.prev_hash != expected_prev:
                    return (
                        False,
                        f"line {line_num}: prev_hash mismatch — "
                        f"chain broken at sequence {entry.sequence}",
                    )

                recomputed = entry.compute_hash()
                if recomputed != entry.this_hash:
                    return (
                        False,
                        f"line {line_num}: this_hash mismatch — "
                        f"entry has been tampered with at sequence {entry.sequence}",
                    )

                expected_prev = entry.this_hash

        return True, None

    def _read_tail(self) -> tuple[str, int]:
        """Return (last_hash, last_sequence) for appending."""
        last_hash = GENESIS_HASH
        last_seq = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    last_hash = data["this_hash"]
                    last_seq = data["sequence"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return last_hash, last_seq


# ---------------------------------------------------------------------------
# NullAuditLog — for tests only
# ---------------------------------------------------------------------------


class NullAuditLog:
    """An audit log that discards everything. For unit tests ONLY.

    The governance layer refuses to load a NullAuditLog when
    ARGOS_MODE=production.
    """

    def append(self, *args, **kwargs) -> str:  # noqa: ARG002
        return GENESIS_HASH

    def verify(self) -> tuple[bool, str | None]:
        return True, None


def load_audit_log_from_env() -> AuditLog:
    mode = os.environ.get("ARGOS_MODE", "demo")
    if mode == "test":
        return NullAuditLog()
    return FileAuditLog()
