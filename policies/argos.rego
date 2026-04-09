# Argos runtime policies — enforced by the Microsoft Agent Governance Toolkit.
#
# These Rego policies are checked at sub-millisecond latency before every tool
# call a graph node attempts. The policies are deliberately narrow and explicit:
# a node that tries to do something not listed here is denied by default, and
# the denial is logged to the audit trail as a security event.
#
# Why OPA Rego
# ------------
# Rego is a declarative language for policy-as-code. Security reviewers can
# read these rules without understanding Python, and the policies are
# enforceable at runtime by the Agent Governance Toolkit regardless of what
# the node code says it's doing.
#
# OWASP ASI Top 10 2026 mapping
# -----------------------------
# - ASI02 Tool Misuse          -> allowed_tools_per_node rules
# - ASI04 Privilege Compromise -> scoped_credentials_only rule
# - ASI08 Cascading Failures   -> circuit_breaker rule
# - ASI10 Rogue Agents         -> no_network_from_reason rule
#
# For the full threat model: docs/THREAT_MODEL.md

package argos.authz

default allow = false

# ---------------------------------------------------------------------------
# Per-node tool allow-lists
# ---------------------------------------------------------------------------
#
# Each node is allowed a specific set of external calls. Anything else is
# denied. The reasoning node is notable for allowing NOTHING — it receives
# its input and returns its output, with no capability to reach outside.

intake_allowed_tools := {"data_source.get_customer_baseline", "data_source.count_prior_alerts"}
sanctions_allowed_tools := {"data_source.check_sanctions"}
behavioral_allowed_tools := {"data_source.get_recent_transactions"}
package_allowed_tools := set()  # pure aggregation, no external calls
reason_allowed_tools := set()  # THE LLM NODE — no tool access whatsoever
handoff_allowed_tools := {"audit_log.append", "case_connector.create_case"}

# The main allow rule: node X calling tool Y is allowed iff Y is in X's list.
allow {
    input.node == "intake"
    intake_allowed_tools[input.tool]
}

allow {
    input.node == "sanctions_check"
    sanctions_allowed_tools[input.tool]
}

allow {
    input.node == "behavioral_delta"
    behavioral_allowed_tools[input.tool]
}

allow {
    input.node == "package_evidence"
    count(package_allowed_tools) == 0  # explicit: no tools allowed
    false                               # always deny any tool call from this node
}

allow {
    input.node == "reason"
    count(reason_allowed_tools) == 0  # explicit: no tools allowed
    false                              # always deny any tool call from this node
}

allow {
    input.node == "handoff"
    handoff_allowed_tools[input.tool]
}

# ---------------------------------------------------------------------------
# Reasoning-node network egress — hard deny
# ---------------------------------------------------------------------------
#
# The reasoning node cannot make ANY network call other than to the configured
# LLM backend, and even that happens through the ReasoningBackend interface —
# not as a "tool" call the policy layer would see. So from the policy layer's
# perspective, reason has zero network.

deny_network {
    input.node == "reason"
    input.action == "network"
}

# ---------------------------------------------------------------------------
# Scoped credential rule
# ---------------------------------------------------------------------------
#
# Credentials must be scoped to the investigation they're used in. A node
# using a credential outside its declared scope is denied. The credential ID
# appears in the audit log's ProvenanceEntry so auditors can trace usage.

deny_credential_misuse {
    input.action == "credential_use"
    input.credential.investigation_id != input.investigation_id
}

deny_credential_misuse {
    input.action == "credential_use"
    input.credential.ttl_seconds > 3600  # no credential lives longer than 1h
}

# ---------------------------------------------------------------------------
# Circuit breaker — kill switch on anomalous behavior
# ---------------------------------------------------------------------------
#
# If the reasoning node's decision distribution drifts beyond configured
# bounds (too many auto-approvals, too many invalid citations, etc.), the
# circuit breaker trips and ALL subsequent cases route straight to human
# review until an operator manually resets it. This addresses ASI08
# Cascading Failures.

deny_reason_call {
    input.node == "reason"
    input.action == "invoke"
    input.circuit_breaker.state == "open"
}

# ---------------------------------------------------------------------------
# Audit log integrity — no writes from anything but handoff
# ---------------------------------------------------------------------------
#
# Only the handoff node may write to the audit log. Any other node attempting
# to do so is denied and the attempt is itself logged as a security event.

deny_audit_write {
    input.action == "audit_write"
    input.node != "handoff"
}

# ---------------------------------------------------------------------------
# Sanctions override enforcement
# ---------------------------------------------------------------------------
#
# If the sanctions check returned a primary hit, the graph MUST route to
# handoff. A path that goes from sanctions_check to reason after a primary
# hit is a policy violation and will be denied.

deny_reason_after_sanctions_hit {
    input.node == "reason"
    input.action == "invoke"
    input.state.sanctions.primary_hit == true
}
