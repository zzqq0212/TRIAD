"""Typed representations shared by the M1-M4 pipeline.

This module collects the trigger-constraint/construction types, the sparse
evidence contract (``NormalizedBugReport``) and the versioned contexts. Every
value is a plain JSON-serialisable ``dict``/``list`` so that stages, prompt
payloads and persisted ledgers share one contract.
"""

from __future__ import annotations

import hashlib
import json

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

NODE_TYPES = ("Resource", "Object", "UserOperation", "KernelEvent", "Actor")

EDGE_TYPES = (
    "produces", "consumes", "binds", "transitions", "activates",
    "before", "overlaps", "not-happens-before",
)

# Controllability classes of a constraint (Section 2.3 / M2).
CONTROL_CLASSES = ("direct", "influenceable", "observable", "environment")

# Relation grounding grades (Section M2).
GRADES = ("G0", "G1", "G2", "G3")

# Effect grades for operation semantics (Section M3).
EFFECT_GRADES = ("must", "may")

# Matcher statuses assigned per condition by M4.
MATCH_STATUSES = ("satisfied", "violated", "unobserved", "uninstrumented")

# Terminal outcomes (Section 2.5).
TERMINALS = (
    "Verified", "Evidence-Insufficient", "Target-Version-Mismatch",
    "Target-Already-Fixed", "Environment-Unavailable", "Unsupported-Condition",
    "Construction-Unsatisfied", "Unconfirmed-Identity", "Search-Exhausted",
    "Beam-Truncated(M3)", "Budget-Exhausted(M1)", "Budget-Exhausted(M2)",
    "Budget-Exhausted(M3)", "Budget-Exhausted(M4)",
)

# F1-F5 blocker patterns (Table in M4).
BLOCKERS = ("F1", "F2", "F3", "F4", "F5")

# Evidence extraction modes and leaf conflict states.
MODES = ("parsed", "semantic")
LEAF_STATES = ("consistent", "conflicting", "unassessed")


# --------------------------------------------------------------------------- #
# Trigger-graph and construction constructors
# --------------------------------------------------------------------------- #

def node(node_id, node_type, **attrs):
    if node_type not in NODE_TYPES:
        raise ValueError("unknown node type: %r" % (node_type,))
    n = {"id": node_id, "type": node_type}
    n.update(attrs)
    return n


def edge(edge_type, src, dst, **attrs):
    if edge_type not in EDGE_TYPES:
        raise ValueError("unknown edge type: %r" % (edge_type,))
    e = {"kind": edge_type, "src": src, "dst": dst}
    e.update(attrs)
    return e


def constraint(kind, subjects, predicate, provenance, grounding,
               confidence, verification, control):
    if kind not in EDGE_TYPES:
        raise ValueError("unknown constraint kind: %r" % (kind,))
    if control not in CONTROL_CLASSES:
        raise ValueError("unknown control class: %r" % (control,))
    if grounding not in GRADES:
        raise ValueError("unknown grounding grade: %r" % (grounding,))
    return {
        "kind": kind, "subjects": list(subjects), "predicate": predicate,
        "provenance": provenance, "grounding": grounding,
        "confidence": confidence, "verification": verification, "control": control,
    }


def hypothesis(objects, invariant, anchors, causal_subgraph):
    return {
        "objects": list(objects), "invariant": invariant,
        "anchors": list(anchors), "causal_subgraph": causal_subgraph,
    }


def operation(call, args, r_in, r_out, pre, effects, activations, actor, rev):
    for eff in effects:
        if eff.get("grade") not in EFFECT_GRADES:
            raise ValueError("unknown effect grade: %r" % (eff.get("grade"),))
    return {
        "call": call, "args": args, "resources_in": list(r_in),
        "resources_out": list(r_out), "pre": list(pre), "effects": list(effects),
        "activations": list(activations), "actor": actor, "rev": rev,
    }


def validate_trigger_graph(graph):
    if not isinstance(graph, dict):
        raise ValueError("trigger graph must be an object")
    nodes = graph.get("nodes")
    constraints = graph.get("constraints")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("trigger graph requires a non-empty nodes list")
    if not isinstance(constraints, list):
        raise ValueError("trigger graph requires a constraints list")
    ids = set()
    for n in nodes:
        if not isinstance(n, dict) or "id" not in n or "type" not in n:
            raise ValueError("malformed trigger node")
        if n["type"] not in NODE_TYPES:
            raise ValueError("unknown node type %r" % (n["type"],))
        if n["id"] in ids:
            raise ValueError("duplicate node id %r" % (n["id"],))
        ids.add(n["id"])
    for c in constraints:
        if not isinstance(c, dict):
            raise ValueError("malformed constraint")
        for key in ("kind", "subjects", "predicate", "provenance", "grounding",
                    "confidence", "verification", "control"):
            if key not in c:
                raise ValueError("constraint missing key %r" % (key,))
        if c["kind"] not in EDGE_TYPES:
            raise ValueError("unknown constraint kind %r" % (c["kind"],))
        if c["control"] not in CONTROL_CLASSES:
            raise ValueError("unknown control class %r" % (c["control"],))
        if c["grounding"] not in GRADES:
            raise ValueError("unknown grounding grade %r" % (c["grounding"],))
        for subject in c["subjects"]:
            if subject not in ids:
                raise ValueError("constraint subject %r is not a node" % (subject,))
    return graph


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    for key in ("constraint_bindings", "runtime_checks", "pre_state", "observers"):
        if key not in manifest:
            raise ValueError("manifest missing key %r" % (key,))
    for binding in manifest["constraint_bindings"]:
        for key in ("constraint_id", "producer", "domain", "observer", "binding"):
            if key not in binding:
                raise ValueError("constraint binding missing key %r" % (key,))
    return manifest


# --------------------------------------------------------------------------- #
# Evidence contract (M1)
# --------------------------------------------------------------------------- #

def leaf(key, value, type_, origin, locator, mode, confidence,
         verifiability, availability, visibility, state):
    if mode not in MODES:
        raise ValueError("unknown mode: %r" % (mode,))
    if state not in LEAF_STATES:
        raise ValueError("unknown leaf state: %r" % (state,))
    return {
        "key": key, "value": value, "type": type_, "origin": origin,
        "locator": locator, "mode": mode, "confidence": confidence,
        "verifiability": verifiability, "availability": availability,
        "visibility": visibility, "state": state,
    }


class NormalizedBugReport:
    """Sparse, extensible normalized report ``R_vis`` (Section M1)."""

    def __init__(self, report_id, channel, projection=True):
        self.report_id = report_id
        self.channel = channel
        self.projection = projection
        self._leaves = []
        self._groups = {}

    def add(self, key, value, type_, origin, locator, mode,
            confidence=1.0, verifiability=True, availability=True,
            visibility=None, state="consistent"):
        if visibility is None:
            visibility = "visible" if self.projection else "withheld"
        self._leaves.append(leaf(key, value, type_, origin, locator, mode,
                                 confidence, verifiability, availability,
                                 visibility, state))

    def leaves(self, visible_only=False):
        if not visible_only:
            return list(self._leaves)
        return [x for x in self._leaves if x["visibility"] == "visible"]

    def group(self, name):
        return self._groups.setdefault(name, {})

    def to_dict(self, visible_only=False):
        result = {"report_id": self.report_id, "channel": self.channel}
        for group, values in self._groups.items():
            result[group] = values
        result["_leaf_count"] = len(self.leaves(visible_only=visible_only))
        return result

    def __repr__(self):
        return "NormalizedBugReport(%r, channel=%r, leaves=%d)" % (
            self.report_id, self.channel, len(self._leaves))


def readiness_vector(target_ready, failure_ready, identity_evidence_complete,
                     seed_usable, analysis_available, diag_available):
    return {
        "targetReady": bool(target_ready),
        "failureReady": bool(failure_ready),
        "identityEvidenceComplete": bool(identity_evidence_complete),
        "seedUsable": bool(seed_usable),
        "analysisAvailable": bool(analysis_available),
        "diagAvailable": bool(diag_available),
    }


def route(analysis_available, seed_usable):
    return {
        "mechanism": "align" if analysis_available else "infer",
        "construction": "seed-completion" if seed_usable else "seed-free",
    }


def route_label(analysis_available, seed_usable):
    r = route(analysis_available, seed_usable)
    return r["mechanism"] + "+" + r["construction"].replace("seed-completion", "seed").replace("seed-free", "free")


def target_attestation(target_id, source_hash, config_hash, baseline,
                       environment, capabilities):
    return {
        "id": target_id, "sourceHash": source_hash, "configHash": config_hash,
        "baseline": baseline, "environment": environment,
        "capabilities": list(capabilities),
    }


# --------------------------------------------------------------------------- #
# Versioned contexts (Section M1)
# --------------------------------------------------------------------------- #

def _sha(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False, allow_nan=False).encode("utf-8")
    ).hexdigest()


def digest(value):
    return _sha(value)


def context_report(episode_id, report_version, report_digest):
    body = {"episode_id": episode_id, "report_version": report_version,
            "report_digest": report_digest}
    return {
        "ctx": "ctx_R", "episode_id": episode_id,
        "report_version": report_version, "report_digest": report_digest,
        "digest": _sha(body),
    }


def context_hypothesis(parent_ctx_r, hypothesis_version, trigger_version,
                       attestation_digest):
    body = {"parent_digest": parent_ctx_r["digest"],
            "hypothesis_version": hypothesis_version,
            "trigger_version": trigger_version,
            "attestation_digest": attestation_digest}
    return {
        "ctx": "ctx_H", "parent": parent_ctx_r,
        "hypothesis_version": hypothesis_version,
        "trigger_version": trigger_version,
        "attestation_digest": attestation_digest, "digest": _sha(body),
    }


def context_action(parent_ctx_h, operation_version):
    body = {"parent_digest": parent_ctx_h["digest"],
            "operation_version": operation_version}
    return {
        "ctx": "ctx_A", "parent": parent_ctx_h,
        "operation_version": operation_version, "digest": _sha(body),
    }


def admit(child_ctx, expected_parent_digest):
    parent = child_ctx.get("parent")
    return isinstance(parent, dict) and parent.get("digest") == expected_parent_digest
