"""M4 - execution- and condition-guided refinement plus frozen joint confirmation.

M4 tests the manifest from clean baselines, assigns each condition one of four
matcher statuses, derives the condition frontier, applies scoped repairs (F1-F5)
and, only after freezing the candidate pool, performs joint identity-and-mechanism
confirmation (Section M4).
"""

from __future__ import annotations

from .model import MATCH_STATUSES, BLOCKERS

# F1-F5 first-repair policy (Table in M4).
_REPAIR = {
    "F1": "repair setup/dependencies; re-attest target",
    "F2": "search arguments; inspect preconditions",
    "F3": "inspect coverage; revise call/state mapping",
    "F4": "retry observer; revise domain contradiction",
    "F5": "vary activation, repeats, CPU, or schedule",
}


def feedback_level(trace):
    """Return the highest feedback level present in a trial trace (L0-L3)."""
    if not isinstance(trace, dict):
        return "L0"
    if trace.get("lifecycle_events") or trace.get("ordering_events"):
        return "L3"
    if trace.get("coverage"):
        return "L2"
    if trace.get("diagnostics") or trace.get("signature"):
        return "L1"
    return "L0"


def match_condition(trace, condition, observers):
    """Assign a per-condition matcher status ``s_x(c)`` (Section M4).

    A condition is *satisfied* when its checkable event pattern appears in the
    trace, *violated* when a counterexample contradicts it, *unobserved* when
    its events are missing or lost, and *uninstrumented* when the observer that
    would produce the pattern is absent from the declared observer set.
    """
    verification = condition.get("verification", "")
    observed = [e.get("pattern") for e in trace.get("events", [])]
    if verification in observed:
        return "satisfied"
    if trace.get("counterexamples"):
        return "violated"
    # An observer is uninstrumented only when none of the trace's declared
    # observers could plausibly produce this verification pattern; for the
    # reference implementation we conservatively report unobserved instead of
    # asserting an absent observer unless the observer set is empty.
    if not observers:
        return "uninstrumented"
    return "unobserved"


def condition_frontier(trigger_graph, trace, observers):
    """Return the minimal set of required constraints with status != satisfied."""
    frontier = []
    for i, c in enumerate(trigger_graph["constraints"]):
        status = match_condition(trace, c, observers)
        if status != "satisfied":
            frontier.append({"constraint_id": "c%d" % i, "kind": c["kind"],
                             "status": status, "subjects": c["subjects"]})
    return frontier


def blocker_pattern(frontier):
    """Map the unresolved condition frontier to an F1-F5 blocker pattern."""
    if not frontier:
        return None
    kinds = {f["kind"] for f in frontier}
    statuses = {f["status"] for f in frontier}
    if "uninstrumented" in statuses:
        return "F4"
    if "produces" in kinds and "unobserved" in statuses:
        return "F1"
    if "violated" in statuses:
        return "F4"
    if "overlaps" in kinds or "not-happens-before" in kinds:
        return "F5"
    if "binds" in kinds:
        return "F3"
    return "F2"


def first_repair(frontier):
    pattern = blocker_pattern(frontier)
    if pattern is None:
        return None
    return {"pattern": pattern, "action": _REPAIR[pattern]}


# --------------------------------------------------------------------------- #
# Frozen joint confirmation
# --------------------------------------------------------------------------- #

def _repeatable(joint_hits, clean_resets, n_c, q):
    return clean_resets == n_c and joint_hits >= q


def confirm(runs, q, n_c):
    """Frozen joint-confirmation accounting over independent clean resets.

    ``runs`` is a list of per-reset records, each with an ``identity`` boolean
    (matches ``I``), an ``outcomes`` boolean (matches ``O_A``) and a
    ``trigger`` boolean (matches ``V_H^confirm``). A reset counts as a joint hit
    only when all three hold in the *same* execution.
    """
    if not (2 <= q <= n_c):
        raise ValueError("confirmation requires 2 <= q <= n_c")
    clean_resets = len(runs)
    joint_hits = sum(1 for r in runs if r.get("identity") and r.get("outcomes") and r.get("trigger"))
    verified = _repeatable(joint_hits, clean_resets, n_c, q)
    probability = joint_hits / clean_resets if clean_resets else None
    return {
        "clean_resets": clean_resets,
        "joint_hits": joint_hits,
        "required_n": n_c,
        "required_q": q,
        "verified": verified,
        "trigger_probability": probability,
    }


__all__ = [
    "feedback_level", "match_condition", "condition_frontier",
    "blocker_pattern", "first_repair", "confirm",
]
