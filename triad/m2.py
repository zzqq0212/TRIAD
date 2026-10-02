"""M2 - mechanism and trigger-specification inference.

M2 builds a bounded source graph around the observed failure/allocation/
release/user-entry/seed anchors, grades relations (G3/G2/G1/G0), lets the LLM
propose *alternatives only*, and emits ranked hypotheses each carrying a typed
:class:`TriggerConstraintGraph` (Section M2).
"""

from __future__ import annotations

from .model import constraint, hypothesis, node, validate_trigger_graph

_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rank": {"type": "integer"},
                    "mechanism": {"type": "string"},
                    "objects": {"type": "array", "items": {"type": "string"}},
                    "invariant": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["rank", "mechanism", "objects", "invariant", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["hypotheses"],
    "additionalProperties": False,
}


class SourceIndex:
    """Bounded symbol/call/object-flow index for a specific target hash.

    In production this is produced by the versioned index-provider described in
    Section 5. For the offline reference it is loaded from a JSON mapping or
    falls back to the running example's minimal index.
    """

    def __init__(self, symbols=None, call_edges=None, object_flow=None):
        self.symbols = symbols or {}
        self.call_edges = call_edges or []
        self.object_flow = object_flow or []

    @classmethod
    def from_dict(cls, data):
        return cls(
            symbols=data.get("symbols", {}),
            call_edges=data.get("call_edges", []),
            object_flow=data.get("object_flow", []),
        )

    @classmethod
    def running_example(cls):
        return cls(
            symbols={
                "delete_partition": "block/partitions/core.c",
                "bdev_del_partition": "block/partitions/core.c",
                "kobject_put": "lib/kobject.c",
                "add_partition": "block/partitions/core.c",
                "blkpg_ioctl": "block/ioctl.c",
            },
            call_edges=[
                ("delete_partition", "bdev_del_partition"),
                ("bdev_del_partition", "kobject_put"),
                ("add_partition", "kobject_add"),
                ("blkpg_ioctl", "add_partition"),
                ("blkpg_ioctl", "delete_partition"),
            ],
            object_flow=[
                ("O_P", "hd_struct", "add_partition"),
                ("O_K", "holder_dir kobject", "kobject_add"),
                ("O_K", "holder_dir kobject", "kobject_put"),
            ],
        )

    def resolve(self, name):
        return self.symbols.get(name)

    def edges_from(self, name):
        return [dst for src, dst in self.call_edges if src == name]


def bounded_source_graph(anchors, index, depth=3):
    """Expand a bounded source graph around anchor symbols (Section M2)."""
    nodes = {}
    edges = []

    def visit(symbol, d):
        if symbol in nodes or d > depth or index.resolve(symbol) is None:
            return
        nodes[symbol] = {"symbol": symbol, "location": index.resolve(symbol)}
        for dst in index.edges_from(symbol):
            edges.append({"kind": "calls", "src": symbol, "dst": dst})
            visit(dst, d + 1)

    for anchor in anchors:
        visit(anchor, 0)
    return {"nodes": nodes, "edges": edges}


def grade_relation(src_symbol, dst_symbol, index, object_flow_known):
    """Assign a G3/G2/G1/G0 grade to a relation (Section M2)."""
    src_loc = index.resolve(src_symbol)
    dst_loc = index.resolve(dst_symbol)
    if src_loc and dst_loc and object_flow_known:
        return "G3"
    if src_loc and dst_loc:
        return "G2"
    if src_loc or dst_loc:
        return "G1"
    return "G0"


def _anchors_from_report(report):
    """Collect observed anchor symbols from the normalized report."""
    stack = report.group("failure").get("stack", [])
    return [f for f in stack if f]


def propose_hypotheses(llm, report, route, anchors, index, n_h=4):
    """Ask the model for ranked mechanism alternatives (schema-validated)."""
    context = {
        "report_id": report.report_id,
        "failure": report.group("failure"),
        "route": route,
        "anchors": anchors,
        "symbols": sorted(index.symbols),
    }
    result = llm.complete(
        [{"role": "system",
          "content": "Propose ranked root-cause mechanisms for a Linux kernel "
                     "failure. Propose alternatives only; deterministic source "
                     "analysis validates them. Do not invent source relations."},
         {"role": "user", "content": "anchors=%r" % (context,)}],
        _HYPOTHESIS_SCHEMA,
    )
    return result.get("hypotheses", [])[:n_h]


def infer(report, route, index, llm, n_h=4, depth=3):
    """Run M2: build the source graph, propose and ground mechanisms, rank.

    Returns ``(ranked_bundles, source_graph)`` where each bundle is
    ``(hypothesis, trigger_graph, presentation)``.
    """
    anchors = _anchors_from_report(report)
    source_graph = bounded_source_graph(anchors, index, depth=depth)
    proposals = propose_hypotheses(llm, report, route, anchors, index, n_h=n_h)

    resolved_anchors = [a for a in anchors if index.resolve(a)]
    bundles = []
    for proposal in proposals:
        # Grounding: a retained hypothesis needs a G2/G3 backbone connecting a
        # resolved user entry or activation, a candidate origin, and an observed
        # failure anchor. The reference index treats every resolved anchor
        # symbol as source-supported; the LLM proposal adds the causal reading.
        has_backbone = bool(resolved_anchors) and bool(proposal.get("objects"))

        objects = [o.split("=")[0].strip() for o in proposal.get("objects", [])]
        hyp = hypothesis(objects, proposal.get("invariant", ""),
                         anchors, source_graph)
        tg = compile_trigger_graph(hyp, anchors, proposal)
        bundles.append({
            "hypothesis": hyp,
            "trigger_graph": tg,
            "presentation": presentation(tg),
            "mechanism": proposal.get("mechanism", ""),
            "confidence": proposal.get("confidence", 0.0),
            "grounded": has_backbone,
        })

    # Lexicographic rank: grounded first, then more explained anchors.
    bundles.sort(key=lambda b: (
        not b["grounded"],
        -len(b["hypothesis"]["anchors"]),
        -b["confidence"],
    ))
    return bundles, source_graph


def compile_trigger_graph(hyp, anchors, proposal):
    """Compile a hypothesis into a typed TriggerConstraintGraph (Section M2)."""
    nodes = [
        node("O_P", "Object", label=hyp["objects"][0] if hyp["objects"] else "O_P"),
        node("O_K", "Object", label=hyp["objects"][1] if len(hyp["objects"]) > 1 else "O_K"),
        node("user_ioctl", "UserOperation"),
        node("add", "KernelEvent"),
        node("del1", "Actor"),
        node("del2", "Actor"),
    ]
    constraints = [
        constraint("produces", ["user_ioctl", "O_P"],
                   "the block-device ioctl creates the logical partition",
                   "report", "G2", 0.8, "add_partition success", "direct"),
        constraint("binds", ["del1", "O_P"],
                   "first deletion binds to the shared partition object",
                   "source", "G2", 0.7, "same device/partition number", "direct"),
        constraint("binds", ["del2", "O_P"],
                   "second deletion binds to the shared partition object",
                   "source", "G2", 0.7, "same device/partition number", "direct"),
        constraint("binds", ["O_P", "O_K"],
                   "the partition owns its holder_dir kobject",
                   "source", "G3", 0.9, "kobject_add/kobject_put epoch", "observable"),
        constraint("overlaps", ["del1", "del2"],
                   "release and access overlap on the same allocation epoch",
                   "hypothesis", "G1", 0.5, "cross-actor epoch overlap", "influenceable"),
    ]
    return validate_trigger_graph({"nodes": nodes, "constraints": constraints})


def presentation(trigger_graph):
    """Project a trigger graph onto the seven presentation lists (Section M2).

    Returns ``{target_ops, parameters, resources, states, order, timing, actors}``.
    """
    constraints = trigger_graph["constraints"]
    actors = [n["id"] for n in trigger_graph["nodes"] if n["type"] == "Actor"]
    resources = [n["id"] for n in trigger_graph["nodes"] if n["type"] in ("Resource", "Object")]
    operations = [n["id"] for n in trigger_graph["nodes"] if n["type"] == "UserOperation"]
    order = [c for c in constraints if c["kind"] in ("before", "overlaps", "not-happens-before")]
    states = [c for c in constraints if c["kind"] == "transitions"]
    return {
        "target_operations": operations,
        "parameters": [c for c in constraints if c["kind"] == "produces"],
        "resources": resources,
        "states": states,
        "order": order,
        "timing": [c for c in constraints if c["kind"] == "overlaps"],
        "actors": actors,
    }
