#!/usr/bin/env python3
"""M2 - infer ranked mechanisms and trigger constraint graphs."""
import argparse
import json
import sys

from triad.llm import MockLLM
from triad.m1 import normalize, decide_route
from triad.m2 import infer, SourceIndex


def main(argv=None):
    p = argparse.ArgumentParser(description="TRIAD M2 mechanism inference")
    p.add_argument("--report", required=True)
    args = p.parse_args(argv)
    with open(args.report, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    llm = MockLLM()
    report = normalize(llm, bundle)
    route, _ = decide_route(report)
    bundles, source_graph = infer(report, route, SourceIndex.running_example(), llm)
    print(json.dumps({
        "source_graph_nodes": len(source_graph["nodes"]),
        "bundles": [{"mechanism": b["mechanism"], "grounded": b["grounded"],
                     "presentation": b["presentation"],
                     "trigger_graph": b["trigger_graph"]} for b in bundles],
    }, indent=2))


if __name__ == "__main__":
    sys.exit(main())
