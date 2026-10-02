#!/usr/bin/env python3
"""M3 - close dependencies and instantiate a syz-lang program + manifest."""
import argparse
import json
import sys

from triad.llm import MockLLM
from triad.m1 import normalize, decide_route
from triad.m2 import infer, SourceIndex
from triad.m3 import (OperationCatalog, close, instantiate,
                      validate_manifest_implication)


def main(argv=None):
    p = argparse.ArgumentParser(description="TRIAD M3 construction")
    p.add_argument("--report", required=True)
    args = p.parse_args(argv)
    with open(args.report, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    llm = MockLLM()
    report = normalize(llm, bundle)
    route, _ = decide_route(report)
    bundles, _ = infer(report, route, SourceIndex.running_example(), llm)
    catalog = OperationCatalog()
    tg = bundles[0]["trigger_graph"]
    op_graph, unresolved = close(tg, catalog, route)
    inst = instantiate(tg, op_graph, route)
    ok, why = validate_manifest_implication(report, inst["manifest"], tg)
    print(json.dumps({"program": inst["program"],
                      "pre_state_checklist": inst["pre_state_checklist"],
                      "manifest": inst["manifest"],
                      "unresolved": unresolved, "manifest_ok": ok, "reason": why},
                     indent=2))


if __name__ == "__main__":
    sys.exit(main())
