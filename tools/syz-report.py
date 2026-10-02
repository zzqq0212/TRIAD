#!/usr/bin/env python3
"""M1 - normalize a report bundle and print R_vis, readiness and route."""
import argparse
import json
import sys

from triad.llm import MockLLM
from triad.m1 import normalize, assess_readiness, decide_route


def main(argv=None):
    p = argparse.ArgumentParser(description="TRIAD M1 report normalization")
    p.add_argument("--report", required=True)
    args = p.parse_args(argv)
    with open(args.report, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    report = normalize(MockLLM(), bundle)
    route, qr = decide_route(report)
    print(json.dumps({"report": report.to_dict(visible_only=True),
                      "readiness": qr, "route": route}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
