#!/usr/bin/env python3
"""M4 - frozen joint-confirmation accounting over recorded reset runs."""
import argparse
import json
import sys

from triad.m4 import confirm


def main(argv=None):
    p = argparse.ArgumentParser(description="TRIAD M4 confirmation accounting")
    p.add_argument("--runs", required=True, help="JSON array of reset runs")
    p.add_argument("--q", type=int, default=2)
    p.add_argument("--n-c", type=int, default=5)
    args = p.parse_args(argv)
    with open(args.runs, "r", encoding="utf-8") as f:
        runs = json.load(f)
    print(json.dumps(confirm(runs, args.q, args.n_c), indent=2))


if __name__ == "__main__":
    sys.exit(main())
