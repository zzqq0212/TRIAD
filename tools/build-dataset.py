#!/usr/bin/env python3
"""Build the formal ``data/samples.jsonl`` evaluation ledger from the cohort.

Reads ``data/dataset.jsonl`` (the curated cohort) and, for each entry, joins it
with operator-stored evidence and a preflight target registry to produce the
ledger schema accepted by ``python3 -m triad validate``. It never invents a
digest or a build/boot attestation:

1. SHA-256 of the original evidence bytes under ``data/raw/<id>.txt``, and
2. the preflight target registry ``data/private/targets.json``
   (``id -> {revision, architecture, compiler, environment_id, source_sha256,
   config_sha256, baseline_sha256, buildable}``).

Entries without evidence or an attested target are deferred to a review report.
Run only on the Ubuntu host that performed preflight.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cohort", default=str(ROOT / "data/dataset.jsonl"))
    p.add_argument("--targets", default=str(ROOT / "data/private/targets.json"))
    p.add_argument("--out", default=str(ROOT / "data/samples.jsonl"))
    args = p.parse_args(argv)

    cohort = load_jsonl(args.cohort)
    targets = {}
    if Path(args.targets).exists():
        targets = json.loads(Path(args.targets).read_text(encoding="utf-8"))

    admitted, deferred = [], []
    for bug in cohort:
        raw = ROOT / "data" / "raw" / (bug["id"] + ".txt")
        target = targets.get(bug["id"])
        problems = []
        if not raw.exists():
            problems.append("missing data/raw/%s.txt" % bug["id"])
        if not target:
            problems.append("missing preflight target in data/private/targets.json")
        if problems:
            deferred.append({"id": bug["id"], "identifier": bug["identifier"], "problems": problems})
            continue
        admitted.append({
            "id": bug["id"],
            "record_kind": "real",
            "partition": "evaluation",
            "source": {
                "kind": bug["source"],
                "id": bug["identifier"],
                "url": bug.get("url"),
                "reported_on": bug["reported_on"],
                "retrieved_on": bug.get("retrieved_on", bug["reported_on"]),
                "artifact_sha256": sha256_file(raw),
            },
            "bug_class": bug["bug_class"],
            "analysis_available": bug.get("analysis_available"),
            "seed_usable": bug.get("seed_available"),
            "buildable": target.get("buildable", True),
            "pre_routing_terminal": False,
            "embedded_code": bug.get("embedded_code", False),
            "patch_oracle_available": bug.get("fix_available", True),
            "assessment_ref": "cohort/" + bug["id"],
            "target": target,
        })

    out = Path(args.out)
    if admitted:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            for row in admitted:
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    print(json.dumps({"admitted": len(admitted), "deferred": deferred,
                      "output": str(out) if admitted else None}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
