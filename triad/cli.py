"""Command-line interface for the TRIAD pipeline and record tooling.

Project execution is gated to Ubuntu 22.04/24.04. The ``run-example`` command
performs a deterministic offline dry-run that exercises M1-M4 without a kernel,
VM, model key or the fuzzing runtime. The ``validate``/``report``/``export``
commands process recorded metadata and never execute or generate programs.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import sys
from pathlib import Path
from urllib.parse import urlparse

from .records import (Invalid, digest, load_json, load_jsonl, require, route,
                      summarize, validate_protocol, validate_runs,
                      validate_samples)


def ubuntu_environment():
    require(platform.system() == "Linux", "TRIAD execution is Ubuntu-only; macOS is disabled")
    info = platform.freedesktop_os_release()
    require(info.get("ID") == "ubuntu" and info.get("VERSION_ID") in ("22.04", "24.04"),
            "supported environments: Ubuntu 22.04 or 24.04")
    require(sys.version_info >= (3, 10), "Python >= 3.10 required")
    return {"os": "Ubuntu", "version": info["VERSION_ID"],
            "architecture": platform.machine(), "python": platform.python_version()}


def llm_config(path):
    cfg = load_json(path)
    require(isinstance(cfg, dict), "LLM config must be an object")
    require(set(cfg) == {"provider", "base_url", "api_key_env", "model"}, "unexpected/missing LLM config keys")
    require(cfg["provider"] in ("openai", "deepseek", "glm", "openai-compatible"), "unknown provider")
    require(all(isinstance(v, str) and v.strip() for v in cfg.values()), "empty LLM setting")
    require("REPLACE" not in cfg["model"], "set an account-accessible model ID")
    url = urlparse(cfg["base_url"])
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment,
            "base_url must be HTTPS without credentials, query or fragment")
    require(cfg["api_key_env"] in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GLM_API_KEY", "TRIAD_LLM_API_KEY"),
            "use a documented API key variable")
    require(bool(os.environ.get(cfg["api_key_env"], "").strip()), "configured API key variable is empty")
    return {"configuration": "present", "authentication_tested": False,
            "model_access_tested": False, "network_requests": 0}


def write_csv(path, rows):
    with path.open("x", encoding="utf-8", newline="") as f:
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)


def _cmd_run_example(args):
    from .controller import run_pipeline, PipelineConfig
    config = PipelineConfig(
        target={
            "id": "example-nullb-x86_64",
            "source_sha256": "0" * 64,
            "config_sha256": "0" * 64,
            "baseline": "qemu snapshot 0",
            "environment": "ubuntu-22.04 qemu kvm",
            "capabilities": ["kasan", "kcov", "kprobe", "ftrace"],
        },
        confirmation={"q": 2, "n_c": args.n_c},
    )
    print(json.dumps(run_pipeline(EXAMPLE_REPORT, config), indent=2, allow_nan=False))


def _cmd_run(args):
    from .controller import run_pipeline, PipelineConfig, build_llm
    with open(args.target, "r", encoding="utf-8") as f:
        target = json.load(f)
    config = PipelineConfig(target=target, confirmation={"q": args.q, "n_c": args.n_c})
    llm = build_llm(args.llm_config) if args.llm_config else None
    print(json.dumps(run_pipeline(args.report, config, llm=llm), indent=2, allow_nan=False))


def _cmd_validate_report(args):
    p = load_json(args.protocol)
    validate_protocol(p, frozen=args.command == "report")
    samples = validate_samples(load_jsonl(args.samples), p)
    runs = load_jsonl(args.runs)
    require(p["status"] == "frozen" or not runs, "runs cannot be attached to a draft protocol")
    missing = validate_runs(runs, samples, p) if p["status"] == "frozen" else set()
    result = {"protocol_status": p["status"], "subjects": len(samples),
              "recorded_runs": len(runs),
              "missing_run_cells": len(missing) if p["status"] == "frozen" else None,
              "strata": {k: sum(1 for s in samples.values() if route(s) == k) for k in
                         ("align+seed", "align+free", "infer+seed", "infer+free", "pre-routing-terminal")},
              "publication_ready": False,
              "note": "Metadata validation does not authenticate evidence or reproduce results."}
    if args.command == "report":
        summary = summarize(samples, runs, p)
        out = Path(args.output)
        require(not out.exists(), "output directory already exists; choose a new directory")
        out.mkdir(parents=True)
        write_csv(out / "primary.csv", [r for r in summary if r["kind"] == "primary"])
        write_csv(out / "patch-assisted.csv", [r for r in summary if r["kind"] == "patch-assisted"])
        strata = [{"stratum": key, "subjects": sum(route(s) == key for s in samples.values())}
                  for key in ("align+seed", "align+free", "infer+seed", "infer+free", "pre-routing-terminal")]
        write_csv(out / "strata.csv", strata)
        stability = [{"run_id": r["id"], "configuration": r["configuration_id"],
                      "sample_id": r["sample_id"], "seed": r["seed"],
                      "joint_hits": r["joint_hits"], "clean_resets": r["clean_resets"],
                      "observed_probability": r["joint_hits"] / r["clean_resets"] if r["clean_resets"] else None,
                      "terminal_outcome": r["terminal_outcome"], "oracle_verdict": r["oracle_verdict"]}
                     for r in runs]
        write_csv(out / "stability.csv", stability)
        result.update(protocol_sha256=digest(p), samples_sha256=digest(list(samples.values())),
                      runs_sha256=digest(runs), environment=ubuntu_environment())
        (out / "provenance.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, allow_nan=False))


def _cmd_export(args):
    from .records import export
    print(json.dumps(export(Path(__file__).resolve().parent.parent, Path(args.output)),
                     indent=2, allow_nan=False))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="triad", description="TRIAD M1-M4 pipeline and record tooling")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="inspect the Ubuntu environment")

    ex = sub.add_parser("run-example", help="offline M1-M4 dry-run on the bundled example")
    ex.add_argument("--n-c", type=int, default=5)
    ex.set_defaults(func=_cmd_run_example)

    run = sub.add_parser("run", help="run the pipeline on a report bundle")
    run.add_argument("report")
    run.add_argument("--target", required=True)
    run.add_argument("--llm-config", default=None)
    run.add_argument("--q", type=int, default=2)
    run.add_argument("--n-c", type=int, default=5)
    run.set_defaults(func=_cmd_run)

    llm = sub.add_parser("llm-config", help="validate LLM configuration offline")
    llm.add_argument("config")

    d = sub.add_parser("digest", help="canonical SHA-256 of a JSON record")
    d.add_argument("file")

    for name in ("validate", "report"):
        p = sub.add_parser(name)
        p.add_argument("--protocol", required=True)
        p.add_argument("--samples", required=True)
        p.add_argument("--runs", required=True)
        if name == "report":
            p.add_argument("--output", required=True)
        p.set_defaults(func=_cmd_validate_report)

    exp = sub.add_parser("export", help="export the allowlisted release archive")
    exp.add_argument("--output", required=True)
    exp.set_defaults(func=_cmd_export)

    args = parser.parse_args(argv)
    try:
        env = ubuntu_environment()
    except Invalid as exc:
        print("invalid: %s" % exc, file=sys.stderr)
        return 2

    if args.command == "doctor":
        print(json.dumps({**env, "scope": "M1-M4 pipeline + record tooling"}, indent=2))
        return 0
    if args.command == "digest":
        print(json.dumps({"sha256": digest(load_json(args.file))}, indent=2))
        return 0
    if args.command == "llm-config":
        try:
            print(json.dumps(llm_config(args.config), indent=2))
            return 0
        except Invalid as exc:
            print("invalid: %s" % exc, file=sys.stderr)
            return 2
    try:
        args.func(args)
        return 0
    except (Invalid, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        if isinstance(exc, Invalid):
            print("invalid: %s" % exc, file=sys.stderr)
        else:
            print("error (%s): %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2


# Bundled example report matching the paper's running example
# (KASAN use-after-free in delete_partition). Used for offline dry-runs only and
# never recorded as an evaluation result.
EXAMPLE_REPORT = {
    "report_id": "a09edb22-example",
    "channel": "syzbot",
    "report_version": 1,
    "origin_commit": "f75aef392f86",
    "kernel": "5.9.0-rc3",
    "arch": "x86_64",
    "bug_class": "KASAN use-after-free read",
    "prose": (
        "Two deletion paths appear to race while deleting the same logical "
        "partition. One path releases the holder_dir kobject before the other "
        "accesses the same allocation epoch."
    ),
    "stack": (
        "#0 kobject_put lib/kobject.c:748\n"
        "#1 bdev_del_partition block/partitions/core.c:324\n"
        "#2 delete_partition block/partitions/core.c:443\n"
        "#3 blkpg_ioctl block/ioctl.c:112\n"
    ),
    "log": (
        "KASAN: use-after-free Read in kobject_put\n"
        "Call Trace:\n"
        " kobject_put lib/kobject.c:748\n"
        " bdev_del_partition block/partitions/core.c:324\n"
        " delete_partition block/partitions/core.c:443\n"
        "commit f75aef392f86\n"
    ),
    "syz_prog": (
        "r0 = openat$nullb(0x0, &(0x7f0000000000)='/dev/nullb0', 0x2, 0x0)\n"
        "ioctl$BLKPG_ADD_PARTITION(r0, 0x1268, &(0x7f0000000040))\n"
        "ioctl$BLKPG_DEL_PARTITION(r0, 0x1269, &(0x7f0000000080))\n"
    ),
    "c_repro": "#include <linux/blkpg.h>\n/* ... */",
    "console_log": "present",
}


if __name__ == "__main__":
    raise SystemExit(main())
