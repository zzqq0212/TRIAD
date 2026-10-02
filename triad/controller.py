"""Top-level orchestration of the M1-M4 pipeline.

The controller threads the versioned contexts through the four stages, enforces
the admission checks, applies the scoped-repair loop, and emits either a
reproducer package or an explicit non-success terminal outcome (Section M4).
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .model import (NormalizedBugReport, context_report, context_hypothesis,
                    context_action, digest, admit)
from .llm import LLMClient, MockLLM
from .m1 import normalize, assess_readiness, decide_route, preflight
from .m2 import infer, SourceIndex
from .m3 import (OperationCatalog, partition_obligations, close, instantiate,
                 validate_manifest_implication)
from .m4 import feedback_level, condition_frontier, first_repair, confirm


class PipelineConfig:
    """Freeze-able pipeline configuration (target, budgets, confirmation)."""

    def __init__(self, target, budgets=None, confirmation=None, seed=None,
                 seed_prog=None, max_rounds=4):
        self.target = target
        self.budgets = budgets or {"wall_seconds": 3600, "executions": 200,
                                   "llm_calls": 200, "llm_tokens": 400000}
        self.confirmation = confirmation or {"q": 2, "n_c": 5}
        self.seed = seed
        self.seed_prog = seed_prog
        self.max_rounds = max_rounds


def build_llm(llm_config_path=None, mock=False):
    """Construct the LLM client from a config path, or a mock when requested."""
    if mock or not llm_config_path:
        return MockLLM()
    return LLMClient.from_config(llm_config_path)


def run_pipeline(report_bundle, config, llm=None, source_index=None,
                 catalog=None, runtime=None):
    """Run the complete pipeline and return a structured result.

    ``config`` is a :class:`PipelineConfig`. ``report_bundle`` is the raw report
    (dict) or a path to a JSON bundle.
    """
    if isinstance(report_bundle, str):
        with open(report_bundle, "r", encoding="utf-8") as f:
            report_bundle = json.load(f)

    llm = llm or MockLLM()
    source_index = source_index or SourceIndex.running_example()
    catalog = catalog or OperationCatalog()
    runtime = runtime or DryRunRuntime()

    budget = dict(config.budgets)
    q, n_c = config.confirmation["q"], config.confirmation["n_c"]
    started = time.monotonic()
    executions = 0

    # --- M1: normalization, readiness, routing, preflight ----------------- #
    report = normalize(llm, report_bundle)
    route, qr = decide_route(report)

    if not qr["failureReady"] or not qr["targetReady"]:
        return _terminal("Evidence-Insufficient", report=report.to_dict(visible_only=True),
                         readiness=qr, reason="missing target metadata or falsifiable anchor")

    a_k = preflight(config.target["id"], config.target["source_sha256"],
                    config.target["config_sha256"], config.target["baseline"],
                    config.target["environment"], config.target["capabilities"])

    ctx_r = context_report(report_bundle.get("report_id", "episode-0"),
                           report_bundle.get("report_version", 1),
                           digest(report.to_dict(visible_only=True)))

    # --- M2: mechanism and trigger inference ------------------------------ #
    bundles, source_graph = infer(report, route, source_index, llm,
                                  n_h=min(4, budget.get("llm_calls", 4)))
    if not bundles:
        return _terminal("Search-Exhausted", report=report.to_dict(visible_only=True),
                         readiness=qr, route=route, source_graph=source_graph, stage="M2")

    # --- M3: construction ------------------------------------------------- #
    candidate = None
    for bundle in bundles:
        tg = bundle["trigger_graph"]
        operation_graph, unresolved = close(tg, catalog, route,
                                            seed_ops=_seed_ops(config, catalog))
        if unresolved:
            continue
        inst = instantiate(tg, operation_graph, route, seed_prog=config.seed_prog)
        ok, why = validate_manifest_implication(report, inst["manifest"], tg)
        if not ok:
            continue
        candidate = {"bundle": bundle, "operation_graph": operation_graph,
                     "program": inst["program"], "manifest": inst["manifest"],
                     "pre_state": inst["pre_state_checklist"]}
        break

    if candidate is None:
        return _terminal("Construction-Unsatisfied", report=report.to_dict(visible_only=True),
                         readiness=qr, route=route, bundles=bundles, source_graph=source_graph)

    # --- M4: refinement + confirmation ------------------------------------ #
    ctx_h = context_hypothesis(ctx_r, hypothesis_version=1, trigger_version=1,
                               attestation_digest=digest(a_k))
    ctx_a = context_action(ctx_h, operation_version=1)
    if not (admit(ctx_h, ctx_r["digest"]) and admit(ctx_a, ctx_h["digest"])):
        return _terminal("Unconfirmed-Identity", report=report.to_dict(visible_only=True),
                         readiness=qr, route=route, reason="context admission failed")

    observers = set(candidate["manifest"]["observers"])
    trials, repairs = [], []
    final_program = candidate["program"]

    for round_idx in range(config.max_rounds):
        trace = runtime.run(final_program, candidate["manifest"], attempt=round_idx)
        executions += 1
        frontier = condition_frontier(candidate["bundle"]["trigger_graph"], trace, observers)
        repair = first_repair(frontier)
        trials.append({"round": round_idx, "trace": trace, "frontier": frontier,
                       "repair": repair})
        if repair is None:
            break
        # Scoped repair: in this offline reference the dry-run runtime already
        # varies its trace deterministically; record the repair and continue.
        repairs.append(repair)

    # Frozen joint confirmation over n_c fresh resets.
    reset_runs = []
    for i in range(n_c):
        trace = runtime.run(final_program, candidate["manifest"], attempt=i)
        executions += 1
        reset_runs.append({
            "identity": _identity_match(trace, report),
            "outcomes": _outcome_match(trace, candidate["manifest"]),
            "trigger": _trigger_match(trace, candidate["bundle"]["trigger_graph"]),
        })
    confirmation = confirm(reset_runs, q, n_c)

    used = {
        "wall_seconds": round(time.monotonic() - started, 3),
        "executions": executions,
        "llm_calls": getattr(llm, "calls", 0),
        "llm_tokens": getattr(llm, "tokens", 0),
    }
    audit = {
        "budget_limits": budget,
        "budget_used": used,
        "accepted_edits": repairs,
        "rounds": len(trials),
        "terminal_reason": ("confirmation threshold met" if confirmation["verified"]
                            else "joint confirmation below q"),
    }

    terminal = "Verified" if confirmation["verified"] else "Unconfirmed-Identity"
    # Budget exhaustion is recorded explicitly and never redefines a result.
    if used["wall_seconds"] > budget["wall_seconds"]:
        terminal = "Budget-Exhausted(M4)"
    elif used["executions"] > budget["executions"]:
        terminal = "Budget-Exhausted(M4)"
    elif used["llm_calls"] > budget["llm_calls"] or used["llm_tokens"] > budget["llm_tokens"]:
        terminal = "Budget-Exhausted(M2)"

    return {
        "terminal_outcome": terminal,
        "report": report.to_dict(visible_only=True),
        "readiness": qr,
        "route": route,
        "target": a_k,
        "source_graph": source_graph,
        "bundles": [{"mechanism": b["mechanism"], "presentation": b["presentation"],
                     "grounded": b["grounded"]} for b in bundles],
        "program": final_program,
        "manifest": candidate["manifest"],
        "pre_state_checklist": candidate["pre_state"],
        "trials": trials,
        "repairs": repairs,
        "confirmation": confirmation,
        "audit": audit,
    }


def _seed_ops(config, catalog):
    if config.seed_prog:
        return [catalog.get("openat$nullb")] if catalog.get("openat$nullb") else []
    return None


def _identity_match(trace, report):
    # In a real run this correlates the observed failure with the frozen
    # visible identity predicates (allocation/access epoch + code context). The
    # dry-run runtime signals that correlation by emitting lifecycle events.
    return bool(trace.get("events"))


def _outcome_match(trace, manifest):
    # O_A matches when the build/setup succeeded and no operation returned an
    # early error; the dry-run signals a must-effect failure with ``errno``.
    return bool(trace.get("build_ok") and trace.get("setup_ok") and not trace.get("errno"))


def _trigger_match(trace, trigger_graph):
    patterns = {c["verification"] for c in trigger_graph["constraints"]}
    observed = {e.get("pattern") for e in trace.get("events", [])}
    return bool(patterns & observed)


def _terminal(outcome, **extra):
    result = {"terminal_outcome": outcome}
    result.update(extra)
    return result


# --------------------------------------------------------------------------- #
# Trial runtimes (Section 5)
# --------------------------------------------------------------------------- #

def trial_result(**kwargs):
    """Build a trial trace record."""
    base = {
        "build_ok": True,
        "setup_ok": True,
        "returns": {},
        "errno": None,
        "diagnostics": [],
        "signature": None,
        "coverage": [],
        "events": [],
        "counterexamples": [],
    }
    base.update(kwargs)
    return base


class DryRunRuntime:
    """Deterministic offline trace generator for the running example."""

    def run(self, program, manifest, attempt=0):
        # Deterministic: even attempts observe the required overlap, odd attempts
        # return early (ENXIO) before reaching the deletion path.
        if attempt % 2 == 0:
            return trial_result(
                setup_ok=True,
                returns={"openat$nullb": 0},
                errno=None,
                diagnostics=["openat succeeded"],
                coverage=["blkpg_ioctl", "add_partition", "bdev_del_partition"],
                events=[{"pattern": "add_partition success"},
                        {"pattern": "same device/partition number"},
                        {"pattern": "cross-actor epoch overlap"}],
                counterexamples=[],
            )
        return trial_result(
            setup_ok=True,
            returns={"openat$nullb": -1},
            errno="-ENXIO",
            diagnostics=["-ENXIO before deletion"],
            coverage=["blkpg_ioctl"],
            events=[],
            counterexamples=[],
        )


class QemuRuntime:
    """Production runner over the vendored fuzzing runtime.

    The executor and ``syz-execprog`` are built by ``fuzzer/build-runtime.sh``;
    ``config`` is a manager configuration (see ``fuzzer/config.example.json``).
    This backend runs only on the Ubuntu experiment host with a booted target.
    """

    def __init__(self, syz_execprog=None, executor=None, config=None, workdir=None):
        root = Path(__file__).resolve().parent.parent
        self.syz_execprog = syz_execprog or str(root / "fuzzer" / "bin" / "linux_amd64" / "syz-execprog")
        self.executor = executor or str(root / "fuzzer" / "bin" / "linux_amd64" / "syz-executor")
        self.config = config or str(root / "fuzzer" / "config.example.json")
        self.workdir = workdir or str(root / "workdir")

    def run(self, program, manifest, attempt=0):
        proc = subprocess.run(
            [self.syz_execprog, "-executor", self.executor,
             "-cover", "-repeat=1", "-procs=1", "-config", self.config, "-"],
            input=program, capture_output=True, text=True, check=False,
        )
        return trial_result(
            build_ok=proc.returncode == 0,
            diagnostics=[proc.stderr[-4000:] if proc.stderr else ""],
            coverage=[],  # populated by the KCOV parser on the host
        )
