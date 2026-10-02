"""M1 - report normalization, readiness and routing.

Deterministic parsers handle artifacts with stable syntax (stacks, logs,
configurations, metadata, programs); an LLM extracts only semantic prose
claims. Both paths populate a sparse :class:`NormalizedBugReport` and preserve
exact artifacts beside their parsed projections (Section M1).
"""

from __future__ import annotations

import re

from .model import (NormalizedBugReport, readiness_vector, route,
                    target_attestation)
from .llm import validate_schema

# --------------------------------------------------------------------------- #
# Deterministic parsers
# --------------------------------------------------------------------------- #

_STACK_FRAME = re.compile(r"(?:#\d+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\+?[^\n]*")
_KASAN_UAF = re.compile(r"KASAN:\s*(use-after-free|out-of-bounds|double-free|slab-out-of-bounds)[^\n]*", re.I)
_CALL_TRACE = re.compile(r"Call Trace:[\s\S]*?(?=\n\n|\Z)")
_ORIGIN_COMMIT = re.compile(r"\bcommit[:=\s]+([0-9a-f]{7,40})\b", re.I)
# Broader diagnostic classes: sanitizer reports, faults, BUG/WARNING.
_DIAGNOSTIC = re.compile(
    r"(?:KASAN|KCSAN|KFENCE|UBSAN|KMEMLEAK):\s*[^\n]*(use-after-free|"
    r"out-of-bounds|double-free|wild-memory-access|slab-out-of-bounds|"
    r"invalid-free|stack-out-of-bounds|global-out-of-bounds)[^\n]*", re.I)
_NULL_DEREF = re.compile(r"(?:BUG: )?(?:KASAN: )?null-ptr-deref[^\n]*", re.I)
_GPF = re.compile(r"general protection fault[^\n]*", re.I)
_BUG_WARN = re.compile(r"(?:kernel BUG at [^\n]+|WARNING: [^\n]+)", re.I)


def parse_stack(text):
    """Return a list of function names from a kernel stack trace."""
    frames = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip frame numbers, addresses and offsets; keep the symbol.
        m = _STACK_FRAME.match(line)
        if m:
            frames.append(m.group(1))
    return frames


def parse_kasan_class(text):
    """Extract a KASAN/diagnostic failure class from a report body."""
    m = _KASAN_UAF.search(text or "")
    return m.group(1) if m else None


def parse_diagnostic_class(text):
    """Extract a broader diagnostic class: sanitizer classes, null-pointer
    dereference, general protection fault, or BUG/WARNING."""
    text = text or ""
    for pattern in (_DIAGNOSTIC, _NULL_DEREF, _GPF, _BUG_WARN):
        m = pattern.search(text)
        if m:
            return m.group(0).strip()
    return None


def parse_syzbot_report(text):
    """Extract structured metadata from a syzbot report body.

    Returns ``{title, repro_syz, repro_c, config, commit}`` where each artifact
    is flagged by its presence; values are never invented when absent.
    """
    text = text or ""
    title = ""
    for line in text.splitlines():
        if line.strip():
            title = line.strip()
            break
    return {
        "title": title,
        "repro_syz": "syz repro" in text,
        "repro_c": "C reproducer" in text or "C repro" in text,
        "config": "config:" in text.lower(),
        "commit": parse_origin_commit(text),
    }


def parse_call_trace(text):
    m = _CALL_TRACE.search(text or "")
    return m.group(0).strip() if m else None


def parse_origin_commit(text):
    m = _ORIGIN_COMMIT.search(text or "")
    return m.group(1) if m else None


def parse_config(text):
    """Extract ``CONFIG_*=*`` lines from a kernel configuration."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("CONFIG_"):
            if "=" in line:
                key, _, val = line.partition("=")
                out[key] = val
            else:
                out[line] = True
    return out


def parse_syz_program(text):
    """Best-effort structural parse of a syz-lang program.

    Returns the ordered call names and a flag indicating whether the program
    type-checks against the declared resource syntax (this prototype checks the
    coarse ``r0 = ...`` resource-binding shape, not the full syzkaller type
    checker).
    """
    calls = []
    resource_bound = False
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            lhs = line.split("=")[0].strip()
            if lhs.startswith("r") and lhs[1:].isdigit():
                resource_bound = True
        if "(" in line:
            name = line.split("(")[0].strip()
            # Strip a leading assignment such as "r0 = openat(...)".
            if "=" in name:
                name = name.split("=")[-1].strip()
            if name and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name):
                calls.append(name)
    return {"calls": calls, "resource_bound": resource_bound}


# --------------------------------------------------------------------------- #
# Semantic prose extraction (LLM, schema-validated)
# --------------------------------------------------------------------------- #

_SEMANTIC_SCHEMA = {
    "type": "object",
    "properties": {"claims": {"type": "array", "items": {
        "type": "object",
        "properties": {
            "key": {"type": "string"},
            "value": {"type": "string"},
            "confidence": {"type": "number"},
        },
        "required": ["key", "value", "confidence"],
        "additionalProperties": False,
    }}},
    "required": ["claims"],
    "additionalProperties": False,
}


def extract_prose_claims(llm, prose):
    """Extract only semantic claims from prose; no invented exact artifacts."""
    if not (prose or "").strip():
        return []
    result = llm.complete(
        [{"role": "system",
          "content": "Extract only semantic claims (invariants, environment "
                     "requirements) from the report prose. Do not invent or "
                     "rewrite addresses, stacks, configurations or seeds."},
         {"role": "user", "content": prose}],
        _SEMANTIC_SCHEMA,
    )
    return result.get("claims", [])


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def normalize(llm, bundle, projection=True):
    """Normalize a raw report bundle into a :class:`NormalizedBugReport`.

    ``bundle`` may carry ``report_id``, ``channel``, ``prose``, ``stack``,
    ``config``, ``log``, ``syz_prog``, ``c_repro``, ``origin_commit``, ``kernel``
    and ``arch``. Unknown or absent fields remain absent.
    """
    report_id = bundle.get("report_id", "unnamed")
    channel = bundle.get("channel", "unknown")
    report = NormalizedBugReport(report_id, channel, projection=projection)

    origin = report.group("origin")
    if bundle.get("origin_commit") or parse_origin_commit(bundle.get("log", "")):
        origin["commit"] = bundle.get("origin_commit") or parse_origin_commit(bundle.get("log", ""))
        report.add("origin.commit", origin["commit"], "string", "report", "origin", "parsed")
    if bundle.get("kernel"):
        origin["kernel"] = bundle["kernel"]
        report.add("origin.kernel", origin["kernel"], "string", "report", "origin", "parsed")
    if bundle.get("arch"):
        origin["arch"] = bundle["arch"]
        report.add("origin.arch", origin["arch"], "string", "report", "origin", "parsed")

    # Failure evidence.
    failure = report.group("failure")
    kasan_class = (bundle.get("bug_class")
                   or parse_kasan_class(bundle.get("log", ""))
                   or parse_diagnostic_class(bundle.get("log", "")))
    if kasan_class:
        failure["class"] = kasan_class
        report.add("failure.class", kasan_class, "string", "log", "failure", "parsed")
    stack = parse_stack(bundle.get("stack", "")) or parse_stack(parse_call_trace(bundle.get("log", "")))
    if stack:
        failure["stack"] = stack
        report.add("failure.stack", stack, "list", "stack", "failure", "parsed")

    # Reproduction evidence.
    repro = report.group("reproduction")
    if bundle.get("syz_prog"):
        parsed = parse_syz_program(bundle["syz_prog"])
        repro["syz"] = {"status": "usable" if parsed["resource_bound"] else "present"}
        report.add("reproduction.syz", repro["syz"], "object", "program", "reproduction", "parsed")
    if bundle.get("c_repro"):
        repro["c_repro"] = "present"
        report.add("reproduction.c_repro", "present", "string", "program", "reproduction", "parsed")
    if bundle.get("console_log"):
        repro["console_log"] = "present"
        report.add("reproduction.console_log", "present", "string", "log", "reproduction", "parsed")

    # Prose semantics via LLM only.
    claims = extract_prose_claims(llm, bundle.get("prose", ""))
    if claims:
        analysis = report.group("analysis")
        analysis["claims"] = claims
        for i, claim in enumerate(claims):
            report.add("analysis.claim.%d" % i, claim, "object", "prose", "analysis",
                       "semantic", confidence=claim.get("confidence", 0.5),
                       verifiability=False)

    return report


# --------------------------------------------------------------------------- #
# Readiness and routing
# --------------------------------------------------------------------------- #

def assess_readiness(report):
    """Compute ``Q_R`` from the normalized report (presence != usability)."""
    failure = report.group("failure")
    repro = report.group("reproduction")
    target_ready = bool(report.group("origin").get("commit") and report.group("origin").get("kernel"))
    failure_ready = bool(failure.get("class") or failure.get("stack"))
    identity_complete = bool(failure.get("class") and failure.get("stack"))
    seed_usable = repro.get("syz", {}).get("status") == "usable"
    analysis_available = bool(report.group("analysis"))
    diag_available = bool(repro.get("console_log") or repro.get("c_repro"))
    return readiness_vector(target_ready, failure_ready, identity_complete,
                            seed_usable, analysis_available, diag_available)


def decide_route(report):
    """Return ``Route_R`` plus the route label from the two routing axes."""
    qr = assess_readiness(report)
    r = route(qr["analysisAvailable"], qr["seedUsable"])
    return r, qr


# --------------------------------------------------------------------------- #
# Trusted preflight (target attestation)
# --------------------------------------------------------------------------- #

def preflight(target_id, source_hash, config_hash, baseline, environment,
              capabilities):
    """Freeze ``A_K``. In a real run this also builds and boots the target."""
    return target_attestation(target_id, source_hash, config_hash, baseline,
                              environment, capabilities)


__all__ = [
    "NormalizedBugReport", "normalize", "assess_readiness", "decide_route",
    "preflight", "parse_stack", "parse_kasan_class", "parse_diagnostic_class",
    "parse_syzbot_report", "parse_config", "parse_syz_program",
    "extract_prose_claims",
]
