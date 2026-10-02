"""Record validation and the deterministic release export.

Validation never executes or generates test programs. The exporter reads the
explicit ``config/release-files.json`` allowlist (file entries or directory
entries), scans text content for common secrets, and writes a deterministic
archive with content digests.
"""

import datetime as dt
import gzip
import hashlib
import io
import json
import math
import re
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


class Invalid(ValueError):
    """A record is incomplete or contradicts the declared protocol."""


TERMINALS = {
    "Verified", "Evidence-Insufficient", "Target-Version-Mismatch",
    "Target-Already-Fixed", "Environment-Unavailable", "Unsupported-Condition",
    "Construction-Unsatisfied", "Unconfirmed-Identity", "Search-Exhausted",
    "Beam-Truncated(M3)",
    *(f"Budget-Exhausted({s})" for s in ("M1", "M2", "M3", "M4")),
}
ROUTES = ("align+seed", "align+free", "infer+seed", "infer+free", "pre-routing-terminal")


def require(condition, message):
    if not condition:
        raise Invalid(message)


def object_record(value, label):
    require(isinstance(value, dict), f"{label}: expected an object")
    return value


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def sha256(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def load_json(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            require(k not in result, f"{Path(path).name}: duplicate JSON key {k}")
            result[k] = v
        return result

    def invalid_constant(_):
        raise Invalid("non-finite JSON numeric constant")

    return json.loads(Path(path).read_text(encoding="utf-8"),
                      object_pairs_hook=unique, parse_constant=invalid_constant)


def load_jsonl(path):
    rows = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        def unique(pairs):
            record = {}
            for k, v in pairs:
                require(k not in record, f"line {n}: duplicate JSON key {k}")
                record[k] = v
            return record
        row = json.loads(line, object_pairs_hook=unique)
        object_record(row, f"line {n}")
        rows.append(row)
    return rows


def date(value):
    require(isinstance(value, str), "date must be YYYY-MM-DD")
    parsed = dt.date.fromisoformat(value)
    require(parsed.isoformat() == value, "date must be YYYY-MM-DD")
    return parsed


def validate_protocol(p, frozen=False):
    object_record(p, "protocol")
    require(p.get("schema_version") == 1, "unsupported protocol schema")
    require(p.get("status") in ("draft", "frozen"), "unknown protocol status")
    if p["status"] == "draft":
        require(not frozen, "protocol is draft; no publication report can be produced")
        return
    for field in ("inclusion_criteria", "oracle_policy_ref", "hardware_description"):
        require(nonempty(p.get(field)), f"protocol.{field} is required")
    window = object_record(p.get("source_window"), "source_window")
    require(date(window.get("start")) <= date(window.get("end")), "reversed source window")
    seeds = p.get("seeds")
    require(isinstance(seeds, list) and seeds and all(integer(x) for x in seeds), "missing integer seeds")
    require(len(seeds) == len(set(seeds)), "duplicate seeds")
    b = object_record(p.get("budgets"), "budgets")
    for k in ("wall_seconds", "executions", "llm_calls", "llm_tokens"):
        require(integer(b.get(k), 1), f"positive protocol budget required: {k}")
    c = object_record(p.get("confirmation"), "confirmation")
    require(integer(c.get("q"), 2) and integer(c.get("n_c"), 2), "q and n_c must be integers >= 2")
    require(c["q"] <= c["n_c"], "q exceeds n_c")
    configs = p.get("configurations")
    require(isinstance(configs, list) and configs, "no configurations frozen")
    ids = []
    for config in configs:
        object_record(config, "configuration")
        for key in ("id", "model_revision", "component_revision", "ablation"):
            require(nonempty(config.get(key)), f"configuration.{key} is required")
        require(config.get("kind") in ("primary", "patch-assisted"), "unknown configuration kind")
        require(config.get("feedback_level") in ("L0", "L1", "L2", "L3"), "unknown feedback level")
        ids.append(config["id"])
    require(len(set(ids)) == len(ids), "duplicate configuration IDs")


def route(sample):
    if sample["pre_routing_terminal"]:
        return "pre-routing-terminal"
    return ("align" if sample["analysis_available"] else "infer") + "+" + (
        "seed" if sample["seed_usable"] else "free")


def validate_samples(rows, protocol):
    ids, sources = set(), set()
    for s in rows:
        object_record(s, "sample")
        sid = s.get("id")
        require(nonempty(sid) and sid not in ids, "missing or duplicate sample ID")
        ids.add(sid)
        require(s.get("record_kind") == "real", f"{sid}: only real records enter the evaluation")
        require(s.get("partition") == "evaluation", f"{sid}: reference/example records cannot enter evaluation")
        require(nonempty(s.get("bug_class")), f"{sid}: missing bug class")
        src = object_record(s.get("source"), f"{sid}.source")
        require(src.get("kind") in ("public-cve", "syzbot", "third-party"), f"{sid}: unknown source kind")
        require(nonempty(src.get("id")), f"{sid}: missing source identifier")
        identity = (src["kind"], src["id"])
        require(identity not in sources, f"{sid}: duplicate source; resolve aliases before freezing")
        sources.add(identity)
        if src["kind"] != "third-party":
            u = urlparse(src.get("url", ""))
            require(u.scheme == "https" and u.hostname and not u.username and not u.password,
                    f"{sid}: public source needs an HTTPS provenance URL")
        else:
            require(nonempty(src.get("provenance_ref")), f"{sid}: third-party provenance reference required")
        date(src.get("retrieved_on"))
        reported = date(src.get("reported_on"))
        require(sha256(src.get("artifact_sha256")), f"{sid}: source artifact SHA-256 required")
        if protocol["status"] == "frozen":
            w = protocol["source_window"]
            require(date(w["start"]) <= reported <= date(w["end"]), f"{sid}: outside declared source window")
        for f in ("pre_routing_terminal", "embedded_code", "patch_oracle_available"):
            require(type(s.get(f)) is bool, f"{sid}.{f}: explicit boolean required")
        for f in ("analysis_available", "seed_usable", "buildable"):
            require(s.get(f) is None or type(s.get(f)) is bool, f"{sid}.{f}: boolean or null required")
        require(nonempty(s.get("assessment_ref")), f"{sid}: readiness annotation reference required")
        if s["pre_routing_terminal"]:
            require(s.get("terminal_outcome") in TERMINALS - {"Verified"}, f"{sid}: explicit terminal outcome required")
        else:
            require(all(type(s.get(f)) is bool for f in ("analysis_available", "seed_usable")),
                    f"{sid}: undecidable routing belongs in the pre-routing stratum")
            require(s.get("buildable") is True, f"{sid}: successful target preflight required for route-eligible subject")
            target = object_record(s.get("target"), f"{sid}.target")
            for f in ("revision", "architecture", "compiler", "environment_id"):
                require(nonempty(target.get(f)), f"{sid}.target.{f} is required")
            for f in ("source_sha256", "config_sha256", "baseline_sha256"):
                require(sha256(target.get(f)), f"{sid}.target.{f} is required")
    return {s["id"]: s for s in rows}


def validate_runs(rows, samples, protocol, complete=False):
    validate_protocol(protocol, frozen=True)
    configs = {c["id"]: c for c in protocol["configurations"]}
    seen, run_ids = set(), set()
    q, nc = protocol["confirmation"]["q"], protocol["confirmation"]["n_c"]
    for r in rows:
        object_record(r, "run")
        rid = r.get("id")
        require(nonempty(rid) and rid not in run_ids, "duplicate or missing run ID")
        run_ids.add(rid)
        sid, cid, seed = r.get("sample_id"), r.get("configuration_id"), r.get("seed")
        require(isinstance(sid, str) and sid in samples, f"{rid}: unknown sample")
        require(isinstance(cid, str) and cid in configs, f"{rid}: unknown configuration")
        require(integer(seed) and seed in protocol["seeds"], f"{rid}: undeclared random seed")
        key = (sid, cid, seed)
        require(key not in seen, f"{rid}: duplicate sample/configuration/seed cell")
        seen.add(key)
        require(r.get("record_kind") == "real", f"{rid}: synthetic run prohibited")
        require(r.get("protocol_sha256") == digest(protocol), f"{rid}: protocol digest mismatch")
        require(r.get("sample_sha256") == digest(samples[sid]), f"{rid}: sample digest mismatch")
        require(r.get("terminal_outcome") in TERMINALS, f"{rid}: unknown terminal outcome")
        require(r.get("oracle_verdict") in ("confirmed", "rejected", "unresolved"), f"{rid}: missing oracle verdict")
        require(r.get("feedback_level") == configs[cid]["feedback_level"], f"{rid}: feedback configuration mismatch")
        require(isinstance(r.get("blockers"), list) and all(x in ("F1", "F2", "F3", "F4", "F5") for x in r["blockers"]),
                f"{rid}: blockers must be a list of F1-F5 labels")
        for f in ("wall_seconds", "cost_usd", "setup_seconds"):
            require(number(r.get(f)), f"{rid}.{f}: finite nonnegative value required")
        for f in ("executions", "llm_calls", "llm_tokens", "interventions", "rounds", "clean_resets", "joint_hits"):
            require(integer(r.get(f)), f"{rid}.{f}: nonnegative integer required")
        for f in protocol["budgets"]:
            require(r[f] <= protocol["budgets"][f], f"{rid}: exceeded frozen budget {f}")
        require(0 <= r["joint_hits"] <= r["clean_resets"] <= nc, f"{rid}: invalid confirmation counts")
        require(sha256(r.get("evidence_sha256")) and nonempty(r.get("evidence_ref")), f"{rid}: evidence bundle reference/digest required")
        require(sha256(r.get("oracle_record_sha256")) and nonempty(r.get("oracle_record_ref")), f"{rid}: adjudication reference/digest required")
        if samples[sid]["pre_routing_terminal"]:
            require(r["terminal_outcome"] == samples[sid]["terminal_outcome"], f"{rid}: pre-routing outcome changed")
            require(r["oracle_verdict"] != "confirmed", f"{rid}: terminal intake cannot be confirmed")
        if r["terminal_outcome"] == "Verified" or r["oracle_verdict"] == "confirmed":
            require(samples[sid]["buildable"] is True, f"{rid}: confirmation on unbuildable target")
            require(r["clean_resets"] == nc and r["joint_hits"] >= q, f"{rid}: confirmation threshold not met")
        if r["oracle_verdict"] == "confirmed":
            require(r["terminal_outcome"] == "Verified", f"{rid}: oracle confirmation without pipeline package")
            require(r.get("oracle_rule_frozen") is True and r.get("outputs_frozen_before_oracle") is True,
                    f"{rid}: oracle independence not attested")
            if samples[sid]["patch_oracle_available"]:
                require(r.get("fixed_build_negative") is True, f"{rid}: negative fixed-build differential required")
            else:
                experts = r.get("expert_ids")
                require(isinstance(experts, list) and all(nonempty(x) for x in experts) and len(set(experts)) >= 2,
                        f"{rid}: two distinct agreeing anonymous adjudicators required")
    expected = {(sid, cid, seed) for sid in samples for cid in configs for seed in protocol["seeds"]}
    missing = expected - seen
    if complete:
        require(samples, "evaluation dataset is empty")
        require(not missing, f"incomplete run matrix: {len(missing)} missing cells (not treated as failures)")
    return missing


def summarize(samples, runs, protocol):
    validate_runs(runs, samples, protocol, complete=True)
    rows = []
    for c in protocol["configurations"]:
        for seed in protocol["seeds"]:
            selected = [r for r in runs if r["configuration_id"] == c["id"] and r["seed"] == seed]
            confirmed = [r for r in selected if r["oracle_verdict"] == "confirmed"]
            buildable = sum(s["buildable"] is True for s in samples.values())
            verified = [r for r in selected if r["terminal_outcome"] == "Verified"]
            decided = [r for r in verified if r["oracle_verdict"] != "unresolved"]
            rows.append({
                "configuration": c["id"], "kind": c["kind"], "seed": seed,
                "subjects": len(samples), "buildable_subjects": buildable,
                "oracle_confirmed": len(confirmed), "rate_all": len(confirmed) / len(samples),
                "rate_buildable": len(confirmed) / buildable if buildable else None,
                "pipeline_verified": len(verified),
                "false_accepts": sum(r["oracle_verdict"] == "rejected" for r in verified),
                "unresolved_verified": sum(r["oracle_verdict"] == "unresolved" for r in verified),
                "precision_decided": sum(r["oracle_verdict"] == "confirmed" for r in decided) / len(decided) if decided else None,
                "wall_seconds_all": sum(r["wall_seconds"] for r in selected),
                "llm_tokens_all": sum(r["llm_tokens"] for r in selected),
                "cost_usd_all": sum(r["cost_usd"] for r in selected),
                "interventions_all": sum(r["interventions"] for r in selected),
            })
    return rows


# --------------------------------------------------------------------------- #
# Deterministic release export
# --------------------------------------------------------------------------- #

def findings(text, upstream=False):
    """Scan text for common secrets.

    ``upstream=True`` marks vendored third-party code: only credential-like
    tokens are checked, because public upstream trees legitimately contain key
    templates, example paths, VM network addresses and developer emails that
    cannot leak the submission authors' identity.
    """
    if upstream:
        checks = {"credential-like-token": r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}"}
    else:
        checks = {
            "private-key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "credential-like-token": r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}",
            "personal-absolute-path": r"/(?:Users|home|disk)/[^\s\"']+",
            "private-network-address": r"\b(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)\b",
            "email-address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        }
    return [name for name, pattern in checks.items() if re.search(pattern, text)]


def _add_release_file(root, path, files, hashes, upstream, skipped):
    require(not any(x.is_symlink() for x in (path, *path.parents) if x != root),
            "symlinks are not exported")
    require(path.is_file() and path.resolve().is_relative_to(root),
            "missing or escaping release file")
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        if upstream:
            # Binary test fixtures and generated data inside the vendored tree
            # are excluded rather than blocking the whole export.
            skipped.append(path.relative_to(root).as_posix())
            return
        raise ValueError("binary files require a separate metadata review") from None
    hits = findings(text, upstream=upstream)
    require(not hits, "release scan blocked %s: %s" % (path, ", ".join(hits)))
    rel = path.relative_to(root).as_posix()
    files[rel] = data
    hashes[rel] = hashlib.sha256(data).hexdigest()


def export(root, destination):
    root, destination = Path(root).resolve(), Path(destination)
    entries = load_json(root / "config/release-files.json")
    require(isinstance(entries, list) and entries and all(isinstance(p, str) for p in entries),
            "invalid release allowlist")
    require(len(entries) == len(set(entries)), "duplicate release paths")
    files, hashes, skipped = {}, {}, []
    for item in sorted(entries):
        rel = PurePosixPath(item)
        require(not rel.is_absolute() and ".." not in rel.parts and rel.parts,
                "release path must stay inside the repository")
        require(rel.parts[0] not in ("legacy", "results", "dist") and item != ".env",
                "private/generated path in release allowlist")
        path = root / item
        upstream = rel.parts[0] == "fuzzer"
        if path.is_dir():
            for child in sorted(x for x in path.rglob("*") if x.is_file()):
                _add_release_file(root, child, files, hashes, upstream, skipped)
        else:
            _add_release_file(root, path, files, hashes, upstream, skipped)
    files["MANIFEST.json"] = (json.dumps({"scope": "artifact-support-only",
                                          "sha256": hashes}, sort_keys=True, indent=2) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo("TRIAD-artifact-support/" + name)
                    info.size = len(data)
                    info.mode = 0o644
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(data))
    return {"scope": "artifact-support-only", "files": len(files),
            "skipped_binary": len(skipped),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "automated_scan": "passed", "human_anonymity_review_required": True,
            "full_pipeline_included": False}
