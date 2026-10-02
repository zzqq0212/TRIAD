"""Toy metadata only: no real targets, programs, network or VM execution."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from triad.cli import llm_config, ubuntu_environment
from triad.records import (Invalid, digest, export, findings, load_json,
                           load_jsonl, route, summarize, validate_protocol,
                           validate_runs, validate_samples)


def fixture():
    # In-memory records exercise the validator's `real` branch. They are not
    # written into data/ and cannot be used as research evidence.
    p = {"schema_version": 1, "status": "frozen",
         "source_window": {"start": "2000-01-01", "end": "2000-12-31"},
         "inclusion_criteria": "UNIT TEST ONLY", "oracle_policy_ref": "test-rule",
         "hardware_description": "UNIT TEST ONLY", "seeds": [7],
         "budgets": {"wall_seconds": 10, "executions": 10, "llm_calls": 10, "llm_tokens": 100},
         "confirmation": {"q": 2, "n_c": 3},
         "configurations": [{"id": "toy", "kind": "primary", "model_revision": "none",
                             "component_revision": "test", "ablation": "none", "feedback_level": "L0"}]}
    s = {"id": "UNIT-TEST", "record_kind": "real", "partition": "evaluation", "bug_class": "toy",
         "source": {"kind": "third-party", "id": "toy", "provenance_ref": "test",
                    "retrieved_on": "2000-06-01", "reported_on": "2000-05-01", "artifact_sha256": "a" * 64},
         "analysis_available": False, "seed_usable": False, "buildable": True,
         "pre_routing_terminal": False, "embedded_code": False, "patch_oracle_available": True,
         "assessment_ref": "test", "target": {"revision": "test", "architecture": "test", "compiler": "test",
         "environment_id": "test", "source_sha256": "a" * 64, "config_sha256": "b" * 64, "baseline_sha256": "c" * 64}}
    r = {"id": "UNIT-RUN", "record_kind": "real", "sample_id": s["id"], "configuration_id": "toy", "seed": 7,
         "protocol_sha256": digest(p), "sample_sha256": digest(s), "terminal_outcome": "Verified",
         "oracle_verdict": "confirmed", "feedback_level": "L0", "blockers": [], "wall_seconds": 1,
         "cost_usd": 0, "setup_seconds": 0, "executions": 3, "llm_calls": 0, "llm_tokens": 0,
         "interventions": 0, "rounds": 1, "clean_resets": 3, "joint_hits": 2,
         "evidence_ref": "test", "evidence_sha256": "d" * 64,
         "oracle_record_ref": "test", "oracle_record_sha256": "e" * 64,
         "oracle_rule_frozen": True, "outputs_frozen_before_oracle": True, "fixed_build_negative": True}
    return p, s, r


class EvidenceAccounting(unittest.TestCase):
    def setUp(self):
        self.p, self.s, self.r = fixture()

    def check(self, r=None):
        validate_protocol(self.p, frozen=True)
        samples = validate_samples([self.s], self.p)
        return validate_runs([r or self.r], samples, self.p, complete=True)

    def test_consistent_metadata(self):
        self.assertEqual(self.check(), set())

    def test_route_axes_are_orthogonal(self):
        for analysis, seed, expected in [(True, True, "align+seed"), (True, False, "align+free"),
                                          (False, True, "infer+seed"), (False, False, "infer+free")]:
            self.s.update(analysis_available=analysis, seed_usable=seed)
            self.assertEqual(route(self.s), expected)

    def test_synthetic_intake_rejected(self):
        self.s["record_kind"] = "synthetic"
        with self.assertRaises(Invalid):
            self.check()

    def test_missing_runs_not_silently_failed(self):
        with self.assertRaisesRegex(Invalid, "missing cells"):
            summarize({self.s["id"]: self.s}, [], self.p)

    def test_single_hit_not_confirmation(self):
        self.r["joint_hits"] = 1
        with self.assertRaises(Invalid):
            self.check()

    def test_all_clean_resets_required(self):
        self.r["clean_resets"] = 2
        with self.assertRaises(Invalid):
            self.check()

    def test_fixed_build_differential_required(self):
        self.r["fixed_build_negative"] = False
        with self.assertRaises(Invalid):
            self.check()

    def test_unresolved_oracle_not_counted(self):
        self.r["oracle_verdict"] = "unresolved"
        rows = summarize({self.s["id"]: self.s}, [self.r], self.p)
        self.assertEqual(rows[0]["oracle_confirmed"], 0)
        self.assertEqual(rows[0]["unresolved_verified"], 1)
        self.assertIsNone(rows[0]["precision_decided"])

    def test_rejected_pipeline_package_is_false_accept(self):
        self.r["oracle_verdict"] = "rejected"
        rows = summarize({self.s["id"]: self.s}, [self.r], self.p)
        self.assertEqual(rows[0]["false_accepts"], 1)

    def test_intake_denominator_retains_pre_routing_terminal(self):
        terminal = copy.deepcopy(self.s)
        terminal.update(id="UNIT-TERMINAL", pre_routing_terminal=True, buildable=False,
                        analysis_available=None, seed_usable=None, terminal_outcome="Environment-Unavailable")
        terminal["source"]["id"] = "toy-terminal"
        failure = copy.deepcopy(self.r)
        failure.update(id="UNIT-FAIL", sample_id=terminal["id"], sample_sha256=digest(terminal),
                       terminal_outcome="Environment-Unavailable", oracle_verdict="unresolved", clean_resets=0, joint_hits=0)
        samples = validate_samples([self.s, terminal], self.p)
        row = summarize(samples, [self.r, failure], self.p)[0]
        self.assertEqual(row["rate_all"], 0.5)
        self.assertEqual(row["rate_buildable"], 1.0)

    def test_patch_assisted_separate(self):
        self.p["configurations"][0]["kind"] = "patch-assisted"
        self.r["protocol_sha256"] = digest(self.p)
        self.assertEqual(summarize({self.s["id"]: self.s}, [self.r], self.p)[0]["kind"], "patch-assisted")

    def test_duplicate_run_rejected(self):
        r2 = dict(self.r, id="duplicate-cell")
        with self.assertRaises(Invalid):
            validate_runs([self.r, r2], {self.s["id"]: self.s}, self.p)

    def test_changed_record_hash_rejected(self):
        self.s["analysis_available"] = True
        with self.assertRaisesRegex(Invalid, "digest mismatch"):
            self.check()

    def test_nonfinite_cost_rejected(self):
        self.r["cost_usd"] = float("nan")
        with self.assertRaises(Invalid):
            self.check()

    def test_boolean_is_not_confirmation_count(self):
        self.r["joint_hits"] = True
        with self.assertRaises(Invalid):
            self.check()

    def test_no_patch_requires_distinct_experts(self):
        self.s["patch_oracle_available"] = False
        self.r["sample_sha256"] = digest(self.s)
        self.r["expert_ids"] = ["expert-1", "expert-1"]
        with self.assertRaises(Invalid):
            self.check()
        self.r["expert_ids"] = ["expert-1", "expert-2"]
        self.check()

    def test_draft_cannot_produce_report(self):
        self.p["status"] = "draft"
        with self.assertRaises(Invalid):
            validate_protocol(self.p, frozen=True)

    def test_strict_json_duplicate_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(Invalid):
                load_json(path)
            with self.assertRaises(Invalid):
                load_jsonl(path)


class EnvironmentAndRelease(unittest.TestCase):
    def test_macos_rejected_before_work(self):
        with patch("platform.system", return_value="Darwin"):
            with self.assertRaises(Invalid):
                ubuntu_environment()

    def test_llm_check_does_not_expose_token(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "llm.json"
            p.write_text(json.dumps({"provider": "openai", "base_url": "https://api.openai.com/v1",
                                     "api_key_env": "OPENAI_API_KEY", "model": "test-only"}), encoding="utf-8")
            token = "unit-test-placeholder"
            with patch.dict(os.environ, {"OPENAI_API_KEY": token}):
                result = llm_config(p)
            self.assertNotIn(token, json.dumps(result))
            self.assertEqual(result["network_requests"], 0)

    def test_release_is_deterministic_and_no_private_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/release-files.json").write_text('["README.md"]', encoding="utf-8")
            (root / "README.md").write_text("Toy public content", encoding="utf-8")
            (root / "legacy").mkdir()
            (root / "legacy/private.txt").write_text("PRIVATE", encoding="utf-8")
            a, b = root / "a.tar.gz", root / "b.tar.gz"
            export(root, a)
            export(root, b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            import tarfile
            with tarfile.open(a) as archive:
                self.assertFalse(any("legacy" in n for n in archive.getnames()))
            with self.assertRaises(FileExistsError):
                export(root, a)

    def test_release_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/release-files.json").write_text('["link"]', encoding="utf-8")
            (root / "target").write_text("public", encoding="utf-8")
            (root / "link").symlink_to(root / "target")
            with self.assertRaises(Invalid):
                export(root, root / "a.tar.gz")

    def test_release_scan_without_real_secret(self):
        fake = "sk" + "-" + "x" * 30
        self.assertIn("credential-like-token", findings(fake))
        self.assertEqual(findings("--ask-for-approval"), [])


if __name__ == "__main__":
    ubuntu_environment()
    unittest.main()
