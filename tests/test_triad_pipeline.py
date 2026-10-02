"""Pure unit tests for the TRIAD M1-M4 pipeline.

These tests exercise report normalization, mechanism/trigger inference,
dependency-aware construction, refinement/confirmation accounting and the LLM
schema validator. They perform no kernel, VM, model or network work.
"""

import unittest

from triad import model
from triad.model import context_report, context_hypothesis, context_action, admit
from triad.llm import MockLLM, validate_schema, LLMError
from triad.m1 import (normalize, assess_readiness, decide_route, parse_stack,
                      parse_kasan_class, parse_syz_program)
from triad.m2 import infer, SourceIndex, presentation
from triad.m3 import (partition_obligations, close, instantiate,
                      validate_manifest_implication)
from triad.m4 import confirm, condition_frontier, blocker_pattern
from triad.m3 import OperationCatalog
from triad.controller import run_pipeline, PipelineConfig
from triad.cli import EXAMPLE_REPORT


class TestParsers(unittest.TestCase):
    def test_parse_stack(self):
        frames = parse_stack(EXAMPLE_REPORT["stack"])
        self.assertEqual(frames[:2], ["kobject_put", "bdev_del_partition"])

    def test_parse_kasan(self):
        self.assertEqual(parse_kasan_class(EXAMPLE_REPORT["log"]), "use-after-free")

    def test_parse_syz_program(self):
        parsed = parse_syz_program(EXAMPLE_REPORT["syz_prog"])
        self.assertTrue(parsed["resource_bound"])
        self.assertIn("openat$nullb", parsed["calls"])


class TestM1(unittest.TestCase):
    def test_normalize_and_route(self):
        llm = MockLLM()
        report = normalize(llm, EXAMPLE_REPORT)
        self.assertEqual(report.group("failure")["class"], "KASAN use-after-free read")
        self.assertTrue(report.group("origin")["commit"])
        route, qr = decide_route(report)
        self.assertEqual(route["mechanism"], "align")
        self.assertEqual(route["construction"], "seed-completion")
        self.assertTrue(qr["failureReady"])


class TestM2(unittest.TestCase):
    def test_infer_produces_trigger_graph(self):
        llm = MockLLM()
        report = normalize(llm, EXAMPLE_REPORT)
        route, _ = decide_route(report)
        bundles, source_graph = infer(report, route, SourceIndex.running_example(), llm)
        self.assertTrue(bundles)
        tg = bundles[0]["trigger_graph"]
        model.validate_trigger_graph(tg)
        kinds = {c["kind"] for c in tg["constraints"]}
        self.assertIn("overlaps", kinds)
        self.assertTrue(presentation(tg)["actors"])


class TestM3(unittest.TestCase):
    def test_close_and_instantiate(self):
        llm = MockLLM()
        report = normalize(llm, EXAMPLE_REPORT)
        route, _ = decide_route(report)
        bundles, _ = infer(report, route, SourceIndex.running_example(), llm)
        tg = bundles[0]["trigger_graph"]
        build, runtime = partition_obligations(tg)
        self.assertTrue(build)
        catalog = OperationCatalog()
        op_graph, unresolved = close(tg, catalog, route)
        self.assertFalse(unresolved)
        inst = instantiate(tg, op_graph, route)
        self.assertIn("ioctl$BLKPG_ADD_PARTITION", inst["program"])
        ok, _ = validate_manifest_implication(report, inst["manifest"], tg)
        self.assertTrue(ok)


class TestM4(unittest.TestCase):
    def test_confirm_accounting(self):
        runs = [{"identity": True, "outcomes": True, "trigger": True}] * 3
        result = confirm(runs, q=2, n_c=3)
        self.assertTrue(result["verified"])
        self.assertEqual(result["joint_hits"], 3)

    def test_confirm_rejects_insufficient(self):
        runs = [{"identity": True, "outcomes": True, "trigger": True},
                {"identity": False, "outcomes": True, "trigger": True}] * 2
        result = confirm(runs, q=2, n_c=3)
        self.assertFalse(result["verified"])


class TestLLMSchema(unittest.TestCase):
    def test_schema_validation(self):
        schema = {"type": "object", "properties": {"claims": {"type": "array"}},
                  "required": ["claims"], "additionalProperties": False}
        self.assertEqual(validate_schema(schema, {"claims": []}), {"claims": []})
        with self.assertRaises(LLMError):
            validate_schema(schema, {"other": 1})


class TestContexts(unittest.TestCase):
    def test_admission(self):
        r = context_report("ep", 1, "d")
        h = context_hypothesis(r, 1, 1, "a")
        a = context_action(h, 1)
        self.assertTrue(admit(h, r["digest"]))
        self.assertTrue(admit(a, h["digest"]))
        self.assertFalse(admit(a, "wrong"))


class TestController(unittest.TestCase):
    def test_run_pipeline_dry_run(self):
        config = PipelineConfig(
            target={"id": "t", "source_sha256": "0" * 64, "config_sha256": "0" * 64,
                    "baseline": "s0", "environment": "ubuntu-22.04",
                    "capabilities": ["kasan", "kcov", "kprobe"]},
            confirmation={"q": 2, "n_c": 5},
        )
        result = run_pipeline(EXAMPLE_REPORT, config)
        self.assertIn(result["terminal_outcome"], ("Verified", "Unconfirmed-Identity"))
        self.assertIn("ioctl$BLKPG_ADD_PARTITION", result["program"])
        self.assertEqual(result["confirmation"]["clean_resets"], 5)


if __name__ == "__main__":
    unittest.main()
