"""Tests for benchmark correctness checks, evidence retention, and reporting."""

from contextlib import redirect_stdout
from argparse import Namespace
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import run as bench


def case(role="candidate", mode="single", asm=False):
    return {
        "id": f"{role}-asm-{'on' if asm else 'off'}-{mode}",
        "role": role,
        "revision": ("a" if role == "candidate" else "b") * 40,
        "asm": asm,
        "mode": mode,
        "workers": 12 if mode == "multi" else 1,
    }


def workload(config, seconds=1.0):
    rows = [
        {"kind": "timing", "profile": profile, "step": step,
         "iteration": iteration, "seconds": seconds + iteration}
        for profile, steps in bench.TIMINGS.items()
        for step, count in steps.items() for iteration in range(count)
    ]
    rows += [{"kind": "proof", "label": label, "bytes": 123, "digest": "a" * 128}
             for label in sorted(bench.PROOFS)]
    for profile, label in sorted(bench.SHAPES):
        wallet = profile == "wallet"
        rows.append({
            "kind": "shape", "profile": profile, "label": label,
            "rank": 13 if wallet else 15, "polynomials": 92 if wallet else 152,
            "points": 157 if wallet else 225, "scalars": 69,
            "compressed_bytes": 7264 if wallet else 9440,
            "ordinary_bytes": 24120832 if wallet else 159389056,
            "digest": "b" * 128,
        })
    return rows + [
        {"kind": "rng", "value": 12345},
        {"kind": "configuration", "workers": config["workers"],
         "asm_feature": config["asm"], "seed": 0, "header": 4,
         "inputs": [42, 7], "backend": "AcceleratedBackend"},
        {"kind": "complete", "accepted": True},
    ]


def write_records(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "run.jsonl"
        self.config = case()

    def validate(self, rows, config=None):
        write_records(self.path, rows)
        return bench.records(self.path, config or self.config)

    def test_rejects_incomplete_or_duplicate_evidence(self):
        original = workload(self.config)
        for kind in ["timing", "proof", "shape", "rng", "configuration", "complete"]:
            index = next(i for i, row in enumerate(original) if row["kind"] == kind)
            for alteration in ["missing", "duplicate"]:
                with self.subTest(kind=kind, alteration=alteration):
                    rows = copy.deepcopy(original)
                    if alteration == "missing":
                        rows.pop(index)
                    else:
                        rows.insert(index, copy.deepcopy(rows[index]))
                    with self.assertRaises(ValueError):
                        self.validate(rows)

    def test_rejects_invalid_timings_and_wrong_runtime(self):
        for seconds in [float("nan"), float("inf"), -1, True]:
            rows = workload(self.config)
            rows[0]["seconds"] = seconds
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                self.validate(rows)
        for key, value in [("workers", 12), ("asm_feature", True), ("seed", 1)]:
            rows = workload(self.config)
            rows[-2][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(rows)

    def test_identities_bind_proofs_shapes_and_rng_but_not_timing(self):
        _, original = self.validate(workload(self.config))
        _, different_time = self.validate(workload(self.config, 20))
        self.assertEqual(original, different_time)
        for kind, key, value in [
            ("proof", "digest", "c" * 128),
            ("shape", "digest", "d" * 128),
            ("shape", "ordinary_bytes", 123),
            ("rng", "value", 12346),
        ]:
            rows = workload(self.config)
            next(row for row in rows if row["kind"] == kind)[key] = value
            _, modified = self.validate(rows)
            self.assertNotEqual(original, modified)
        # Previous published runs predate the explicit runtime record. They
        # remain usable as identity references, but cannot pass as new runs.
        rows = [row for row in workload(self.config) if row["kind"] != "configuration"]
        write_records(self.path, rows)
        self.assertEqual(bench.records(self.path)[1], original)
        with self.assertRaises(ValueError):
            bench.records(self.path, self.config)

    def test_external_contention_excludes_only_our_process_tree(self):
        rows = [
            {"pid": 10, "parent": 1, "cpu": 0, "command": "/usr/bin/time"},
            {"pid": 11, "parent": 10, "cpu": 500, "command": "/tmp/workflow-candidate"},
            {"pid": 12, "parent": 11, "cpu": 100, "command": "/tmp/release/child"},
            {"pid": 20, "parent": 1, "cpu": 100, "command": "/usr/bin/rustc"},
            {"pid": 21, "parent": 20, "cpu": 100, "command": "/other/release/test"},
            {"pid": 30, "parent": 1, "cpu": 1, "command": "/usr/bin/cargo"},
        ]
        self.assertEqual([r["pid"] for r in bench.competing(rows, 10)], [20, 21])

    def test_rss_platform_units(self):
        self.assertEqual(bench.peak_rss("12345  maximum resident set size", "Darwin"), 12345)
        self.assertEqual(bench.peak_rss("Maximum resident set size (kbytes): 12345", "Linux"),
                         12345 * 1024)
        self.assertIsNone(bench.peak_rss("no external time command", "Linux"))

    def test_feature_selection_and_round_order(self):
        cases = [case(mode=mode, asm=asm) for mode in ["single", "multi"] for asm in [False, True]]
        for config in cases:
            flags = bench.feature_flags(config)
            self.assertIn("--no-default-features", flags)
            features = set(flags[-1].split(","))
            self.assertEqual("multicore" in features, config["mode"] == "multi")
            self.assertEqual("asm" in features, config["asm"])
            self.assertNotIn("large-msm-tables", features)
        observed = []
        for number in range(4):
            ordered = bench.order(cases, number)
            self.assertCountEqual(ordered, cases)
            observed.append([c["id"] for c in ordered])
        self.assertCountEqual([ids[0] for ids in observed], [c["id"] for c in cases])
        self.assertEqual(bench.order(cases, 4), list(reversed(cases)))


class CampaignTests(unittest.TestCase):
    """Exercise the real scheduler/report/resume logic with synthetic processes."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.out = Path(self.temporary.name)
        for name in ["controller", "raw", "bin", "interrupted"]:
            (self.out / name).mkdir()
        (self.out / "controller/workflow.rs").write_text("test workload")
        self.cases = [case(role=role, mode=mode)
                      for mode in ["single", "multi"] for role in ["baseline", "candidate"]]
        self.host = {key: "test" for key in
                     ["system", "release", "machine", "logical_cpus", "hardware", "rustc", "cargo"]}
        self.manifest = {
            "schema": bench.SCHEMA, "cases": self.cases, "sources": {},
            "runner_sha256": bench.sha256(Path(bench.__file__)),
            "harness_sha256": bench.sha256(self.out / "controller/workflow.rs"),
            "toolchain": "test", "environment": self.host, "warmups": 2,
            "repetitions": 2, "supplied_reference": None,
        }
        bench.write_json(self.out / "manifest.json", self.manifest)
        self.invocations = []
        self.change_rng = False
        for config in self.cases:
            binary = self.out / "bin" / ("workflow-" + config["id"])
            binary.write_bytes(b"synthetic executable")
            bench.write_json(self.out / "bin" / (config["id"] + ".json"),
                             {"case": config, "sha256": bench.sha256(binary)})

    def execute(self, out, manifest, config, phase, number):
        name = f"{phase}-{number:03d}-{config['id']}"
        self.invocations.append(name)
        # Round 1 has one sleep interruption; retain all four configurations
        # but replace the whole round. Warmups must not offset round numbering.
        interrupted_round = phase == "measure" and number == 1
        seconds = 1000 if interrupted_round else number + (2 if config["role"] == "baseline" else 1)
        rows = workload(config, seconds)
        if self.change_rng and config["role"] == "candidate":
            next(row for row in rows if row["kind"] == "rng")["value"] += 1
        raw = out / "raw"
        write_records(raw / (name + ".jsonl"), rows)
        (raw / (name + ".stderr")).write_text("")
        bench.write_json(raw / (name + ".cpu.json"), [])
        saved = {
            "case": config, "phase": phase, "round": number, "exit_code": 0,
            "binary_sha256": bench.read_json(out / "bin" / (config["id"] + ".json"))["sha256"],
            "slept": interrupted_round and config == self.cases[0],
            "prior_interruption": False, "peak_rss_bytes": 12345, "competing": False,
            "process_telemetry_unavailable": False,
            "stdout_sha256": bench.sha256(raw / (name + ".jsonl")),
            "stderr_sha256": bench.sha256(raw / (name + ".stderr")),
            "cpu_sha256": bench.sha256(raw / (name + ".cpu.json")),
        }
        bench.write_json(raw / (name + ".meta.json"), saved)
        return saved

    def run_campaign(self, execute=True):
        with patch.object(bench, "environment", return_value=self.host), \
                patch.object(bench.platform, "system", return_value="Linux"), \
                patch.object(bench, "build"), redirect_stdout(io.StringIO()):
            if execute:
                with patch.object(bench, "run_one", side_effect=self.execute):
                    bench.run(self.out, self.manifest)
            else:
                # Real run_one must reuse completed artifacts, never execute.
                with patch.object(bench.subprocess, "Popen", side_effect=AssertionError("reran workload")):
                    bench.run(self.out, self.manifest)

    def test_interrupted_round_retention_pooling_and_resume(self):
        self.run_campaign()
        self.assertEqual(len(self.invocations), 20)  # 2 warmups + 3 rounds, four cases
        quality = bench.read_json(self.out / "quality.json")
        self.assertEqual(quality["selected_rounds"], [2, 3])
        self.assertEqual(quality["retained_rounds"], 3)
        result = bench.read_json(self.out / "results.json")[self.cases[1]["id"]]
        self.assertEqual(result["wallet/seed"]["samples"], [3, 4, 4, 5])
        self.assertEqual(result["wallet/seed"]["process_medians"], [3.5, 4.5])
        self.assertEqual(result["aggregator/verify_compressed"]["median"], 3.5)
        report = (self.out / "report.md").read_text()
        self.assertIn("4.500 → 3.500 s (-22.2%)", report)
        self.assertIn("159.39 MB", report)
        self.assertIn("9.44 KB", report)
        self.assertNotIn("Total, two-proof workflow", report)
        raw_hash = bench.tree_digest(self.out / "raw")
        self.run_campaign(execute=False)
        self.assertEqual(raw_hash, bench.tree_digest(self.out / "raw"))
        self.assertEqual(len(self.invocations), 20)

    def test_proof_rng_mismatch_stops_campaign_without_publishing_results(self):
        self.change_rng = True
        with self.assertRaisesRegex(ValueError, "Proof, shape, or RNG mismatch"):
            self.run_campaign()
        self.assertFalse((self.out / "report.md").exists())
        self.assertTrue(list((self.out / "raw").glob("*.jsonl")))

    def test_report_rejects_changed_raw_artifacts_and_selected_rounds(self):
        self.run_campaign()
        quality = bench.read_json(self.out / "quality.json")
        quality["selected_rounds"] = [1, 3]
        bench.write_json(self.out / "quality.json", quality)
        with self.assertRaisesRegex(ValueError, "interrupted round"):
            bench.summarize(self.out)
        quality["selected_rounds"] = [2, 3]
        bench.write_json(self.out / "quality.json", quality)
        path = next((self.out / "raw").glob("measure-002-*.jsonl"))
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "Changed raw artifact"):
            bench.summarize(self.out)


class SourceTests(unittest.TestCase):
    def test_archives_committed_libraries_and_overlays_identical_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()

            def git(*args):
                result = subprocess.run(
                    ["git", "-c", "user.name=Benchmark test", "-c",
                     "user.email=benchmark@example.invalid", "-c", "commit.gpgsign=false",
                     "-c", "core.hooksPath=" + str(root / "no-hooks"), *args],
                    cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                return result.stdout.strip()

            git("init", "-q")
            (repo / bench.BENCH).parent.mkdir(parents=True)
            (repo / bench.BENCH).write_text("old harness")
            (repo / "crates/ragu_pcd/Cargo.toml").write_text('[package]\nname = "ragu_pcd"\n')
            (repo / "Cargo.lock").write_text("# frozen test lock\n")
            (repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "test"\n')
            library = repo / "library.rs"
            library.write_text("committed baseline")
            git("add", ".")
            git("commit", "-qm", "baseline")
            baseline = git("rev-parse", "HEAD")
            library.write_text("committed candidate")
            git("commit", "-qam", "candidate")
            candidate = git("rev-parse", "HEAD")
            library.write_text("uncommitted edit must not be measured")
            (repo / bench.BENCH).write_text("shared current workload")
            args = Namespace(
                repo=repo, revision="HEAD", base=baseline, toolchain=None,
                output=root / "output", asm="both", modes=["single", "multi"],
                threads=12, reference=None, jobs=2, offline=True,
                warmups=1, repetitions=3, no_wait=False,
            )
            with patch.object(bench, "environment", return_value={}), redirect_stdout(io.StringIO()):
                out, manifest = bench.initialize(args)
            self.assertEqual(len(manifest["cases"]), 8)
            for revision, expected in [(baseline, "committed baseline"),
                                       (candidate, "committed candidate")]:
                source = out / "sources" / revision
                self.assertEqual((source / "library.rs").read_text(), expected)
                self.assertEqual((source / bench.BENCH).read_text(), "shared current workload")
                target = bench.tomllib.loads((source / "crates/ragu_pcd/Cargo.toml").read_text())
                self.assertEqual(target["bench"], [{"name": "workflow", "harness": False}])
                self.assertEqual((source / "Cargo.lock").read_text(), "# frozen test lock\n")
            self.assertEqual(library.read_text(), "uncommitted edit must not be measured")


if __name__ == "__main__":
    unittest.main()
