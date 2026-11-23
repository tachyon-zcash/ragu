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

    def test_commitment_tables_reach_every_process_only_when_requested(self):
        with patch.dict("os.environ", {"RAGU_BENCH_COMMITMENT_TABLES": "1"}):
            for requested in [False, True]:
                for role in ["baseline", "candidate"]:
                    env = bench.process_environment({"commitment_tables": requested},
                                                    case(role=role, mode="multi"))
                    self.assertEqual(env["RAYON_NUM_THREADS"], "12")
                    self.assertEqual(env.get("RAGU_BENCH_COMMITMENT_TABLES"),
                                     "1" if requested else None)
            # Campaigns that predate the option request none.
            self.assertNotIn("RAGU_BENCH_COMMITMENT_TABLES", bench.process_environment({}, case()))

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
        self.invocations = []
        self.change_rng = False
        self.write_campaign_files()

    def write_campaign_files(self):
        bench.write_json(self.out / "manifest.json", self.manifest)
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
        # One table per profile, each mode with both medians and the speedup;
        # a campaign that names no labels uses the defaults.
        for title in bench.PROFILES.values():
            self.assertIn("### " + title, report)
        self.assertIn("Each cell: main → optimized median time (change in time, speedup).", report)
        self.assertIn("| Operation | single | 12 workers |", report)
        self.assertIn("| Seed one leaf | 5.000 → 4.000 s (-20%, 1.25×) "
                      "| 5.000 → 4.000 s (-20%, 1.25×) |", report)
        self.assertEqual(report.count("| Fuse two children | 4.500 → 3.500 s (-22%, 1.29×) |"), 2)
        self.assertEqual(report.count("| Seed one leaf |"), 1)
        self.assertEqual(report.count("| Decompress one wallet proof |"), 1)
        self.assertEqual(report.count("| Finalize + bootstrap (once) |"), 2)
        self.assertIn("159.39 MB", report)
        self.assertIn("9.44 KB", report)
        self.assertNotIn("Total, two-proof workflow", report)
        table = bench.terminal(report).splitlines()
        header = next(i for i, line in enumerate(table) if line.startswith("Operation"))
        self.assertEqual(set(table[header + 1]), {"-", " "})
        self.assertTrue(any(line.startswith("Seed one leaf") and "(-20%, 1.25×)" in line
                            for line in table))
        self.assertFalse(any("|" in line or "Process medians" in line for line in table))
        raw_hash = bench.tree_digest(self.out / "raw")
        self.run_campaign(execute=False)
        self.assertEqual(raw_hash, bench.tree_digest(self.out / "raw"))
        self.assertEqual(len(self.invocations), 20)

    def test_asm_comparison_with_an_older_candidate(self):
        self.cases[:] = [case(c["role"], c["mode"], asm=c["role"] == "baseline")
                         for c in self.cases]
        self.write_campaign_files()
        self.run_campaign()
        report = (self.out / "report.md").read_text()
        self.assertIn("## ASM feature enabled", report)
        self.assertNotIn("## ASM feature disabled", report)
        self.assertIn("The candidate was built without the ASM feature.", report)
        self.assertEqual(report.count("| Fuse two children | 4.500 → 3.500 s"), 2)

    def test_proof_rng_mismatch_stops_campaign_without_publishing_results(self):
        self.change_rng = True
        with self.assertRaisesRegex(ValueError, "Proof, shape, or RNG mismatch"):
            self.run_campaign()
        self.assertFalse((self.out / "report.md").exists())
        self.assertTrue(list((self.out / "raw").glob("*.jsonl")))

    def test_supplied_reference_uses_current_counts_for_matching_proofs(self):
        path = self.out / "supplied-reference.jsonl"
        rows = workload(self.cases[0])
        old_shape = next(row for row in rows
                         if row["kind"] == "shape" and row["profile"] == "aggregator")
        current_shape = old_shape.copy()
        old_shape["polynomials"] += 21
        old_shape["points"] -= 18
        old_shape["scalars"] += 18
        write_records(path, rows)
        _, self.manifest["supplied_reference"] = bench.records(path)
        bench.write_json(self.out / "manifest.json", self.manifest)

        self.run_campaign()
        self.assertEqual(
            bench.read_json(self.out / "reference.json")["shape:aggregator:parent"],
            current_shape,
        )
        self.run_campaign(execute=False)

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

            git("init", "-q", "-b", "trunk")
            (repo / bench.BENCH).parent.mkdir(parents=True)
            (repo / bench.BENCH).write_text("old harness")
            package = repo / "crates/ragu_pcd/Cargo.toml"
            package.write_text('[package]\nname = "ragu_pcd"\n')
            (repo / "Cargo.lock").write_text("# frozen test lock\n")
            (repo / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "test"\n')
            library = repo / "library.rs"
            library.write_text("committed old")
            git("add", ".")
            git("commit", "-qm", "old, before the asm feature")
            old = git("rev-parse", "HEAD")
            package.write_text('[package]\nname = "ragu_pcd"\n\n[features]\nasm = []\n')
            library.write_text("committed baseline")
            git("commit", "-qam", "baseline")
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
                warmups=1, repetitions=3, no_wait=False, baseline_without_asm=True,
                label="tuned", base_label="before", no_base=False,
                commitment_tables=False,
            )
            with patch.object(bench, "environment", return_value={}), redirect_stdout(io.StringIO()):
                _, manifest = bench.initialize(args)
            self.assertEqual(manifest["labels"], {"baseline": "before", "candidate": "tuned"})
            self.assertFalse(manifest["commitment_tables"])
            self.assertEqual(sorted(c["id"] for c in manifest["cases"] if c["role"] == "baseline"),
                             ["baseline-asm-off-multi", "baseline-asm-off-single"])
            self.assertEqual(len(manifest["cases"]), 6)
            args.output, args.baseline_without_asm = root / "output-asm", False
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

            def baselines(output, **changes):
                for key, value in changes.items():
                    setattr(args, key, value)
                args.output = root / output
                with patch.object(bench, "environment", return_value={}), \
                        redirect_stdout(io.StringIO()):
                    _, manifest = bench.initialize(args)
                return manifest, sorted((c["id"], c["revision"]) for c in manifest["cases"]
                                        if c["role"] == "baseline")

            # A baseline that predates the asm feature is built only without it.
            _, cases = baselines("output-old", base=old)
            self.assertEqual(cases, [("baseline-asm-off-multi", old),
                                     ("baseline-asm-off-single", old)])
            # Without --base, the baseline is main as of the candidate.
            git("branch", "main", baseline)
            manifest, cases = baselines("output-main", base=None)
            self.assertEqual({revision for _, revision in cases}, {baseline})
            self.assertEqual(manifest["baseline_ref"], "merge base with main")
            # --no-base, or a candidate on main, measures the candidate alone.
            _, cases = baselines("output-alone", no_base=True)
            self.assertEqual(cases, [])
            _, cases = baselines("output-on-main", no_base=False, revision="main")
            self.assertEqual(cases, [])
            # The candidate can also predate ASM, alone or against a newer baseline.
            for selection in ("on", "both"):
                manifest, _ = baselines("old-alone-" + selection, revision=old, base=None,
                                        no_base=True, asm=selection)
                self.assertEqual([c["id"] for c in manifest["cases"]],
                                 ["candidate-asm-off-single", "candidate-asm-off-multi"])
            manifest, cases = baselines("old-vs-new", base=baseline, no_base=False, asm="on")
            self.assertEqual({c["asm"] for c in manifest["cases"] if c["role"] == "candidate"},
                             {False})
            self.assertEqual(cases, [("baseline-asm-on-multi", baseline),
                                     ("baseline-asm-on-single", baseline)])


if __name__ == "__main__":
    unittest.main()
