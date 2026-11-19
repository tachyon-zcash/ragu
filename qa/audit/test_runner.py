"""Exercise review scheduling and failure handling without model calls."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import runner
from test_findings import finding, group


class RunnerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        base = Path(directory.name).resolve()
        self.root, self.work, self.out, self.private = [base / name for name in ("root", "work", "out", "private")]
        self.root.mkdir()
        self.run = {"head": "a" * 40, "base": "b" * 40, "configuration": "b" * 40,
                    "model": "claude-opus-5-5", "effort": "xhigh"}
        for skill in runner.SKILLS:
            path = self.root / ".claude/skills" / skill
            path.mkdir(parents=True)
            (path / "SKILL.md").write_text("Trusted skill\n")

    def prepare(self, *args):
        for skill in runner.ROLES:
            (self.work / skill).mkdir()
        return self.run["base"]

    def invoke(self, execute, changed_skill=None, reuse=None):
        def unchanged(root, source, revision, **kwargs):
            self.assertEqual(revision, self.run["head"])
            return source.name != changed_skill

        def execute_review(command, **kwargs):
            result = execute(command, **kwargs)
            runner.write_json(self.out / f"{kwargs['skill']}.json", result)
            return result

        def version(command, **kwargs):
            self.assertNotIn("GH_TOKEN", kwargs["env"])
            self.assertNotIn("GH_READ_TOKEN", kwargs["env"])
            self.assertNotIn("ANTHROPIC_API_KEY", kwargs["env"])
            return runner.CLAUDE_VERSION + " (Claude Code)\n"

        with patch.dict(os.environ, {"PATH": os.environ["PATH"], "HOME": str(self.root), "CARGO_HOME": str(self.work / "cargo"),
                                     "GH_TOKEN": "dummy-parent-token", "GH_READ_TOKEN": "dummy-parent-read-token"}, clear=True), \
             patch.object(runner.shutil, "which", return_value=sys.executable), \
             patch.object(runner.subprocess, "check_output", side_effect=version), \
             patch.object(runner, "prepare", side_effect=self.prepare), patch.object(runner, "unchanged", side_effect=unchanged), \
             patch.object(runner, "execute_review", side_effect=execute_review):
            runner.review(self.root, self.run, self.work, self.out, self.private, reuse)

    def result(self, command, complete=True, returncode=0):
        return {
            "type": "result", "subtype": "success", "is_error": False, "permission_denials": [],
            "total_cost_usd": 0.01,
            "structured_output": {"complete": complete, "report": "Recorded review and validation evidence.", "findings": [], "assessments": []},
        }

    def test_specialists_overlap_after_core_and_receipt_order_is_deterministic(self):
        specialists = threading.Barrier(3)
        release = threading.Event()
        snapshots, states = [], {}
        write_json = runner.write_json

        def record(path, value):
            write_json(path, value)
            if path.name == "receipt.json":
                names = [phase["skill"] for phase in value["phases"]]
                snapshots.append(names)
                if names == ["code-review", "alex-review"]:
                    release.set()

        def execute(command, **kwargs):
            env = kwargs["env"]
            skill = Path(env["CLAUDE_CONFIG_DIR"]).name
            states[skill] = env["CLAUDE_CONFIG_DIR"]
            # Linux cannot hide a read-denied file that does not exist when a
            # Bash sandbox starts, including reports a peer will write later.
            self.assertTrue(all((self.out / f"{name}.{suffix}").is_file()
                                for name in runner.SKILLS for suffix in runner.REPORT_SUFFIXES))
            self.assertEqual(env["TMPDIR"], env["CLAUDE_CODE_TMPDIR"])
            self.assertEqual(Path(env["TMPDIR"]).name, skill)
            self.assertLess(len(str(Path(env["TMPDIR"]) / f"claude-{os.getuid()}")), 60)
            self.assertTrue(Path(env["TMPDIR"]).is_dir())
            self.assertEqual(command[command.index("--model") + 1], self.run["model"])
            self.assertEqual(command[command.index("--effort") + 1], "xhigh")
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("GH_READ_TOKEN", env)
            self.assertNotIn("ANTHROPIC_API_KEY", env)
            core_paths = [self.out / name for name in ("core-findings.json", "code-review.md")]
            if skill == "code-review":
                target = Path(env["CARGO_TARGET_DIR"])
                target.mkdir()
                (target / "build-output").touch()
                for path in core_paths:
                    self.assertNotIn(str(path), command[-1])
            else:
                self.assertFalse((Path(env["TMPDIR"]).parent / "code-review" / "target").exists())
                for path in core_paths:
                    self.assertIn(str(path), command[-1])
                self.assertEqual(runner.read_json(self.out / "core-findings.json"), {"findings": []})
                self.assertIn("Recorded review and validation evidence", (self.out / "code-review.md").read_text())
                specialists.wait(timeout=5)
                if skill != "alex-review":
                    self.assertTrue(release.wait(timeout=5), "early specialist result was not recorded")
            return self.result(command)

        with patch.object(runner, "write_json", side_effect=record):
            self.invoke(execute)
        receipt = runner.verify(self.run, self.out)
        self.assertIn(["code-review", "alex-review"], snapshots)
        self.assertEqual([phase["skill"] for phase in receipt["phases"]], list(runner.SKILLS))
        self.assertEqual(len(set(states.values())), 4)
        self.assertTrue(all(phase["duration_seconds"] >= 0 for phase in receipt["phases"]))

    def reconcile_result(self, command, **kwargs):
        result = self.result(command)
        skill = kwargs["skill"]
        if skill == runner.RECONCILER:
            self.assertEqual(kwargs["timeout"], 180)
            self.assertEqual(command[command.index("--max-turns") + 1], "20")
            self.assertEqual(command[command.index("--tools") + 1], "Read")
            self.assertEqual(len(runner.verify(self.run, self.out)["phases"]), 4)
            result["structured_output"] = {"complete": True, "report": "Checked the pinned source.",
                                            "groups": [group(*[f"{name}:1" for name in runner.SKILLS])]}
        else:
            result["structured_output"]["findings"] = [finding()]
        return result

    def test_reconciliation_waits_for_four_reviews_and_preserves_receipt(self):
        calls = []

        def execute(command, **kwargs):
            calls.append(kwargs["skill"])
            return self.reconcile_result(command, **kwargs)

        self.invoke(execute)
        self.assertEqual(calls[-1], runner.RECONCILER)
        bundle, groups = runner.verify_reconciliation(self.run, self.out)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(bundle["findings"]), 4)
        self.assertEqual([phase["skill"] for phase in runner.verify(self.run, self.out)["phases"]], list(runner.SKILLS))

    def test_reconciliation_timeout_or_missing_findings_preserves_four_review_gate(self):
        for failure in ("timeout", "omitted", "cancelled"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                self.out = Path(temporary) / "reports"
                self.work = Path(temporary) / "work"
                def execute(command, **kwargs):
                    if kwargs["skill"] == runner.RECONCILER:
                        if failure == "timeout":
                            raise subprocess.TimeoutExpired("UNTRUSTED_COMMAND_CANARY", 180)
                        if failure == "cancelled":
                            kwargs["cancelled"].set()
                            raise ValueError("cancelled")
                        result = self.reconcile_result(command, **kwargs)
                        result["structured_output"]["groups"] = []
                        return result
                    return self.reconcile_result(command, **kwargs)
                output = io.StringIO()
                with redirect_stdout(output):
                    self.invoke(execute)
                self.assertNotIn("UNTRUSTED_COMMAND_CANARY", output.getvalue())
                self.assertEqual(len(runner.verify(self.run, self.out)["phases"]), 4)
                with self.assertRaises(ValueError):
                    runner.verify_reconciliation(self.run, self.out)
                self.assertEqual(len(runner.candidates(self.run, self.out)["findings"]), 4)
                summary = (self.out / "combined.md").read_text()
                self.assertEqual(summary.count("**Incorrect output**"), 1)
                self.assertIn("Code review, Sean, Tal, Alex", summary)

    def test_modified_reconciliation_result_or_bundle_is_rejected(self):
        self.invoke(self.reconcile_result)
        original = (self.out / "reconcile.json").read_text()
        result = runner.read_json(self.out / "reconcile.json")
        result["structured_output"]["groups"][0]["title"] = "Tampered report"
        runner.write_json(self.out / "reconcile.json", result)
        with self.assertRaises(ValueError):
            runner.verify_reconciliation(self.run, self.out)
        (self.out / "reconcile.json").write_text(original)
        bundle = runner.read_json(self.out / "findings.json")
        bundle["findings"] = []
        runner.write_json(self.out / "findings.json", bundle)
        with self.assertRaises(ValueError):
            runner.verify_reconciliation(self.run, self.out)
        runner.verify(self.run, self.out)

    def test_empty_reviews_skip_extra_model_call(self):
        self.invoke(lambda command, **kwargs: self.result(command))
        bundle, groups = runner.verify_reconciliation(self.run, self.out)
        self.assertEqual((bundle["findings"], groups), ([], []))

    def test_reconciliation_has_readonly_source_and_no_peer_reports(self):
        scratch = self.work / "scratch"
        source = self.work / runner.RECONCILER
        policy = runner.settings(self.root, source, self.work, self.out, self.private, self.work / "trusted-plugin", scratch)
        fs = policy["sandbox"]["filesystem"]
        self.assertIn(str(source), fs["denyWrite"])
        self.assertNotIn(str(source), fs["allowWrite"])
        self.assertNotIn(str(self.out / "findings.json"), fs["denyRead"])
        for name in runner.SKILLS:
            self.assertIn(str(self.out / f"{name}.md"), fs["denyRead"])
            self.assertIn(str(self.work / "claude" / name), fs["denyRead"])
        self.assertIn(str(self.out / "receipt.json"), fs["denyRead"])
        self.assertIn(str(self.private), fs["denyRead"])

    def test_incomplete_core_still_runs_specialists_independently(self):
        calls, prompts = [], {}

        def execute(command, **kwargs):
            skill = Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]).name
            calls.append(skill)
            prompts[skill] = command[-1]
            return self.result(command, complete=skill != "code-review")

        with self.assertRaisesRegex(ValueError, "review incomplete: code-review"):
            self.invoke(execute)
        self.assertEqual((calls[0], sorted(calls)), ("code-review", sorted(runner.SKILLS)))
        for skill in runner.SKILLS[1:]:
            self.assertIn("core review is unavailable", prompts[skill])
            self.assertNotIn("core-findings.json", prompts[skill])
        phases = runner.read_json(self.out / "receipt.json")["phases"]
        self.assertEqual([phase["skill"] for phase in phases], list(runner.SKILLS[1:]))
        with self.assertRaises(ValueError):
            runner.verify(self.run, self.out)
        recovered = runner.verify(self.run, self.out, partial=True)
        self.assertEqual(([phase["skill"] for phase in recovered["phases"]], recovered["unavailable"]), (list(runner.SKILLS[1:]), []))
        self.assertEqual((self.out / "reconciliation-receipt.json").read_text(), "")  # No reconciliation without the core.

    def test_transient_failure_is_retried_once_but_incomplete_coverage_is_not(self):
        attempts = {}

        def execute(command, **kwargs):
            skill = Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]).name
            attempts[skill] = attempts.get(skill, 0) + 1
            if skill == "sean-review" and attempts[skill] == 1:
                raise runner.TransientFailure("Claude Code exited unsuccessfully")
            if skill == "tal-review":
                raise runner.TransientFailure("Claude Code returned no final result")
            return self.result(command, complete=skill != "alex-review")

        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(ValueError, "review incomplete: tal-review, alex-review"):
            self.invoke(execute)
        self.assertEqual(attempts, {"code-review": 1, "sean-review": 2, "tal-review": 2, "alex-review": 1})
        self.assertIn("Retrying sean-review once", output.getvalue())
        phases = runner.read_json(self.out / "receipt.json")["phases"]
        self.assertEqual([phase["skill"] for phase in phases], ["code-review", "sean-review"])

    def test_sessions_fit_the_job_time_and_short_ones_are_not_started(self):
        schedule = runner.Schedule(runner.REVIEW_TIMEOUT + runner.RECONCILE_TIMEOUT + 600)
        self.assertEqual(schedule.allowance(runner.RECONCILE_TIMEOUT), runner.REVIEW_TIMEOUT)
        self.assertLess(schedule.allowance(runner.REVIEW_TIMEOUT + runner.RECONCILE_TIMEOUT), runner.MIN_REVIEW)
        self.assertEqual(runner.Schedule(0).allowance(0), 0)
        timeouts = {}

        def execute(command, **kwargs):
            timeouts[Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]).name] = kwargs["timeout"]
            return self.result(command)

        budget = runner.REVIEW_TIMEOUT + runner.RECONCILE_TIMEOUT + runner.MIN_REVIEW - 60
        with patch.object(runner, "CONTROLLER_BUDGET", budget), self.assertRaisesRegex(ValueError, "review incomplete: code-review"):
            self.invoke(execute)
        self.assertEqual(sorted(timeouts), sorted(runner.SKILLS[1:]))  # The core had no room; the specialists did.
        self.assertTrue(all(runner.MIN_REVIEW <= value <= runner.REVIEW_TIMEOUT for value in timeouts.values()))
        self.assertEqual(runner.read_json(self.out / "code-review.status.json")["state"], "schedule")

    def test_failed_specialist_preserves_siblings_and_cannot_pass_gate(self):
        specialists = threading.Barrier(3)

        def execute(command, **kwargs):
            skill = Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]).name
            if skill != "code-review":
                specialists.wait(timeout=5)
            return self.result(command, complete=skill != "tal-review")

        with self.assertRaisesRegex(ValueError, "review incomplete: tal-review"):
            self.invoke(execute)
        phases = runner.read_json(self.out / "receipt.json")["phases"]
        self.assertEqual([phase["skill"] for phase in phases], ["code-review", "sean-review", "alex-review"])
        self.assertTrue(all((self.out / f"{skill}.json").is_file() for skill in runner.SKILLS))
        with self.assertRaises(ValueError):
            runner.verify(self.run, self.out)

    def test_timeout_preserves_siblings_without_logging_command_text(self):
        def execute(command, **kwargs):
            if Path(kwargs["env"]["CLAUDE_CONFIG_DIR"]).name == "sean-review":
                raise subprocess.TimeoutExpired("UNTRUSTED_COMMAND_CANARY", 3300)
            return self.result(command)

        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(ValueError, "review incomplete: sean-review"):
            self.invoke(execute)
        self.assertNotIn("UNTRUSTED_COMMAND_CANARY", output.getvalue())
        phases = runner.read_json(self.out / "receipt.json")["phases"]
        self.assertEqual([phase["skill"] for phase in phases], ["code-review", "tal-review", "alex-review"])
        with self.assertRaises(ValueError):
            runner.verify(self.run, self.out)

    def test_modified_specialist_source_cannot_pass_gate(self):
        with self.assertRaisesRegex(ValueError, "review incomplete: sean-review"):
            self.invoke(lambda command, **kwargs: self.result(command), changed_skill="sean-review")
        phases = runner.read_json(self.out / "receipt.json")["phases"]
        self.assertEqual([phase["skill"] for phase in phases], ["code-review", "tal-review", "alex-review"])
        with self.assertRaises(ValueError):
            runner.verify(self.run, self.out)

    def test_deleting_command_stops_all_three_specialists(self):
        self.run["comment_id"] = 12
        started = threading.Event()
        barrier = threading.Barrier(3, action=started.set)
        stopped = []

        def execute(command, **kwargs):
            skill = kwargs["skill"]
            if skill == "code-review":
                return self.result(command)
            barrier.wait(timeout=3)
            self.assertTrue(kwargs["cancelled"].wait(timeout=3))
            stopped.append(skill)
            raise ValueError("review cancelled")

        with patch.object(runner, "COMMENT_POLL_SECONDS", 0.01), \
             patch.object(runner, "comment_exists", side_effect=lambda run: not started.is_set()), \
             self.assertRaisesRegex(ValueError, "review incomplete"):
            self.invoke(execute)
        self.assertEqual(set(stopped), set(runner.SKILLS[1:]))
        self.assertEqual([phase["skill"] for phase in runner.verify(self.run, self.out, partial=True)["phases"]], ["code-review"])

    def test_peer_state_reports_and_worktrees_are_protected(self):
        for skill in runner.SKILLS:
            source = self.work / skill
            scratch = self.work / "scratch"
            settings = runner.settings(self.root, source, self.work, self.out, self.private, self.work / "trusted-plugin", scratch)
            filesystem = settings["sandbox"]["filesystem"]
            # A session cannot write its own checkout either; builds go to its scratch.
            self.assertNotIn(str(source), filesystem["allowWrite"])
            self.assertIn(str(source), filesystem["denyWrite"])
            self.assertIn(f"Edit(/{source}/**)", settings["permissions"]["deny"])
            self.assertIn(str(scratch / skill), filesystem["allowWrite"])
            target = Path(runner.environment(self.run, self.work, skill, scratch)["CARGO_TARGET_DIR"])
            self.assertTrue(target.is_relative_to(scratch / skill))
            self.assertNotIn(str(self.work / "claude" / skill), filesystem["denyRead"])
            self.assertNotIn(str(self.out / "code-review.md"), filesystem["denyRead"])
            for peer in runner.SKILLS:
                if peer != skill:
                    self.assertIn(str(self.work / peer), filesystem["denyWrite"])
                    self.assertIn(str(self.work / "claude" / peer), filesystem["denyRead"])
                    self.assertIn(str(scratch / peer), filesystem["denyRead"])
                    self.assertIn(str(scratch / peer), filesystem["denyWrite"])
                    if peer != "code-review":
                        for suffix in runner.REPORT_SUFFIXES:
                            self.assertIn(str(self.out / f"{peer}.{suffix}"), filesystem["denyRead"])
            for path in runner.shared_scratch():
                self.assertIn(str(path), filesystem["denyRead"])
                self.assertIn(str(path), filesystem["denyWrite"])

    def test_cargo_build_parallelism_accounts_for_concurrent_reviewers(self):
        for cpus, core, specialist in ((None, "1", "1"), (1, "1", "1"), (2, "1", "1"),
                                       (4, "3", "1"), (8, "7", "2")):
            with patch.object(os, "cpu_count", return_value=cpus):
                values = [runner.environment(self.run, self.work, skill, self.work / "scratch") for skill in runner.SKILLS]
            for variable in ("CARGO_BUILD_JOBS", "RAYON_NUM_THREADS", "RUST_TEST_THREADS"):
                self.assertEqual([value[variable] for value in values], [core, specialist, specialist, specialist])
            self.assertEqual({value["CARGO_PROFILE_DEV_DEBUG"] for value in values}, {"0"})

    def test_linux_mounts_private_temp_before_starting_claude(self):
        command = ["claude", "--print", "--", "trusted review prompt"]
        with patch.object(sys, "platform", "linux"), patch.object(runner.shutil, "which", return_value="/usr/bin/bwrap"):
            wrapped = runner.isolate_shared_temp(command, self.work)
        self.assertEqual(wrapped[:8], ["/usr/bin/bwrap", "--die-with-parent", "--unshare-pid", "--dev-bind", "/", "/", "--proc", "/proc"])
        for path in runner.shared_scratch():
            index = wrapped.index(str(path))
            self.assertEqual(wrapped[index - 2:index], ["--bind", str(self.work / "shared-temp")])
        self.assertEqual(wrapped[-len(command) - 1:], ["--", *command])

    def test_linux_without_bubblewrap_fails_closed(self):
        with patch.object(sys, "platform", "linux"), patch.object(runner.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "bubblewrap is required"):
                runner.isolate_shared_temp(["claude"], self.work)


class ProcessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.out, self.private = self.root / "out", self.root / "private"
        self.out.mkdir()
        self.private.mkdir()
        (self.private / "key").write_text("dummy-local-key")
        self.run = {"head": "a" * 40}

    def execute(self, script, *, cancelled=None, timeout=5, wrap=False):
        command = [sys.executable, "-c", script]
        if wrap:
            scratch = self.root / "scratch"
            (scratch / "shared-temp").mkdir(parents=True)
            for path in runner.shared_scratch():
                path.mkdir(parents=True, exist_ok=True)
            command = runner.isolate_shared_temp(command, scratch)
        with patch.object(runner, "REVIEW_TIMEOUT", timeout), patch.object(runner, "HEARTBEAT_SECONDS", 0.05):
            return runner.execute_review(command, cwd=self.root, env={"PATH": os.environ["PATH"]},
                                         run=self.run, skill="code-review", out=self.out, private=self.private,
                                         cancelled=cancelled or threading.Event())

    def test_timeout_keeps_safe_progress_and_stderr_and_stops_children(self):
        marker = self.root / "child-survived"
        child = f"import time; from pathlib import Path; time.sleep(0.8); Path({str(marker)!r}).touch()"
        event = {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "UNTRUSTED_COMMAND_CANARY"}}]}}
        script = (f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}]); "
                  f"print({json.dumps(event)!r}, flush=True); "
                  "print('diagnostic dummy-local-key', file=sys.stderr, flush=True); time.sleep(10)")
        log = io.StringIO()
        with redirect_stdout(log), self.assertRaisesRegex(ValueError, "review timeout"):
            self.execute(script, timeout=0.25)
        time.sleep(0.9)
        self.assertFalse(marker.exists(), "a child survived the review deadline")
        status = runner.read_json(self.out / "code-review.status.json")
        self.assertEqual(status["state"], "timeout")
        self.assertEqual(status["tool_calls"], 1)
        self.assertEqual(status["last_tool"], "Bash")
        self.assertIn("diagnostic [REDACTED]", (self.out / "code-review.stderr").read_text())
        self.assertIn("tool calls", log.getvalue())
        self.assertRegex(log.getvalue(), r"\d+ MiB disk available")
        artifacts = "".join(path.read_text() for path in self.out.iterdir()) + log.getvalue()
        self.assertNotIn("dummy-local-key", artifacts)
        self.assertNotIn("UNTRUSTED_COMMAND_CANARY", artifacts)

    def test_cancellation_stops_a_running_review(self):
        cancelled = threading.Event()
        timer = threading.Timer(0.1, cancelled.set)
        timer.start()
        try:
            with self.assertRaisesRegex(ValueError, "review cancelled"):
                self.execute("import time; time.sleep(10)", cancelled=cancelled)
        finally:
            timer.join(timeout=1)
        self.assertEqual(runner.read_json(self.out / "code-review.status.json")["state"], "cancelled")

    def test_comment_deletion_stops_process_before_model_deadline(self):
        self.run["comment_id"] = 12
        cancelled = threading.Event()
        with patch.object(runner, "comment_exists", side_effect=[True, False]), \
             patch.object(runner, "COMMENT_POLL_SECONDS", 0.05), \
             runner.watch_comment(self.run, cancelled), self.assertRaisesRegex(ValueError, "review cancelled"):
            self.execute("import time; time.sleep(10)", cancelled=cancelled)
        self.assertEqual(runner.read_json(self.out / "code-review.status.json")["state"], "cancelled")

    def test_deleted_command_never_launches_a_model_process(self):
        self.run["comment_id"] = 12
        cancelled = threading.Event()
        with patch.object(runner, "comment_exists", return_value=False), \
             runner.watch_comment(self.run, cancelled), \
             patch.object(runner.subprocess, "Popen") as launch, self.assertRaisesRegex(ValueError, "review cancelled"):
            self.execute("raise RuntimeError('must not run')", cancelled=cancelled)
        launch.assert_not_called()

    def test_temporary_api_error_does_not_cancel_a_review(self):
        self.run["comment_id"] = 12
        cancelled = threading.Event()
        error = HTTPError("https://api.github.com", 503, "Unavailable", {}, None)
        observations = iter((True, error, False))
        checked_after_error = threading.Event()

        def exists(run):
            value = next(observations)
            if isinstance(value, Exception):
                raise value
            self.assertFalse(cancelled.is_set(), "a transient API error cancelled the review")
            if value is False:
                checked_after_error.set()
            return value

        with patch.object(runner, "comment_exists", side_effect=exists), \
             patch.object(runner, "COMMENT_POLL_SECONDS", 0.03), runner.watch_comment(self.run, cancelled):
            self.assertTrue(checked_after_error.wait(timeout=2))
            self.assertTrue(cancelled.wait(timeout=2))

    def test_only_comment_not_found_is_treated_as_deletion(self):
        self.run["comment_id"] = 12
        for code in (404, 403, 500):
            error = HTTPError("https://api.github.com", code, "error", {}, None)
            with patch.dict(os.environ, {"GH_TOKEN": "dummy-read-only-token"}), \
                 patch.object(runner, "urlopen", side_effect=error):
                if code == 404:
                    self.assertFalse(runner.comment_exists(self.run))
                else:
                    with self.assertRaises(HTTPError):
                        runner.comment_exists(self.run)

    def test_stream_retains_only_final_result_and_fixed_tool_names(self):
        result = {"type": "result", "subtype": "success", "is_error": False,
                  "structured_output": {"complete": True, "report": "finding dummy-local-key"}}
        events = [{"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "SECRET_CANARY", "input": {"secret": "SECRET_CANARY"}}]}}, result]
        script = "import sys; " + "; ".join(f"print({json.dumps(event)!r})" for event in events)
        returned = self.execute(script)
        self.assertTrue(runner.completed(returned))
        self.assertEqual(runner.read_json(self.out / "code-review.json"), returned)
        self.assertEqual(runner.read_json(self.out / "code-review.status.json")["last_tool"], "other")
        self.assertNotIn("SECRET_CANARY", "".join(path.read_text() for path in self.out.iterdir()))
        self.assertIn("[REDACTED]", returned["structured_output"]["report"])

    def test_invalid_missing_duplicate_and_oversized_results_fail_closed(self):
        for script in ("print('[]')", "print('{}')", "print('not JSON')",
                       "print('{\"type\":\"result\"}\\n{\"type\":\"result\"}')",
                       "print('x' * 300)", "import sys; sys.exit(3)"):
            with self.subTest(script=script), patch.object(runner, "MAX_STREAM_LINE", 128):
                with self.assertRaises(ValueError):
                    self.execute(script)
                self.assertIn(runner.read_json(self.out / "code-review.status.json")["state"], ("exit", "protocol"))

    @unittest.skipUnless(sys.platform == "linux", "Linux PID namespace containment")
    def test_linux_deadline_also_stops_detached_grandchildren(self):
        marker = self.root / "detached-child-survived"
        child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
        script = (f"import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session=True); "
                  "print('{}', flush=True); time.sleep(10)")
        with self.assertRaisesRegex(ValueError, "review timeout"):
            self.execute(script, timeout=0.3, wrap=True)
        time.sleep(1.1)
        self.assertFalse(marker.exists(), "a detached child escaped Linux review cleanup")

    def test_git_commands_have_a_deadline_and_cannot_prompt(self):
        with patch.object(subprocess, "check_output", return_value="revision\n") as execute:
            self.assertEqual(runner.git(self.root, "rev-parse", "HEAD"), "revision")
        options = execute.call_args.kwargs
        self.assertEqual(options["timeout"], runner.GIT_TIMEOUT)
        self.assertEqual(options["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(options["env"]["GIT_ASKPASS"], "/bin/false")


class SourceTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.root = self.base / "root"
        for name, text in (("a.rs", "fn a() {}\n"), ("bin/run.sh", "#!/bin/sh\n"), ("crates/x/lib.rs", "pub fn x() {}\n")):
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text)
        (self.root / "bin/run.sh").chmod(0o755)
        (self.root / "link").symlink_to("a.rs")
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-qm", "pinned")

    def git(self, *args):
        identity = {f"GIT_{role}_{field}": value for role in ("AUTHOR", "COMMITTER")
                    for field, value in (("NAME", "audit"), ("EMAIL", "audit@example.com"))}
        env = {**os.environ, **identity, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True,
                              text=True, env=env).stdout.strip()

    def worktree(self, name):
        path = self.base / "work" / name
        self.git("worktree", "add", "-q", "--detach", str(path), "HEAD")
        return path

    def prepare(self, name):
        """Prepare the review worktrees of the current commit without fetching it."""
        head = self.git("rev-parse", "HEAD")
        real = runner.git
        offline = lambda root, *args, **kwargs: "" if args[0] == "fetch" else real(root, *args, **kwargs)
        with patch.object(runner, "git", side_effect=offline):
            runner.prepare(self.root, {"configuration": head, "base": head, "head": head}, self.base / name)
        return self.base / name

    def test_tracked_files_must_match_the_pinned_head(self):
        def retype(path):
            (path / "link").unlink()
            (path / "link").write_text("a.rs")

        def relink(path):
            (path / "elsewhere").mkdir()
            (path / "crates/x").rename(path / "elsewhere/x")
            (path / "crates/x").symlink_to(path / "elsewhere/x")

        def fifo(path):
            (path / "a.rs").unlink()
            os.mkfifo(path / "a.rs")

        def alias(path):
            (path / "copy.rs").write_text("fn a() {}\n")
            (path / "a.rs").unlink()
            (path / "a.rs").symlink_to("copy.rs")

        def directory(path):
            (path / "a.rs").unlink()
            (path / "a.rs").mkdir()

        head = self.git("rev-parse", "HEAD")
        source = self.worktree("intact")
        self.assertTrue(runner.unchanged(self.root, source, head))
        (source / "target").mkdir()
        (source / "target/untracked").write_text("build output\n")
        self.assertTrue(runner.unchanged(self.root, source, head))
        for change, apply in (("content", lambda path: (path / "a.rs").write_text("fn b() {}\n")),
                              ("mode", lambda path: (path / "bin/run.sh").chmod(0o644)),
                              ("deletion", lambda path: (path / "crates/x/lib.rs").unlink()),
                              ("type", retype), ("leading symlink", relink), ("fifo", fifo),
                              ("symlink to a copy", alias), ("directory", directory),
                              # Reading a terabyte-long sparse file would exhaust the controller.
                              ("sparse", lambda path: os.truncate(path / "a.rs", 1 << 40))):
            with self.subTest(change=change):
                source = self.worktree(change.replace(" ", "-"))
                apply(source)
                self.assertFalse(runner.unchanged(self.root, source, head))
        # A checkout reached through a symlink is not the one that was prepared.
        (self.base / "alias").symlink_to(self.base / "work/intact")
        self.assertFalse(runner.unchanged(self.root, self.base / "alias", head))

    def test_head_attributes_cannot_convert_the_checkout(self):
        (self.root / "id.rs").write_text("// $Id$\n")
        (self.root / "crates/x/.gitattributes").write_text("*.rs working-tree-encoding=UTF-16LE\n")
        (self.root / ".gitattributes").write_text("*.rs text eol=crlf ident\n*.sh filter=lfs\n")
        self.git("add", "id.rs", ".gitattributes", "crates/x/.gitattributes")
        self.git("commit", "-qm", "attributes")
        head = self.git("rev-parse", "HEAD")
        # A plain checkout converts files, which then differ from their blobs.
        self.assertFalse(runner.unchanged(self.root, self.worktree("plain"), head))
        work = self.prepare("prepared")
        for skill in runner.ROLES:
            with self.subTest(skill=skill):
                self.assertTrue(runner.unchanged(self.root, work / skill, head))

    def test_head_symlinks_must_stay_inside_the_checkout(self):
        # `up` is the checkout itself, so a target through it leaves without naming a parent.
        (self.root / "crates/x/up").symlink_to("../..")
        self.git("add", "-A")
        self.git("commit", "-qm", "inside")
        self.prepare("inside")
        for case, target in (("absolute", "/etc/hosts"), ("relative", "../cargo/registry/lib.rs"),
                             ("chained", "crates/x/up/../cargo/registry/lib.rs")):
            with self.subTest(target=target):
                (self.root / "escape").symlink_to(target)
                self.git("add", "-A")
                self.git("commit", "-qm", case)
                with self.assertRaisesRegex(ValueError, "symlink leaving"):
                    self.prepare(case)
                (self.root / "escape").unlink()

    def test_repository_planted_at_a_gitlink_never_runs(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},crates/vendor/sub")
        self.git("commit", "-qm", "gitlink")
        head = self.git("rev-parse", "HEAD")
        source = self.worktree("code-review")
        # What a build script could plant if the sandbox let it write its worktree.
        planted, marker = source / "target/.g", self.base / "escaped"
        for name in ("objects", "refs"):
            (planted / name).mkdir(parents=True)
        (planted / "HEAD").write_text("ref: refs/heads/main\n")
        (planted / "hook.sh").write_text(f"touch '{marker}'\n")
        (planted / "config").write_text(f"[core]\n\tbare = false\n\tfsmonitor = \"sh {planted / 'hook.sh'}\"\n")
        (source / "crates/vendor/sub/.git").write_text(f"gitdir: {planted}\n")

        self.assertFalse(runner.unchanged(self.root, source, head))
        self.assertFalse(marker.exists())
        with self.assertRaisesRegex(ValueError, "gitlink"):
            self.prepare("pending")
        self.assertFalse((self.base / "pending").exists())
        self.assertFalse(marker.exists())
        # Diffing the worktree, as the controller once did, runs the planted hook.
        runner.git(source, "diff", "HEAD", "--")
        self.assertTrue(marker.exists())


if __name__ == "__main__":
    unittest.main()
