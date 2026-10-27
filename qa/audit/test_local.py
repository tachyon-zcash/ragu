"""Exercise local sign-in, version binding, and publication without model calls."""

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

import github
import local
import runner
import test_audit
from test_audit import APP, BASE, HEAD, candidate, native

LOGIN = {"type": "User", "login": "maintainer"}


def local_run(**changes):
    return {"repository": github.REPOSITORY, "pr": 9, "head": HEAD, "base": BASE, "configuration": BASE,
            "model": "claude-sonnet-5-5", "effort": "high", "reconcile_model": "claude-sonnet-5-5",
            "reconcile_effort": "high", "local": True, "claude_version": "9.9.9", **changes}


class MaintainerAPI(test_audit.API):
    """The fake GitHub API, with new items created by a maintainer instead of the App."""

    def call(self, path, data=None, method=None):
        if data is None and path == "/user":
            return dict(LOGIN)
        counts = len(self.reviews), len(self.review_comments), len(self.comments)
        result = super().call(path, data, method)
        for values, count in zip((self.reviews, self.review_comments, self.comments), counts):
            for item in values[count:]:
                item["user"] = dict(LOGIN)
        if method == "POST" and isinstance(result, dict) and "user" in result:
            result["user"] = dict(LOGIN)
        return result


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_audit.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.out = self.fixture.out
        self.api = MaintainerAPI()
        self.api.files = [{"filename": "src/lib.rs", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"}]

    def reports(self, run, *items):
        result = native()
        result["structured_output"]["findings"] = list(items)
        receipt = self.fixture.reports(run, {name: copy.deepcopy(result) for name in runner.SKILLS})
        receipt["claude_version"] = run["claude_version"]
        runner.write_json(self.out / "receipt.json", receipt)

    def test_local_cli_uses_the_maintainer_login_without_keys_or_tokens(self):
        secrets = {"USER": "maintainer", "LOGNAME": "maintainer", "ANTHROPIC_API_KEY": "dummy-key", "GH_TOKEN": "dummy-token"}
        with patch.dict(os.environ, secrets):
            values = runner.environment(local_run(), self.out, "code-review", self.out / "scratch")
            workflow = runner.environment({"model": "claude-opus-5-5", "effort": "xhigh"}, self.out, "code-review", self.out / "scratch")
        for key in ("ANTHROPIC_API_KEY", "GH_TOKEN", "CLAUDE_CONFIG_DIR"):
            self.assertNotIn(key, values)
        self.assertEqual((values["USER"], values["LOGNAME"]), ("maintainer", "maintainer"))
        self.assertEqual(values["CLAUDE_CODE_DISABLE_AUTO_MEMORY"], "1")
        self.assertEqual(values["ENABLE_CLAUDEAI_MCP_SERVERS"], "false")
        self.assertNotIn("USER", workflow)
        self.assertEqual(workflow["CLAUDE_CONFIG_DIR"], str(self.out / "claude/code-review"))

    def test_local_command_drops_bare_and_key_helper_and_hides_credential_stores(self):
        names = ("root", "work", "reports", "private", "plugin", "scratch")
        root, work, out, private, plugin, scratch = [self.out / name for name in names]

        def invocation(run, key):
            command = runner.command("code-review", "claude", root, run, work, out, key, plugin, scratch,
                                     "trusted prompt", runner.SCHEMA, runner.TOOLS)
            return command, json.loads(command[command.index("--settings") + 1])

        command, settings = invocation(local_run(), None)
        self.assertNotIn("--bare", command)
        self.assertNotIn("apiKeyHelper", settings)
        filesystem = settings["sandbox"]["filesystem"]
        for name in runner.LOCAL_SECRETS:
            self.assertIn(str(Path.home() / name), filesystem["denyRead"])
        self.assertNotIn("None", filesystem["denyRead"] + filesystem["denyWrite"])
        self.assertIn(str(root), filesystem["denyWrite"])
        command, settings = invocation({"model": "claude-opus-5-5", "effort": "xhigh"}, private)
        self.assertIn("--bare", command)
        self.assertIn("apiKeyHelper", settings)
        self.assertNotIn(str(Path.home() / ".config/gh"), settings["sandbox"]["filesystem"]["denyRead"])

    def test_local_and_workflow_runs_cannot_swap_credentials(self):
        with patch.dict(os.environ), patch("subprocess.check_output") as call:
            os.environ.pop("ANTHROPIC_API_KEY", None)
            with self.assertRaisesRegex(ValueError, "own login"):
                runner.review(self.out, local_run(), self.out, self.out, self.out)
            with self.assertRaisesRegex(ValueError, "own login"):
                runner.review(self.out, {}, self.out, self.out, None)
        call.assert_not_called()

    def test_receipts_bind_the_local_cli_version(self):
        run = local_run()
        self.reports(run)
        runner.verify(run, self.out)
        receipt = runner.read_json(self.out / "receipt.json")
        receipt["claude_version"] = runner.CLAUDE_VERSION
        runner.write_json(self.out / "receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "different invocation"):
            runner.verify(run, self.out)

    def test_workflow_controller_rejects_local_runs(self):
        with self.assertRaisesRegex(ValueError, "invalid run identity"):
            github.validate_identity(local_run())
        path = self.out / "run.json"
        runner.write_json(path, local_run())
        with patch.object(sys, "argv", ["runner.py", "run", "--private", str(self.out), "--run", str(path)]), \
             patch.object(runner, "review") as review:
            with self.assertRaisesRegex(ValueError, "local.py"):
                runner.main()
        review.assert_not_called()

    def test_start_binds_the_live_snapshot_and_local_cli(self):
        def git(root, command, *args, **kwargs):
            return "" if command == "status" else BASE

        environment = {key: value for key, value in os.environ.items() if not key.startswith("RAGU_AUDIT_")}
        with patch.dict(os.environ, environment, clear=True), patch.object(local.runner, "git", side_effect=git), \
             patch.object(local.shutil, "which", return_value=sys.executable), \
             patch.object(local.subprocess, "check_output", return_value="2.1.311 (Claude Code)\n"):
            run = local.start(self.api, "9")
            with self.assertRaisesRegex(ValueError, "not " + "c" * 40):
                local.start(self.api, "9", "c" * 40)
        self.assertEqual(run, local_run(claude_version="2.1.311"))
        runner.RunBudget(run)  # The default models are priced by the safety guard.

    def test_start_refuses_uncommitted_review_configuration(self):
        with patch.object(local.runner, "git", return_value=" M .claude/skills/tal-review/SKILL.md"):
            with self.assertRaisesRegex(ValueError, "commit or stash"):
                local.start(self.api, "9")

    def test_failed_review_still_cleans_up_and_writes_a_summary(self):
        run = local_run()
        with patch.object(local.runner, "review", side_effect=ValueError("review incomplete: tal-review")), \
             patch.object(local, "cleanup") as cleanup, patch.dict(os.environ, {"CARGO_HOME": str(Path.home() / ".cargo")}):
            work, state = local.review(run)
            self.assertNotIn("CARGO_HOME", os.environ)
        self.addCleanup(shutil.rmtree, work)
        cleanup.assert_called_once_with(work)
        self.assertEqual(state, "incomplete")
        self.assertEqual(runner.read_json(work / "run.json"), run)
        text = (work / "comment.md").read_text()
        self.assertIn("run `/ragu-audit` again", text)
        self.assertNotIn("actions/runs", text)

    def test_publish_posts_inline_and_one_replaceable_summary_as_the_maintainer(self):
        bot = {"id": 50, "user": {"type": "Bot", "login": APP["slug"] + "[bot]"}, "body": github.MARKER + "\nBot summary",
               "issue_url": f"https://api.github.com/repos/{github.REPOSITORY}/issues/9"}
        self.api.comments.append(copy.deepcopy(bot))
        run = local_run()
        self.reports(run, candidate())
        local.publish(self.api, run, self.out)
        local.publish(self.api, run, self.out)
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(len(self.api.review_comments), 1)
        self.assertEqual(self.api.reviews[0]["user"], LOGIN)
        self.assertEqual(self.api.comments[0], bot)
        self.assertEqual(len(self.api.comments), 2)
        text = self.api.comments[1]["body"]
        self.assertTrue(text.startswith(github.LOCAL_MARKER + "\n"))
        self.assertNotIn(github.MARKER, text)
        self.assertIn("## Ragu audit (local run): completed", text)
        self.assertIn("1 finding posted inline", text)
        self.assertIn("No `ragu-audit/completed` check was recorded", text)
        self.assertIn("Claude Code 9.9.9", text)
        for absent in ("actions/runs", "[Full report]", "Workflow and complete reports"):
            self.assertNotIn(absent, text)
        self.assertEqual(self.api.checks, [])

    def test_moved_head_posts_only_a_stale_summary_but_moved_main_does_not(self):
        run = local_run()
        self.reports(run, candidate())
        self.api.main_sha = "d" * 40
        local.publish(self.api, run, self.out)
        self.assertEqual(len(self.api.reviews), 1)
        self.assertIn("local run): completed", self.api.comments[-1]["body"])
        self.api.target["head"]["sha"] = "c" * 40
        local.publish(self.api, run, self.out)
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(len(self.api.comments), 1)
        self.assertIn("local run): stale", self.api.comments[-1]["body"])

    def test_publish_refuses_workflow_runs(self):
        with self.assertRaisesRegex(ValueError, "not a local run"):
            local.publish(self.api, {**local_run(), "local": False}, self.out)


if __name__ == "__main__":
    unittest.main()
