import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import github
import runner


BASE, HEAD = "b" * 40, "a" * 40
APP = {"id": 17, "slug": "ragu-audit-test"}
ENV = {
    "GITHUB_REPOSITORY": github.REPOSITORY, "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_SHA": BASE, "GITHUB_RUN_ID": "40027821675", "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_ACTOR": "alice", "GITHUB_TRIGGERING_ACTOR": "alice",
    "RAGU_AUDIT_MODEL": "claude-opus-5-5", "RAGU_AUDIT_EFFORT": "xhigh", "RAGU_AUDIT_APP_ID": "17",
}


def native(report="No findings within the reviewed scope."):
    return {"type": "result", "subtype": "success", "is_error": False, "permission_denials": [],
            "structured_output": {"complete": True, "report": report}}


class API:
    def __init__(self):
        self.target = {"state": "open", "number": 9, "head": {"sha": HEAD},
                       "base": {"sha": BASE, "ref": "main", "repo": {"full_name": github.REPOSITORY}}}
        self.permissions = {"alice": "write", "mallory": "read"}
        self.comment = {"body": "/ragu-audit", "user": {"login": "alice", "type": "User"},
                        "issue_url": f"https://api.github.com/repos/{github.REPOSITORY}/issues/9"}
        self.checks, self.comments, self.mutations = [], [], []

    def call(self, path, data=None, method=None):
        if data is None:
            if path.endswith("/pulls/9"):
                return copy.deepcopy(self.target)
            if "/collaborators/" in path:
                return {"permission": self.permissions.get(path.split("/")[-2], "none")}
            if path.endswith("/issues/comments/12"):
                return copy.deepcopy(self.comment)
            raise AssertionError(path)
        self.mutations.append((path, copy.deepcopy(data), method))
        if path.endswith("/check-runs"):
            check = {**data, "id": len(self.checks) + 1, "app": APP}
            self.checks.append(check)
            return copy.deepcopy(check)
        if "/check-runs/" in path:
            check = next(check for check in self.checks if str(check["id"]) == path.split("/")[-1])
            check.update(data)
            return copy.deepcopy(check)
        if "/comments" in path:
            if method == "POST":
                result = {"id": len(self.comments) + 100, "user": {"type": "Bot", "login": APP["slug"] + "[bot]"}, **data}
                self.comments.append(result)
            else:
                result = next(comment for comment in self.comments if str(comment["id"]) == path.split("/")[-1])
                result.update(data)
            return copy.deepcopy(result)
        raise AssertionError(path)

    def pages(self, path, key=None):
        return iter(copy.deepcopy(self.checks if "check-runs" in path else self.comments))


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.api = API()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.out = Path(self.directory.name)

    def event(self, body="/ragu-audit"):
        return {"issue": {"number": 9, "pull_request": {}},
                "comment": {"id": 12, "body": body, "user": {"login": "alice"}}}

    def reports(self, run):
        phases = []
        for skill in runner.SKILLS:
            runner.write_json(self.out / f"{skill}.json", native())
            (self.out / f"{skill}.md").write_text("No findings.\n")
            phases.append({"skill": skill, "complete": True, "sha256": runner.digest(self.out / f"{skill}.md")})
        receipt = {"run": run, "merge_base": BASE, "claude_version": runner.CLAUDE_VERSION, "phases": phases}
        runner.write_json(self.out / "receipt.json", receipt)
        return receipt

    def test_authorized_exact_comment(self):
        event = self.event()
        event["issue"]["pull_request"] = {"url": "PR"}
        self.assertEqual(github.request(self.api, event, "issue_comment"), (9, True))

    def test_unrelated_comment_does_nothing(self):
        for body in ("please /ragu-audit", "/ragu-audit extra", "/ragu-audit-evil"):
            self.assertIsNone(github.request(self.api, self.event(body), "issue_comment"))
        self.assertEqual(self.api.mutations, [])

    def test_live_comment_and_write_permission_are_required(self):
        event = self.event()
        event["issue"]["pull_request"] = {"url": "PR"}
        self.api.comment["body"] = "deleted command"
        self.assertIsNone(github.request(self.api, event, "issue_comment"))
        self.api.comment["body"] = "/ragu-audit"
        self.api.permissions["alice"] = "read"
        self.assertIsNone(github.request(self.api, event, "issue_comment"))

    def test_rerunning_actor_must_have_write_access(self):
        os.environ["GITHUB_TRIGGERING_ACTOR"] = "mallory"
        self.assertIsNone(github.request(self.api, {"inputs": {"pull_request": "9"}}, "workflow_dispatch"))

    def test_bot_commands_are_ignored(self):
        self.api.comment["user"]["type"] = "Bot"
        event = self.event()
        event["issue"]["pull_request"] = {"url": "PR"}
        self.assertIsNone(github.request(self.api, event, "issue_comment"))

    def test_title_edits_do_not_invalidate_review(self):
        self.assertIsNone(github.request(self.api, {"action": "edited", "number": 9, "changes": {"title": {}}}, "pull_request_target"))

    def test_other_base_or_closed_pr_is_rejected(self):
        for key, value in (("ref", "other"), ("repo", {"full_name": "other/repo"})):
            with self.subTest(key=key):
                target = copy.deepcopy(self.api.target)
                self.api.target["base"][key] = value
                with self.assertRaises(ValueError):
                    github.pr(self.api, 9)
                self.api.target = target
        self.api.target["state"] = "closed"
        with self.assertRaises(ValueError):
            github.pr(self.api, 9)

    def test_number_and_revision_validation(self):
        for value in ("9\nexecute=true", "-1", "1; echo bad", "0"):
            with self.assertRaises(ValueError):
                github.number(value)
        for value in ("main", "a" * 39, "z" * 40):
            with self.assertRaises(ValueError):
                github.sha(value)

    def test_automatic_queue_is_blocked_without_creating_comment(self):
        run = github.queue(self.api, 9, False)
        self.assertEqual(self.api.checks[0]["status"], "queued")
        self.assertEqual(self.api.comments, [])
        self.assertIsNone(github.queue(self.api, 9, False))
        self.assertEqual(len(self.api.checks), 1)
        self.assertEqual(run["configuration"], BASE)

    def test_reruns_update_one_app_owned_comment(self):
        old = github.queue(self.api, 9, True)
        os.environ["GITHUB_RUN_ID"] = "40027821676"
        new = github.queue(self.api, 9, True)
        self.assertEqual(len(self.api.comments), 1)
        self.assertEqual(len(self.api.checks), 2)
        with self.assertRaises(ValueError):
            github.guard(self.api, old)
        self.assertEqual(github.guard(self.api, new)["id"], new["check_id"])

    def test_new_base_invalidates_previous_completion_and_comment(self):
        run = github.queue(self.api, 9, True)
        self.api.checks[0].update(status="completed", conclusion="success")
        self.api.target["base"]["sha"] = "c" * 40
        os.environ["GITHUB_WORKFLOW_SHA"] = "c" * 40
        current = github.queue(self.api, 9, False)
        self.assertEqual(len(self.api.comments), 1)
        self.assertIn("fresh review", self.api.comments[0]["body"])
        self.assertEqual(self.api.checks[-1]["status"], "queued")
        self.assertNotEqual(run["external_id"], current["external_id"])

    def test_moved_head_or_base_cannot_publish_success(self):
        run = github.queue(self.api, 9, True)
        self.reports(run)
        for side in ("head", "base"):
            target = copy.deepcopy(self.api.target)
            self.api.target[side]["sha"] = "d" * 40
            with self.assertRaises(ValueError):
                github.publish(self.api, run, self.out, "success")
            self.assertNotIn("conclusion", self.api.checks[0])
            self.api.target = target

    def test_old_workflow_configuration_cannot_queue(self):
        os.environ["GITHUB_WORKFLOW_SHA"] = "c" * 40
        with self.assertRaises(ValueError):
            github.queue(self.api, 9, True)
        self.assertEqual(self.api.mutations, [])

    def test_foreign_app_cannot_satisfy_gate(self):
        run = github.queue(self.api, 9, True)
        self.api.checks[0]["app"] = {"id": 42, "slug": "other"}
        with self.assertRaises(ValueError):
            github.guard(self.api, run)

    def test_comment_marker_alone_does_not_establish_ownership(self):
        for user in ({"type": "User", "login": "alice"}, {"type": "Bot", "login": "other[bot]"}):
            self.assertFalse(github.owns_comment({"body": github.MARKER + "\nforged", "user": user}, APP))

    def test_only_all_four_reports_allow_success(self):
        run = github.queue(self.api, 9, True)
        self.reports(run)
        github.publish(self.api, run, self.out, "success")
        self.assertEqual(self.api.checks[0]["conclusion"], "success")
        self.assertEqual(len(self.api.comments), 1)
        for skill in runner.SKILLS:
            self.assertIn(f"<summary>{skill}</summary>", self.api.comments[0]["body"])

    def test_missing_reports_or_failed_job_publish_failure(self):
        for result in ("success", "failure", "cancelled"):
            with self.subTest(result=result):
                api = API()
                run = github.queue(api, 9, True)
                with self.assertRaises(ValueError):
                    github.publish(api, run, self.out, result)
                self.assertEqual(api.checks[0]["conclusion"], "failure")
                self.assertIn("incomplete", api.comments[0]["body"])

    def test_receipt_order_revision_and_digest_are_bound(self):
        run = github.queue(self.api, 9, True)
        for mutate in (
            lambda receipt: receipt["phases"].reverse(),
            lambda receipt: receipt["phases"].pop(),
            lambda receipt: receipt["phases"][0].update(complete=False),
            lambda receipt: receipt["run"].update(head="c" * 40),
        ):
            receipt = self.reports(copy.deepcopy(run))
            mutate(receipt)
            runner.write_json(self.out / "receipt.json", receipt)
            with self.assertRaises(ValueError):
                runner.verify(run, self.out)
        self.reports(run)
        (self.out / "tal-review.md").write_text("changed")
        with self.assertRaises(ValueError):
            runner.verify(run, self.out)

    def test_native_errors_denials_or_incomplete_results_fail_closed(self):
        for update in ({"subtype": "error_max_turns"}, {"is_error": True}, {"permission_denials": [{"tool_name": "Bash"}]},
                       {"structured_output": {"complete": False, "report": "Missing evidence"}},
                       {"structured_output": {"complete": True, "report": ""}}):
            self.assertFalse(runner.completed({**native(), **update}))

    def test_summary_has_no_mentions_or_active_html_and_is_bounded(self):
        text = github.excerpt("</details><img src=x> @alice ![tracking](https://example.test)" + "💥" * 30000)
        self.assertNotIn("</details>", text)
        self.assertNotIn("@alice", text)
        self.assertNotIn("![", text)
        self.assertLess(len(text.encode()), 9200)

    def test_cli_environment_has_no_inherited_credentials(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "dummy-key", "GH_TOKEN": "dummy-token", "AWS_SECRET_ACCESS_KEY": "dummy-aws"}):
            values = runner.environment({"model": "claude-opus-5-5", "effort": "xhigh"}, self.out)
        for key in ("ANTHROPIC_API_KEY", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(key, values)
        self.assertEqual(values["CLAUDE_CODE_SUBAGENT_MODEL_FORCE"], "1")
        self.assertEqual(values["CLAUDE_CODE_EFFORT_LEVEL"], "xhigh")

    def test_sandbox_cannot_fall_back_or_write_control_paths(self):
        root, source, work, out, private, plugin = [self.out / name for name in ("root", "source", "work", "reports", "private", "plugin")]
        settings = runner.settings(root, source, work, out, private, plugin)
        sandbox = settings["sandbox"]
        self.assertTrue(sandbox["enabled"] and sandbox["failIfUnavailable"])
        self.assertFalse(sandbox["allowUnsandboxedCommands"])
        self.assertEqual(sandbox["excludedCommands"], [])
        self.assertIn(str(private), sandbox["filesystem"]["denyRead"])
        self.assertIn("/proc", sandbox["filesystem"]["denyRead"])
        for path in (root, out, private, plugin):
            self.assertIn(str(path), sandbox["filesystem"]["denyWrite"])
            self.assertIn(f"Write(/{path}/**)", settings["permissions"]["deny"])
        self.assertFalse(sandbox["network"]["allowAllUnixSockets"])

    def test_inherited_key_is_rejected_before_launching_cli(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "dummy"}), patch("subprocess.check_output") as call:
            with self.assertRaisesRegex(ValueError, "separate step"):
                runner.review(self.out, {}, self.out, self.out, self.out)
        call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
