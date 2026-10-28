"""Exercise local sign-in, version binding, and publication without model calls."""

import copy
import json
import os
from pathlib import Path
import re
import shutil
import sys
import threading
import unittest
from unittest.mock import patch

import findings
import github
import local
import runner
import test_audit
from test_audit import APP, BASE, HEAD, candidate, native

LOGIN = {"type": "User", "login": "maintainer"}


def local_run(**changes):
    return {"repository": github.REPOSITORY, "pr": 9, "head": HEAD, "base": BASE, "configuration": BASE,
            "model": "claude-sonnet-5-5", "effort": "high", "reconcile_model": "claude-sonnet-5-5",
            "reconcile_effort": "high", "local": True, "backend": "claude", "cli_version": "9.9.9", **changes}


def codex_run(**changes):
    return local_run(**{"backend": "codex", "cli_version": "0.163.0", "model": "gpt-6.1-sol", "effort": "high",
                        "reconcile_model": "gpt-6.1-sol", "reconcile_effort": "high", **changes})


def inline_table(text):
    """The string pairs of one `-c key={...}` override."""
    return dict(re.findall(r'"((?:[^"\\]|\\.)*)"="((?:[^"\\]|\\.)*)"', text))


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
        receipt["claude_version"] = run["cli_version"]
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

    def test_local_command_hides_credential_stores_and_claude_state_except_its_own_session(self):
        names = ("root", "work", "reports", "private", "plugin", "scratch", "home")
        root, work, out, private, plugin, scratch, home = [self.out / name for name in names]
        state = home / ".claude"
        project = state / "projects" / runner.project_slug(root)
        for path in (home / ".claude.json", state / ".credentials.json", state / "settings.json",
                     state / "projects/-other-project/old.jsonl", project / "earlier.jsonl", project / "memory/MEMORY.md"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        own = project / runner.session_id(work, "code-review")
        peers = [project / runner.session_id(work, role) for role in runner.ROLES if role != "code-review"]

        def invocation(run, key):
            with patch.object(Path, "home", return_value=home):
                command = runner.command("code-review", "claude", root, run, work, out, key, plugin, scratch,
                                         "trusted prompt", runner.SCHEMA, runner.TOOLS)
            return command, json.loads(command[command.index("--settings") + 1])

        command, settings = invocation(local_run(), None)
        self.assertNotIn("--bare", command)
        self.assertNotIn("apiKeyHelper", settings)
        self.assertEqual(command[command.index("--session-id") + 1], own.name)
        filesystem = settings["sandbox"]["filesystem"]
        for name in runner.LOCAL_SECRETS:
            self.assertIn(str(home / name), filesystem["denyRead"])
        for path in (state / ".credentials.json", state / "settings.json", state / "projects/-other-project",
                     project / "earlier.jsonl", project / "memory", *peers):
            self.assertIn(str(path), filesystem["denyRead"])
            self.assertIn(f"Read(/{path}/**)", settings["permissions"]["deny"])
        for path in (state / "projects", project, own):
            self.assertNotIn(str(path), filesystem["denyRead"])
            self.assertNotIn(f"Read(/{path}/**)", settings["permissions"]["deny"])
        # PR commands see none of the Claude state; the Read tool only loses what the run may create.
        self.assertIn(str(state), filesystem["denyRead"])
        self.assertNotIn(f"Read(/{state}/**)", settings["permissions"]["deny"])
        for pattern in ("*.jsonl", "*/subagents/**", "*/session-memory/**", "memory/**"):
            self.assertIn(f"Read(/{project}/{pattern})", settings["permissions"]["deny"])
        self.assertNotIn("None", filesystem["denyRead"] + filesystem["denyWrite"])
        self.assertIn(str(root), filesystem["denyWrite"])
        command, settings = invocation({"model": "claude-opus-5-5", "effort": "xhigh"}, private)
        self.assertIn("--bare", command)
        self.assertNotIn("--session-id", command)
        self.assertIn("apiKeyHelper", settings)
        for path in (home / ".config/gh", state / "settings.json", state):
            self.assertNotIn(str(path), settings["sandbox"]["filesystem"]["denyRead"])
        self.assertFalse([rule for rule in settings["permissions"]["deny"] if "*.jsonl" in rule])

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
            if command == "remote":
                return f"git@github.com:{github.REPOSITORY}.git"
            return "" if command == "status" else BASE

        environment = {key: value for key, value in os.environ.items() if not key.startswith("RAGU_AUDIT_")}
        with patch.dict(os.environ, environment, clear=True), patch.object(local.runner, "git", side_effect=git), \
             patch.object(local.shutil, "which", return_value=sys.executable), \
             patch.object(local.subprocess, "check_output", return_value="2.1.311 (Claude Code)\n"):
            run = local.start(self.api, "9")
            with self.assertRaisesRegex(ValueError, "not " + "c" * 40):
                local.start(self.api, "9", "c" * 40)
        self.assertEqual(run, local_run(cli_version="2.1.311"))
        runner.RunBudget(run)  # The default models are priced by the safety guard.

    def test_start_refuses_uncommitted_review_configuration(self):
        with patch.object(local.runner, "git", return_value=" M .claude/skills/tal-review/SKILL.md"):
            with self.assertRaisesRegex(ValueError, "commit or stash"):
                local.start(self.api, "9")

    def test_client_keeps_the_gh_token_out_of_the_environment(self):
        with patch.dict(os.environ), patch.object(local.subprocess, "check_output", return_value="gho_token\n") as gh:
            os.environ.pop("GH_TOKEN", None)
            api = local.client()
            self.assertNotIn("GH_TOKEN", os.environ)
        gh.assert_called_once()
        self.assertEqual(api.token, "gho_token")
        with patch.dict(os.environ, {"GH_TOKEN": ""}), patch.object(local.subprocess, "check_output", side_effect=FileNotFoundError("gh")):
            with self.assertRaisesRegex(ValueError, "gh auth login"):
                local.client()

    def test_start_refuses_a_fork_as_origin(self):
        def git(root, command, *args, **kwargs):
            return "https://github.com/someone/ragu.git" if command == "remote" else ""

        with patch.object(local.runner, "git", side_effect=git):
            with self.assertRaisesRegex(ValueError, "origin is https://github.com/someone/ragu.git"):
                local.start(self.api, "9")

    def test_command_line_accepts_pr_spellings_and_reports_startup_errors_briefly(self):
        for value in ("921", "#921", f"https://github.com/{github.REPOSITORY}/pull/921", f"https://github.com/{github.REPOSITORY}/pull/921/"):
            self.assertEqual(local.pr_number(value), "921")
        for value in ("pr 921", "https://github.com/other/repo/pull/921", "921abc"):
            with self.assertRaises(local.argparse.ArgumentTypeError):
                local.pr_number(value)
        with patch.object(sys, "argv", ["local.py", "run", "#921", "--backend", "codex"]), patch.object(local, "client", return_value=self.api), \
             patch.object(local, "start", side_effect=ValueError("commit or stash changes")) as start, \
             patch.object(local, "review") as review:
            with self.assertRaises(SystemExit) as stop:
                local.main()
        start.assert_called_once_with(self.api, "921", None, "codex")
        review.assert_not_called()
        self.assertEqual(stop.exception.code, "error: commit or stash changes")

    def test_cleanup_removes_the_cargo_home_and_the_reviewers_session_directories(self):
        work, home = self.out / "work", self.out / "home"
        project = home / ".claude" / "projects" / runner.project_slug(local.ROOT)
        (work / "cargo").mkdir(parents=True)
        for role in runner.ROLES:
            (project / runner.session_id(work, role) / "tool-results").mkdir(parents=True)
        (project / "maintainer-session.jsonl").touch()
        with patch.object(Path, "home", return_value=home), patch.object(local.runner, "git") as git:
            local.cleanup(work, local_run())
        git.assert_not_called()  # No worktrees were left to remove.
        self.assertFalse((work / "cargo").exists())
        self.assertEqual([path.name for path in project.iterdir()], ["maintainer-session.jsonl"])

    def test_failed_review_still_cleans_up_and_writes_a_summary(self):
        run = local_run()
        with patch.object(local.runner, "review", side_effect=ValueError("review incomplete: tal-review")), \
             patch.object(local, "cleanup") as cleanup, patch.dict(os.environ, {"CARGO_HOME": str(Path.home() / ".cargo")}):
            work, state = local.review(run)
            self.assertNotIn("CARGO_HOME", os.environ)
        self.addCleanup(shutil.rmtree, work)
        cleanup.assert_called_once_with(work, run)
        self.assertEqual(state, "incomplete")
        self.assertEqual(runner.read_json(work / "run.json"), run)
        text = (work / "comment.md").read_text()
        self.assertIn("run `/ragu-audit` again", text)
        self.assertNotIn("actions/runs", text)

    def test_publish_posts_inline_and_one_replaceable_summary_as_the_maintainer(self):
        bot = {"id": 50, "user": {"type": "Bot", "login": APP["slug"] + "[bot]"}, "body": github.MARKER + "\nBot summary",
               "issue_url": f"https://api.github.com/repos/{github.REPOSITORY}/issues/9"}
        other = {"id": 51, "user": {"type": "User", "login": "other-maintainer"}, "body": github.LOCAL_MARKER + "\nTheir summary",
                 "issue_url": bot["issue_url"]}
        self.api.comments += [copy.deepcopy(bot), copy.deepcopy(other)]
        run = local_run()
        self.reports(run, candidate())
        local.publish(self.api, run, self.out)
        local.publish(self.api, run, self.out)
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(len(self.api.review_comments), 1)
        self.assertEqual(self.api.reviews[0]["user"], LOGIN)
        self.assertIn("Report excerpts and validation limits are in the audit status comment", self.api.reviews[0]["body"])
        self.assertEqual(self.api.comments[:2], [bot, other])  # The bot's and another maintainer's summaries stay.
        self.assertEqual(len(self.api.comments), 3)
        text = self.api.comments[2]["body"]
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

    def test_authorship_distinguishes_the_app_from_a_maintainer(self):
        bot = {"user": {"type": "Bot", "login": APP["slug"] + "[bot]"}}
        self.assertTrue(github.authored(bot, APP))
        self.assertTrue(github.authored(bot, {**APP, "login": "ignored"}))  # GitHub may extend its App object.
        self.assertFalse(github.authored(bot, {"login": APP["slug"] + "[bot]"}))
        self.assertTrue(github.authored({"user": dict(LOGIN)}, {"login": LOGIN["login"]}))
        self.assertFalse(github.authored({"user": {**LOGIN, "type": "Bot"}}, {"login": LOGIN["login"]}))
        self.assertFalse(github.authored({"user": dict(LOGIN)}, {"login": "someone-else"}))

    def test_codex_command_uses_a_permission_profile_offline_without_user_configuration(self):
        names = ("root", "work", "reports", "plugin", "scratch", "home")
        root, work, out, plugin, scratch, home = [self.out / name for name in names]
        with patch.object(Path, "home", return_value=home):
            command = runner.command("sean-review", "codex", root, codex_run(), work, out, None, plugin, scratch,
                                     "trusted prompt", runner.SCHEMA, runner.TOOLS)
            reconcile = runner.command("reconcile", "codex", root, codex_run(), work, out, None, plugin, scratch,
                                       "reconcile prompt", findings.RECONCILE_SCHEMA, "Read")
        self.assertEqual(command[:3], ["codex", "exec", "--json"])
        for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check"):
            self.assertIn(flag, command)
        self.assertNotIn("--bare", command)
        self.assertEqual(command[command.index("-C") + 1], str(work / "sean-review"))
        self.assertEqual(command[command.index("-m") + 1], "gpt-6.1-sol")
        self.assertEqual(runner.read_json(Path(command[command.index("--output-schema") + 1])), runner.SCHEMA)
        self.assertEqual(command[-2:], ["--", "trusted prompt"])
        self.assertEqual([command[i + 1] for i, token in enumerate(command) if token == "--disable"], list(runner.CODEX_FEATURES_OFF))
        overrides = [command[i + 1] for i, token in enumerate(command) if token == "-c"]
        for expected in ('default_permissions="ragu-audit"', "permissions.ragu-audit.network={enabled=false}", 'approval_policy="never"',
                         "project_doc_max_bytes=0", "mcp_servers={}", 'model_reasoning_effort="high"'):
            self.assertIn(expected, overrides)
        self.assertIn("source review", next(value for value in overrides if value.startswith("developer_instructions=")))
        access = inline_table(next(value for value in overrides if value.startswith("permissions.ragu-audit.filesystem=")))
        self.assertEqual(access["/"], "read")
        for path in (work / "sean-review", runner.cargo_home(work), scratch / "sean-review"):
            self.assertEqual(access[str(path)], "write")
        for path in (work / "tal-review", work / "code-review", scratch / "tal-review", work / "control", out,
                     home / ".codex", home / ".claude", home / ".claude.json", home / ".ssh", home / ".config/gh"):
            self.assertEqual(access[str(path)], "none")
        for name in ("core-findings.json", "code-review.md"):
            self.assertEqual(access[str(out / name)], "read")
        self.assertNotIn(str(out / "findings.json"), access)
        access = inline_table(next(value for i, value in enumerate(reconcile) if reconcile[i - 1] == "-c" and "filesystem=" in value))
        self.assertEqual(access[str(out / "findings.json")], "read")
        self.assertEqual([path for path, mode in access.items() if mode == "write"], [str(scratch / "reconcile")])
        self.assertEqual(runner.read_json(Path(reconcile[reconcile.index("--output-schema") + 1])), findings.RECONCILE_SCHEMA)
        claude = runner.command("sean-review", "claude", root, local_run(), work, out, None, plugin, scratch,
                                "trusted prompt", runner.SCHEMA, runner.TOOLS)
        self.assertNotIn("exec", claude)

    def test_codex_environment_is_offline_without_claude_settings(self):
        values = runner.environment(codex_run(), self.out, "tal-review", self.out / "scratch")
        self.assertEqual((values["CARGO_NET_OFFLINE"], values["TMPDIR"]), ("true", str(self.out / "scratch/tal-review")))
        self.assertEqual(values["CARGO_HOME"], str(runner.cargo_home(self.out)))
        self.assertEqual([key for key in values if key.startswith("CLAUDE") or key == "CODEX_HOME"], [])

    def test_codex_events_become_a_native_result(self):
        run, output = codex_run(), native()["structured_output"]
        events = [{"type": "thread.started", "thread_id": "t"}, {"type": "turn.started"},
                  {"type": "item.completed", "item": {"id": "i0", "type": "reasoning", "text": "thinking"}},
                  {"type": "item.completed", "item": {"id": "i1", "type": "command_execution", "command": "ls", "exit_code": 0}},
                  {"type": "item.completed", "item": {"id": "i2", "type": "agent_message", "text": json.dumps(output)}},
                  {"type": "turn.completed", "usage": {"input_tokens": 10, "cached_input_tokens": 4, "output_tokens": 5}}]
        script = self.out / "codex.py"

        def execute(stream):
            script.write_text("import json\nfor event in " + repr(stream) + ":\n    print(json.dumps(event))\n")
            return runner.execute_review([sys.executable, str(script)], cwd=self.out, env={}, run=run, skill="tal-review",
                                         out=self.out, private=None, cancelled=threading.Event())

        result = execute(events)
        self.assertTrue(runner.completed(result))
        self.assertEqual((result["backend"], result["total_cost_usd"], result["usage"]["output_tokens"]), ("codex", 0.0, 5))
        self.assertEqual(result["structured_output"], output)
        status = runner.read_json(self.out / "tal-review.status.json")
        self.assertEqual((status["tool_calls"], status["last_tool"], status["state"]), (1, "Bash", "returned"))
        self.assertEqual(runner.read_json(self.out / "tal-review.json"), result)
        result = execute([events[0], {"type": "turn.failed", "error": {"message": "boom"}}])
        self.assertFalse(runner.completed(result))
        self.assertIn("Codex session", runner.incomplete_reason(result))
        result = execute(events[:-2] + [{"type": "item.completed", "item": {"id": "i2", "type": "agent_message", "text": "not json"}}, events[-1]])
        self.assertFalse(runner.completed(result))

    def test_codex_review_runs_every_pass_without_a_budget_guard(self):
        root, work, out = self.out / "root", self.out / "work", self.out / "reports"
        for skill in runner.SKILLS:
            (root / ".claude/skills" / skill).mkdir(parents=True)
            (root / ".claude/skills" / skill / "SKILL.md").write_text(f"---\nname: {skill}\n---\n# {skill}\n")
        output = native()["structured_output"]
        fake = self.out / "codex"
        fake.write_text(f"""#!{sys.executable}
import json, sys
if "--version" in sys.argv:
    print("codex-cli 0.163.0"); sys.exit()
for event in ({{"type": "thread.started", "thread_id": "t"}},
              {{"type": "item.completed", "item": {{"id": "i0", "type": "command_execution", "command": "ls", "exit_code": 0}}}},
              {{"type": "item.completed", "item": {{"id": "i1", "type": "agent_message", "text": {json.dumps(json.dumps(output))}}}}},
              {{"type": "turn.completed", "usage": {{"input_tokens": 9, "cached_input_tokens": 0, "output_tokens": 3}}}}):
    print(json.dumps(event))
""")
        fake.chmod(0o755)
        run = codex_run(head="a" * 40)

        def git(path, command, *args, **kwargs):
            return run["head"] if command == "rev-parse" else ""

        with patch.dict(os.environ), patch.object(runner.shutil, "which", return_value=str(fake)), \
             patch.object(runner, "prepare", return_value=run["base"]), patch.object(runner, "git", side_effect=git), \
             patch.object(runner, "prefetch_dependencies") as prefetch, patch.object(runner, "isolate_shared_temp", side_effect=lambda command, scratch: command), \
             patch.object(Path, "home", return_value=self.out / "home"):
            os.environ.pop("CARGO_HOME", None)
            runner.review(root, run, work, out, None)
        prefetch.assert_called_once_with(work / "code-review", work)
        receipt = runner.verify(run, out)
        self.assertEqual([phase["skill"] for phase in receipt["phases"]], list(runner.SKILLS))
        self.assertEqual({runner.read_json(out / f"{skill}.json")["backend"] for skill in runner.SKILLS}, {"codex"})
        self.assertEqual(runner.read_json(out / "reconciliation-receipt.json")["state"], "empty")
        self.assertFalse((self.out / "home").exists())  # No Claude session directories for a Codex run.

    def test_codex_prompt_inlines_the_skill_and_leaves_the_claude_prompt_alone(self):
        work, root = self.out / "work", self.out / "root"
        skill_dir = work / "trusted-plugin/skills/tal-review"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("---\nname: tal-review\n---\n\n# Tal review\nCheck ordering.\n")
        source, out = work / "tal-review", work / "reports"
        codex = runner.prompt("tal-review", source, "m" * 40, codex_run(), out, root)
        claude = runner.prompt("tal-review", source, "m" * 40, local_run(), out, root)
        self.assertIn("# Tal review\nCheck ordering.\n</skill>", codex)
        self.assertNotIn("name: tal-review", codex)
        self.assertIn(f"Trusted policies are in {root}/.claude/code-review and {root}/.claude/review-shared.", codex)
        self.assertIn("no network access", codex)
        self.assertNotIn("/ragu-review:", codex)
        self.assertTrue(claude.startswith("/ragu-review:tal-review Review the changes in"))
        self.assertIn("current working directory's .claude/code-review", claude)
        self.assertIn("allowlist permits Cargo downloads and GitHub", claude)
        self.assertNotIn("<skill>", claude)
        self.assertEqual(claude, runner.prompt("tal-review", source, "m" * 40, {**local_run(), "local": False}, out))

    def test_start_with_codex_records_its_cli_and_the_maintainers_default_model(self):
        def git(root, command, *args, **kwargs):
            if command == "remote":
                return f"git@github.com:{github.REPOSITORY}.git"
            return "" if command == "status" else BASE

        home = self.out / "home"
        (home / ".codex").mkdir(parents=True)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("RAGU_AUDIT_") and key != "CODEX_HOME"}
        with patch.dict(os.environ, environment, clear=True), patch.object(local.runner, "git", side_effect=git), \
             patch.object(local.shutil, "which", return_value=sys.executable), patch.object(Path, "home", return_value=home), \
             patch.object(local.subprocess, "check_output", return_value="codex-cli 0.163.0\n"):
            with self.assertRaisesRegex(ValueError, "set RAGU_AUDIT_MODEL"):
                local.start(self.api, "9", backend="codex")
            (home / ".codex/config.toml").write_text('model = "gpt-6-luna"\nmodel_reasoning_effort = "max"\n')
            run = local.start(self.api, "9", backend="codex")
            with patch.dict(os.environ, {"RAGU_AUDIT_MODEL": "GPT-6", "RAGU_AUDIT_EFFORT": "ultra"}):
                with self.assertRaisesRegex(ValueError, "Codex model ID"):
                    local.start(self.api, "9", backend="codex")
        self.assertEqual(run, codex_run(model="gpt-6-luna", reconcile_model="gpt-6-luna"))
        self.assertIn("Codex CLI 0.163.0 on a maintainer's account", github.summary(run, "incomplete"))

    def test_controller_failure_after_complete_receipts_still_reports_incomplete(self):
        run = local_run()
        self.reports(run, candidate())

        def review(root, run, work, out, private):
            shutil.copytree(self.out, out)  # Four verified reviews, then the controller fails.
            raise runner.SafetyLimit("review reached its safety limit")

        with patch.object(local.runner, "review", side_effect=review), patch.object(local, "cleanup"):
            work, state = local.review(run)
        self.addCleanup(shutil.rmtree, work)
        self.assertEqual(state, "incomplete")
        self.assertTrue(local.verified(run, work / "reports"))
        self.assertIn("SafetyLimit", runner.read_json(work / "reports/controller.json")["error"])
        local.publish(self.api, run, work / "reports")
        self.assertIn("local run): incomplete", self.api.comments[-1]["body"])
        self.assertEqual(len(self.api.reviews), 1)  # Verified findings are still posted, as the workflow does.

    def test_head_moving_after_inline_comments_makes_the_summary_stale(self):
        run = local_run()
        self.reports(run, candidate())
        api = self.api

        def moving_call(path, data=None, method=None):
            result = type(api).call(api, path, data, method)
            if method == "POST" and path.endswith("/reviews"):
                api.target["head"]["sha"] = "c" * 40  # A push lands right after the inline review.
            return result

        with patch.object(api, "call", side_effect=moving_call):
            local.publish(api, run, self.out)
        self.assertEqual(len(api.reviews), 1)
        self.assertIn("local run): stale", api.comments[-1]["body"])

    def test_core_review_can_use_a_stronger_model_than_the_specialists(self):
        base = {"RAGU_AUDIT_MODEL": "claude-sonnet-5-5", "RAGU_AUDIT_EFFORT": "high"}
        with patch.dict(os.environ, base, clear=True):
            plain = github.model_configuration()
        with patch.dict(os.environ, {**base, "RAGU_AUDIT_CORE_MODEL": "claude-opus-5-5", "RAGU_AUDIT_CORE_EFFORT": "xhigh"}, clear=True):
            strong = github.model_configuration()
        with patch.dict(os.environ, {**base, "RAGU_AUDIT_CORE_MODEL": "gpt-6"}, clear=True):
            with self.assertRaisesRegex(ValueError, "explicit Claude model"):
                github.model_configuration()
        self.assertNotIn("core_model", plain)
        self.assertEqual((strong["core_model"], strong["core_effort"]), ("claude-opus-5-5", "xhigh"))
        plain_run, strong_run = local_run(**plain), local_run(**strong)
        self.assertEqual(runner.model_settings(strong_run, "code-review"), ("claude-opus-5-5", "xhigh"))
        self.assertEqual(runner.model_settings(strong_run, "tal-review"), ("claude-sonnet-5-5", "high"))
        self.assertEqual(runner.model_settings(plain_run, "code-review"), ("claude-sonnet-5-5", "high"))
        runner.RunBudget(strong_run)  # Both models are priced by the safety guard.
        self.assertNotIn("core", runner.reuse_key(plain_run))  # Existing checks and reusable reports keep their identity.
        self.assertEqual(runner.reuse_key(strong_run)["core"], ("claude-opus-5-5", "xhigh"))
        self.assertIn("Core review: `claude-opus-5-5` · Effort: `xhigh`", github.summary(strong_run, "incomplete"))
        self.assertNotIn("Core review", github.summary(plain_run, "incomplete"))

    def test_reviewers_are_told_their_time_budget_and_command_cap(self):
        text = runner.prompt("code-review", self.out / "work/code-review", "m" * 40, local_run(), self.out / "work/reports")
        self.assertIn(f"about {runner.REVIEW_TIMEOUT // 60} minutes", text)
        self.assertIn(f"under {runner.COMMAND_MINUTES} minutes", text)
        values = runner.environment(local_run(), self.out, "code-review", self.out / "scratch")
        self.assertEqual(values["BASH_MAX_TIMEOUT_MS"], str(runner.COMMAND_MINUTES * 60000))

    def test_publish_refuses_workflow_runs(self):
        with self.assertRaisesRegex(ValueError, "not a local run"):
            local.publish(self.api, {**local_run(), "local": False}, self.out)


if __name__ == "__main__":
    unittest.main()
