"""Run the Ragu audit with your own Claude or Codex login instead of the workflow's API key.

`run` reviews a PR with the workflow's passes, sandbox, and reconciliation, and
writes the summary the bot would post. `publish` posts the same inline findings
and summary from your GitHub account. Without the App, no completion check is
recorded. The workflow itself always reviews with Claude Code.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

import github
import runner

ROOT = Path(__file__).resolve().parents[2]
# What the reviewers trust from this checkout; the receipt records its revision.
TRUSTED = (".claude/code-review", ".claude/review-shared", "qa/audit", *(f".claude/skills/{skill}" for skill in runner.SKILLS))
BACKENDS = ("claude", "codex")
# The workflow's configured Claude models; the same RAGU_AUDIT_* variables override them.
DEFAULTS = {"RAGU_AUDIT_MODEL": "claude-sonnet-5-5", "RAGU_AUDIT_EFFORT": "high"}
EFFORTS = ("low", "medium", "high", "xhigh", "max")


def client():
    """GitHub access as the maintainer, held by this process only.

    The token goes to the client rather than into the environment, so neither
    the reviewers (an allowlisted environment) nor this process's own git
    subprocesses inherit it.
    """
    token = os.environ.get("GH_TOKEN")
    if not token:
        try:
            token = subprocess.check_output(["gh", "auth", "token"], text=True, timeout=30).strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("GitHub access needs `gh auth login` or GH_TOKEN") from error
    return github.GitHub(token=token)


def pr_number(value):
    """Accept `921`, `#921`, or the pull request's URL."""
    match = re.fullmatch(rf"(?:https://github\.com/{re.escape(github.REPOSITORY)}/pull/|#)?([0-9]+)/?", value.strip())
    if match is None:
        raise argparse.ArgumentTypeError(f"not a Ragu pull request number: {value}")
    return match.group(1)


def codex_default_model():
    """The maintainer's own Codex default; the reviewers ignore that configuration otherwise."""
    path = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "config.toml"
    try:
        model = tomllib.loads(path.read_text()).get("model")
    except (OSError, ValueError):
        model = None
    if not isinstance(model, str) or not model:
        raise ValueError("set RAGU_AUDIT_MODEL to a Codex model, or `model` in ~/.codex/config.toml")
    return model


def codex_models():
    """Model settings for a Codex run: the default model at the bot's effort unless overridden."""
    default = os.environ.get("RAGU_AUDIT_MODEL") or codex_default_model()
    result = {"model": default, "effort": os.environ.get("RAGU_AUDIT_EFFORT") or "high",
              "reconcile_model": os.environ.get("RAGU_AUDIT_RECONCILE_MODEL") or default,
              "reconcile_effort": os.environ.get("RAGU_AUDIT_RECONCILE_EFFORT") or "high"}
    prefixes = ["", "reconcile_"]
    if os.environ.get("RAGU_AUDIT_CORE_MODEL") or os.environ.get("RAGU_AUDIT_CORE_EFFORT"):
        result["core_model"] = os.environ.get("RAGU_AUDIT_CORE_MODEL") or default
        result["core_effort"] = os.environ.get("RAGU_AUDIT_CORE_EFFORT") or result["effort"]
        prefixes.append("core_")
    for prefix in prefixes:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,99}", result[prefix + "model"]) or result[prefix + "effort"] not in EFFORTS:
            raise ValueError("set a Codex model ID and an effort of low, medium, high, xhigh, or max")
    return result


def start(api, pr, head=None, backend="claude"):
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {', '.join(BACKENDS)}")
    target = github.pr(api, pr)  # Open and targeting main; base is main's live tip.
    if head is not None and target["head"]["sha"] != head:
        raise ValueError(f"PR head is {target['head']['sha']}, not {head}")
    if runner.git(ROOT, "status", "--porcelain", "--", *TRUSTED):
        raise ValueError("commit or stash changes to the review skills, policies, or controller; "
                         "the run records their revision")
    origin = runner.git(ROOT, "remote", "get-url", "origin")
    if not re.fullmatch(rf"(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:){re.escape(github.REPOSITORY)}(?:\.git)?/?", origin):
        raise ValueError(f"origin is {origin}; the run fetches the PR from github.com/{github.REPOSITORY}")
    executable = shutil.which(backend)
    if executable is None:
        raise ValueError(f"{backend} is not on PATH")
    version = subprocess.check_output([str(Path(executable).resolve()), "--version"], text=True, timeout=30)
    if backend == "codex":
        models = codex_models()
    else:
        for key, value in DEFAULTS.items():
            os.environ.setdefault(key, value)
        models = github.model_configuration()
    run = {"repository": github.REPOSITORY, "pr": github.number(pr), "head": target["head"]["sha"],
           "base": target["base"]["sha"], "configuration": runner.git(ROOT, "rev-parse", "HEAD"),
           **models, "local": True, "backend": backend, "cli_version": runner.installed_version(version)}
    if run["configuration"] != run["base"]:
        print(f"Skills and policies come from {run['configuration']}, not main's tip {run['base']}.", file=sys.stderr)
    return run


def verified(run, out):
    try:
        runner.verify(run, out)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def outcome(run, out):
    """Completed only if the controller finished and all four reviews verify, as the workflow requires."""
    return "completed" if not (out / "controller.json").exists() and verified(run, out) else "incomplete"


def cleanup(work, run):
    """Remove the review worktrees, Cargo home, and session directories; keep the reports."""
    for role in runner.ROLES:
        if (work / role).exists():
            try:
                runner.git(ROOT, "worktree", "remove", "--force", str(work / role))
            except subprocess.SubprocessError:
                print(f"Could not remove the worktree at {work / role}", file=sys.stderr)
    shutil.rmtree(work / "cargo", ignore_errors=True)
    if runner.backend(run) == "claude":
        # Claude Code spilled oversized tool outputs here; nothing else is kept.
        project = Path.home() / ".claude" / "projects" / runner.project_slug(ROOT)
        for role in runner.ROLES:
            shutil.rmtree(project / runner.session_id(work, role), ignore_errors=True)


def review(run):
    work = Path(tempfile.mkdtemp(prefix=f"ragu-audit-{run['pr']}-", dir="/tmp")).resolve()
    out = work / "reports"
    runner.write_json(work / "run.json", run)
    # A fresh Cargo home per run, as in the workflow, never the maintainer's own.
    os.environ.pop("CARGO_HOME", None)
    try:
        runner.review(ROOT, run, work, out, None)
    except Exception as error:  # Summarize whichever passes still verify.
        print(f"Review incomplete: {error}", file=sys.stderr)
        out.mkdir(parents=True, exist_ok=True)
        runner.write_json(out / "controller.json", {"error": f"{type(error).__name__}: {error}"[:500]})
    finally:
        cleanup(work, run)
    state = outcome(run, out)
    (work / "comment.md").write_text(github.summary(run, state, out))
    return work, state


def live(api, run):
    """Inline comments anchor to the reviewed head, so it must still be current.

    Unlike the workflow, a moved main does not make a local review stale: there
    is no completion check to protect, and the summary names the reviewed base.
    """
    try:
        target = github.pr(api, run["pr"])
    except ValueError as error:
        raise github.StaleReview("PR is no longer open against main") from error
    if target["head"]["sha"] != run["head"]:
        raise github.StaleReview("PR head moved since the review")


def publish(api, run, out):
    """Post inline findings and the summary, replacing your earlier local summary."""
    if not run.get("local"):
        raise ValueError("not a local run")
    author = {"login": api.call("/user")["login"]}
    try:
        live(api, run)
        state = outcome(run, out)
        inline = github.publish_inline(api, run, author, out, live)
        live(api, run)  # The summary describes a head that must still be current.
    except github.StaleReview as error:
        print(f"{error}; posting the summary without inline comments", file=sys.stderr)
        state, inline = "stale", None
    body = github.summary(run, state, out, inline=inline)
    path = f"/repos/{github.REPOSITORY}/issues/{github.number(run['pr'])}/comments"
    existing = next((comment for comment in api.pages(path)
                     if comment.get("body", "").startswith(github.LOCAL_MARKER + "\n")
                     and github.authored(comment, author)), None)
    if existing is None:
        return api.call(path, {"body": body}, "POST")
    return api.call(f"/repos/{github.REPOSITORY}/issues/comments/{github.number(existing['id'])}", {"body": body}, "PATCH")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    start_parser = commands.add_parser("run", help="review a PR; posts nothing")
    start_parser.add_argument("pr", type=pr_number, help="number, #number, or URL")
    start_parser.add_argument("--head", type=github.sha, help="fail unless the PR is at this commit")
    start_parser.add_argument("--backend", choices=BACKENDS, default="claude", help="review with Claude Code (default) or Codex CLI")
    publish_parser = commands.add_parser("publish", help="post a finished run's findings to its PR")
    publish_parser.add_argument("work", type=Path, help="directory printed by `run`")
    args = parser.parse_args()
    try:
        api = client()
        if args.command == "run":
            work, state = review(start(api, args.pr, args.head, args.backend))
            print(f"Review {state}. Reports: {work / 'reports'}")
            print(f"Summary preview: {work / 'comment.md'}")
            print(f"Publish with: python3 {Path(__file__).resolve()} publish {work}")
        else:
            work = args.work.resolve()
            result = publish(api, runner.read_json(work / "run.json"), work / "reports")
            print(f"Posted: {result.get('html_url', 'summary comment')}")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"error: {error}")


if __name__ == "__main__":
    main()
