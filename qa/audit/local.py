"""Run the Ragu audit with your own Claude login instead of the workflow's API key.

`run` reviews a PR with the workflow's passes, sandbox, and reconciliation, and
writes the summary the bot would post. `publish` posts the same inline findings
and summary from your GitHub account. Without the App, no completion check is
recorded.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import github
import runner

ROOT = Path(__file__).resolve().parents[2]
# What the reviewers trust from this checkout; the receipt records its revision.
TRUSTED = (".claude/code-review", ".claude/review-shared", "qa/audit", *(f".claude/skills/{skill}" for skill in runner.SKILLS))
# The workflow's configured models; the same RAGU_AUDIT_* variables override them.
DEFAULTS = {"RAGU_AUDIT_MODEL": "claude-sonnet-5-5", "RAGU_AUDIT_EFFORT": "high"}


def client():
    """GitHub access as the maintainer, held by this process only.

    The runner's environment allowlist keeps the token away from reviewers.
    """
    if not os.environ.get("GH_TOKEN"):
        os.environ["GH_TOKEN"] = subprocess.check_output(["gh", "auth", "token"], text=True, timeout=30).strip()
    return github.GitHub()


def start(api, pr, head=None):
    target = github.pr(api, pr)  # Open and targeting main; base is main's live tip.
    if head is not None and target["head"]["sha"] != head:
        raise ValueError(f"PR head is {target['head']['sha']}, not {head}")
    if runner.git(ROOT, "status", "--porcelain", "--", *TRUSTED):
        raise ValueError("commit or stash changes to the review skills, policies, or controller; "
                         "the run records their revision")
    executable = shutil.which("claude")
    if executable is None:
        raise ValueError("Claude Code is not on PATH")
    version = subprocess.check_output([str(Path(executable).resolve()), "--version"], text=True, timeout=30)
    for key, value in DEFAULTS.items():
        os.environ.setdefault(key, value)
    run = {"repository": github.REPOSITORY, "pr": github.number(pr), "head": target["head"]["sha"],
           "base": target["base"]["sha"], "configuration": runner.git(ROOT, "rev-parse", "HEAD"),
           **github.model_configuration(), "local": True, "claude_version": version.split()[0]}
    if run["configuration"] != run["base"]:
        print(f"Skills and policies come from {run['configuration']}, not main's tip {run['base']}.", file=sys.stderr)
    return run


def verified(run, out):
    try:
        runner.verify(run, out)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def cleanup(work):
    """Remove the review worktrees and Cargo home; keep the reports."""
    for role in runner.ROLES:
        if (work / role).exists():
            try:
                runner.git(ROOT, "worktree", "remove", "--force", str(work / role))
            except subprocess.SubprocessError:
                print(f"Could not remove the worktree at {work / role}", file=sys.stderr)
    shutil.rmtree(work / "cargo", ignore_errors=True)


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
    finally:
        cleanup(work)
    state = "completed" if verified(run, out) else "incomplete"
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
        state = "completed" if verified(run, out) else "incomplete"
        inline = github.publish_inline(api, run, author, out, live)
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
    start_parser.add_argument("pr")
    start_parser.add_argument("--head", type=github.sha, help="fail unless the PR is at this commit")
    publish_parser = commands.add_parser("publish", help="post a finished run's findings to its PR")
    publish_parser.add_argument("work", type=Path, help="directory printed by `run`")
    args = parser.parse_args()
    api = client()
    if args.command == "run":
        work, state = review(start(api, args.pr, args.head))
        print(f"Review {state}. Reports: {work / 'reports'}")
        print(f"Summary preview: {work / 'comment.md'}")
        print(f"Publish with: python3 {Path(__file__).resolve()} publish {work}")
    else:
        work = args.work.resolve()
        result = publish(api, runner.read_json(work / "run.json"), work / "reports")
        print(f"Posted: {result.get('html_url', 'summary comment')}")


if __name__ == "__main__":
    main()
