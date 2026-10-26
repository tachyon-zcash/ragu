"""Authorize requests, bind App checks to revisions, and publish skill reports."""

import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request

import runner
import findings

REPOSITORY = "tachyon-zcash/ragu"
CHECK = "ragu-audit/completed"
MARKER = "<!-- ragu-audit-summary:v2 -->"


class StaleReview(ValueError):
    """A valid invocation whose snapshot or place in the queue has changed."""


class CancelledReview(StaleReview):
    """The maintainer removed the comment that invoked this review."""


def command_present(api, run):
    if "comment_id" not in run:
        return
    try:
        comment = api.call(f"/repos/{REPOSITORY}/issues/comments/{number(run['comment_id'])}")
    except HTTPError as error:
        if error.code == 404:
            raise CancelledReview("trigger comment deleted") from None
        raise
    if comment["issue_url"] != f"https://api.github.com/repos/{REPOSITORY}/issues/{number(run['pr'])}":
        raise ValueError("trigger comment belongs to a different PR")


class GitHub:
    def call(self, path, data=None, method=None):
        request = Request(
            "https://api.github.com" + path,
            data=None if data is None else json.dumps(data).encode(),
            method=method,
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        return json.loads(runner.github_response(request, timeout=45))

    def pages(self, path, key=None):
        for page in range(1, 21):
            response = self.call(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
            values = response[key] if key else response
            yield from values
            if len(values) < 100:
                return
        raise ValueError("GitHub pagination limit reached")


def number(value):
    if not re.fullmatch(r"[1-9][0-9]{0,19}", str(value)):
        raise ValueError("invalid pull request number")
    return int(value)


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("invalid Git revision")
    return value


def output(**values):
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def pr(api, value):
    result = api.call(f"/repos/{REPOSITORY}/pulls/{number(value)}")
    if result["state"] != "open" or result["base"]["repo"]["full_name"] != REPOSITORY or result["base"]["ref"] != "main":
        raise ValueError("review requires an open Ragu PR targeting main")
    # PR metadata can retain an older base.sha after main advances. Bind the
    # review and freshness checks to the live branch tip, not that snapshot.
    result["base"]["sha"] = sha(api.call(f"/repos/{REPOSITORY}/git/ref/heads/main")["object"]["sha"])
    sha(result["head"]["sha"])
    return result


def can_request(api, login):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login):
        return False
    return api.call(f"/repos/{REPOSITORY}/collaborators/{login}/permission").get("permission") in ("admin", "maintain", "write")


def request(api, event, event_name):
    if event_name != "issue_comment":
        return None
    if not event.get("issue", {}).get("pull_request") or event.get("comment", {}).get("body", "") != "/ragu-audit":
        return None
    comment_id = number(event["comment"]["id"])
    comment = api.call(f"/repos/{REPOSITORY}/issues/comments/{comment_id}")
    if comment.get("body", "") != "/ragu-audit" or comment["user"]["type"] != "User":
        return None
    if comment["user"]["login"] != event["comment"]["user"]["login"] or comment["issue_url"] != f"https://api.github.com/repos/{REPOSITORY}/issues/{number(event['issue']['number'])}":
        raise ValueError("comment identity changed")
    if not can_request(api, comment["user"]["login"]):
        return None
    for login in {os.environ["GITHUB_ACTOR"], os.environ["GITHUB_TRIGGERING_ACTOR"]}:
        if not can_request(api, login):
            return None
    value = event["issue"]["number"]
    target = pr(api, value)
    return number(value), target["head"]["sha"]


def scope(run):
    # Checks belong to commits. Identical code in another PR must not
    # invalidate an existing review; PR identity only selects its own comment.
    values = {key: run[key] for key in ("repository", "head", "base", "configuration", "model", "effort")}
    return "ragu-audit:v3:" + hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest() + ":"


def checks(api, head, app_id):
    values = api.pages(f"/repos/{REPOSITORY}/commits/{sha(head)}/check-runs?check_name={CHECK}&filter=all", "check_runs")
    return sorted((check for check in values if check["name"] == CHECK and str(check["app"]["id"]) == str(app_id)), key=lambda check: check["id"], reverse=True)


def owns_comment(comment, app):
    if not comment.get("body", "").startswith(MARKER + "\n") or comment.get("user", {}).get("type") != "Bot":
        return False
    via = comment.get("performed_via_github_app")
    return via.get("id") == app["id"] if via else comment["user"].get("login") == app["slug"] + "[bot]"


def excerpt(text, size=9000):
    text = html.escape(text, quote=False).replace("@", "&#64;").replace("![", "[")
    if len(text.encode()) > size:
        return text.encode()[:size].decode("utf-8", errors="ignore") + "\n\nContinued in the report artifact."
    return text


def incomplete_details(run, out):
    try:
        receipt = runner.verify(run, out, partial=True)
        phases = receipt["phases"]
        names = [phase["skill"] for phase in phases]
        if len(names) == len(runner.SKILLS):
            return "The review job failed after recording all four passes. Inspect the workflow."
        missing = [skill for skill in runner.SKILLS if skill not in names] if names else [runner.SKILLS[0]]
        lines = []
        for skill in missing:
            if skill in receipt["unavailable"]:
                lines.append(f"Could not verify the recovered `{skill}` report; its findings are omitted. Inspect the workflow artifacts.")
                continue
            try:
                status = runner.read_json(out / f"{skill}.status.json")
                reasons = {"timeout": "the review reached its time limit", "cancelled": "the review was cancelled",
                           "exit": "Claude Code exited unsuccessfully", "protocol": "Claude Code returned an invalid event stream",
                           "cleanup": "review process cleanup did not finish"}
                if status.get("run") == run and status.get("skill") == skill and status.get("state") in reasons:
                    lines.append(f"Stopped during `{skill}`: {reasons[status['state']]}.")
                    continue
            except (OSError, ValueError, AttributeError, TypeError):
                pass
            try:
                result = runner.read_json(out / f"{skill}.json")
            except (OSError, ValueError):
                lines.append(f"Stopped during `{skill}` before Claude Code returned a valid result.")
                continue
            lines.append(f"Stopped during `{skill}`: {runner.incomplete_reason(result)}.")
        return "\n\n".join(lines)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return "The review job failed without a verifiable phase result. Inspect the workflow."


def invocation_marker(run):
    return f"<!-- ragu-audit-run:{number(run['run_id'])}:{number(run['attempt'])}:{number(run['check_id'])} -->"


def review_excerpt(text, size):
    # Verified reports already escape HTML, mentions, and images. Quote every
    # line so even an unfinished Markdown fence stays inside its own report.
    text = "\n".join("> " + line for line in text.splitlines())
    if len(text.encode()) > size:
        return text.encode()[:size].decode("utf-8", errors="ignore") + "\n>\n> Continued in the full report linked below."
    return text


def summary(run, state, out=None):
    lines = [MARKER, invocation_marker(run), "", f"## Ragu audit: {state}", ""]
    details = [f"Head: `{run['head']}` · Base: `{run['base']}`", "",
               f"Model: `{run['model']}` · Effort: `{run['effort']}`", ""]
    if state == "running":
        lines += ["Running `code-review`, then `sean-review`, `tal-review`, and `alex-review` in parallel, followed by a short reconciliation. This comment will be updated.", ""]
    else:
        names, bundle, groups = [], None, None
        if out is not None:
            try:
                bundle = runner.candidates(run, out, partial=True)
                names = [review["reviewer"] for review in bundle["reviews"]]
            except (OSError, ValueError, KeyError, TypeError):
                pass
        revision = f"https://github.com/{REPOSITORY}/commit/{run['head']}"
        lines += [f"**{len(names)}/4 reviews completed** · [{run['head'][:8]}]({revision})", ""]
        if state == "stale":
            lines += ["This invocation is stale: the PR changed, closed, or a newer review replaced it. Findings apply only to the snapshot in Run details. Post `/ragu-audit` on the current PR revision to review again.", ""]
        elif state == "cancelled":
            lines += ["The command comment was deleted, so this review was cancelled. Post a new `/ragu-audit` comment to start again.", ""]
        elif state == "publication failed":
            lines += ["The controller could not verify live status or confirm publication. Completion was not granted. Verified reports below remain available; inspect the workflow before retrying.", ""]
        elif state != "completed":
            if out is not None:
                lines += [incomplete_details(run, out), ""]
            lines += ["The review did not complete. Inspect the workflow and available reports, then post `/ragu-audit` to retry.", ""]
        if names == list(runner.SKILLS):
            try:
                bundle, groups = runner.verify_reconciliation(run, out)
            except (OSError, ValueError, KeyError, TypeError):
                pass
        lines += ["### For humans", ""]
        if bundle is not None:
            if groups is None and bundle["findings"]:
                notice = ("Combined reviewer findings. Additional source checking did not complete; disputed claims remain visible."
                          if len(names) == 4 else "Combined findings from the completed reviews.")
                details += [notice, ""]
            short = findings.shortlist(bundle, groups, heading_level=4)
            if len("\n".join(short).encode()) > 54000:
                short = findings.shortlist(bundle, groups, compact=True, heading_level=4)
            lines += short
            if any(runner.read_json(out / f"{skill}.json").get("permission_denials") for skill in names):
                details += ["Some tool requests were blocked; see the individual reports' limitations.", ""]
            dismissed = sum(item["disposition"] == "dismissed" for item in (groups or []))
            if dismissed:
                noun = "finding group" if dismissed == 1 else "finding groups"
                details += [f"{dismissed} {noun} dismissed; reasons are in the reconciliation report in the full bundle.", ""]
        else:
            lines += ["No verified findings are available.", ""]
        if names:
            lines += ["### For agents", ""]
            # Preserve every confirmed defect in the top shortlist, allocating
            # the remaining comment budget to the collapsed original reports.
            size = min(12000, max(0, 60000 - len("\n".join(lines).encode()) - 4000) // len(names))
            for skill in names:
                variable = "RAGU_AUDIT_REPORT_" + skill.upper().replace("-", "_")
                url = os.environ.get(variable, "")
                expected = rf"https://github\.com/{REPOSITORY}/actions/runs/{run['run_id']}/artifacts/[1-9][0-9]*"
                if not re.fullmatch(expected, url):
                    url = run["url"]
                text = review_excerpt((out / f"{skill}.md").read_text(), size)
                label = findings.REVIEWER_NAMES[skill]
                lines += [f"<details><summary>{label}</summary>", "", text, "",
                          f"[Full report]({url})", "", "</details>", ""]
        details += ["Original reports and reconciliation decisions are retained in the workflow artifacts.", "",
                    "Maintainers assess findings and approve changes.", ""]
    lines += ["---", "", "<details><summary>Run details</summary>", "", *details,
              f"[Workflow and complete reports]({run['url']})", "", "</details>"]
    return "\n".join(lines)


def upsert(api, run, check, state, *, out=None, only_current=False):
    comments = api.pages(f"/repos/{REPOSITORY}/issues/{run['pr']}/comments")
    existing = next((comment for comment in comments if owns_comment(comment, check["app"])), None)
    if only_current and (existing is None or invocation_marker(run) not in existing["body"].splitlines()):
        return  # An older invocation must never replace a newer summary.
    body = summary(run, state, out)
    path = f"/repos/{REPOSITORY}/issues/comments/{existing['id']}" if existing else f"/repos/{REPOSITORY}/issues/{run['pr']}/comments"
    try:
        result = api.call(path, {"body": body}, "PATCH" if existing else "POST")
    except (OSError, ValueError):
        # A creation may have succeeded before its response was lost. Confirm
        # the exact App-owned body instead of creating a duplicate comment.
        result = next((comment for comment in api.pages(f"/repos/{REPOSITORY}/issues/{run['pr']}/comments")
                       if owns_comment(comment, check["app"]) and comment["body"] == body), None)
        if result is None:
            raise
    if not owns_comment(result, check["app"]) or result["body"] != body:
        raise ValueError("summary publication was not confirmed")


def queue(api, value, expected_head=None, comment_id=None):
    target = pr(api, value)
    if expected_head is not None and target["head"]["sha"] != sha(expected_head):
        raise ValueError("PR head moved since the request; start a fresh run")
    model, effort = os.environ["RAGU_AUDIT_MODEL"], os.environ["RAGU_AUDIT_EFFORT"]
    if not re.fullmatch(r"claude-[a-z0-9.-]{1,100}", model) or effort not in ("low", "medium", "high", "xhigh", "max"):
        raise ValueError("set an explicit Claude model ID and effort")
    run = {"repository": REPOSITORY, "pr": number(value), "head": target["head"]["sha"], "base": target["base"]["sha"],
           "configuration": sha(os.environ["GITHUB_WORKFLOW_SHA"]), "model": model, "effort": effort,
           "run_id": number(os.environ["GITHUB_RUN_ID"]), "attempt": number(os.environ["GITHUB_RUN_ATTEMPT"])}
    if comment_id is not None:
        run["comment_id"] = number(comment_id)
        command_present(api, run)
    if run["configuration"] != run["base"]:
        raise ValueError("main moved since this workflow was started; start a fresh run")
    run["url"] = f"https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}"
    prefix = scope(run)
    run["external_id"] = prefix + f"{run['pr']}:{run['run_id']}:{run['attempt']}"
    data = {
        "name": CHECK, "head_sha": run["head"], "external_id": run["external_id"], "details_url": run["url"],
        "status": "in_progress",
        "output": {"title": "Review running", "summary": "Four skill reviews must finish for this exact head and base. Invoke with /ragu-audit."},
    }
    try:
        check = api.call(f"/repos/{REPOSITORY}/check-runs", data, "POST")
    except (OSError, ValueError):
        matches = [check for check in checks(api, run["head"], os.environ["RAGU_AUDIT_APP_ID"])
                   if check.get("external_id") == run["external_id"]]
        if len(matches) != 1:
            raise
        check = matches[0]
    if str(check["app"]["id"]) != os.environ["RAGU_AUDIT_APP_ID"] or check["head_sha"] != run["head"]:
        raise ValueError("check was not published by the configured App")
    run["check_id"] = check["id"]
    run["app_id"] = check["app"]["id"]
    try:
        upsert(api, run, check, "running")
    except (OSError, ValueError):
        publication_failure(api, run, check)
        raise
    return run


def validate_identity(run):
    if not isinstance(run, dict):
        raise ValueError("invalid run identity")
    sha(run["head"])
    sha(run["base"])
    for key in ("pr", "run_id", "attempt", "check_id", "app_id"):
        number(run[key])
    if run["repository"] != REPOSITORY or run["configuration"] != sha(os.environ["GITHUB_WORKFLOW_SHA"]):
        raise ValueError("run identity does not match the trusted controller")
    if str(run["run_id"]) != os.environ["GITHUB_RUN_ID"] or str(run["attempt"]) != os.environ["GITHUB_RUN_ATTEMPT"]:
        raise ValueError("run identity does not match this workflow attempt")
    expected = scope(run) + f"{number(run['pr'])}:{number(run['run_id'])}:{number(run['attempt'])}"
    if run["external_id"] != expected or str(run["app_id"]) != os.environ["RAGU_AUDIT_APP_ID"]:
        raise ValueError("invalid check identity")


def own_check(api, run):
    validate_identity(run)
    expected = run["external_id"]
    values = checks(api, run["head"], os.environ["RAGU_AUDIT_APP_ID"])
    own = next((check for check in values if check["id"] == run["check_id"]), None)
    if own is None or own.get("external_id") != expected:
        raise ValueError("invocation does not own this App check")
    return own, values


def guard(api, run):
    own, values = own_check(api, run)
    command_present(api, run)
    try:
        target = pr(api, run["pr"])
    except ValueError as error:
        raise StaleReview("PR is no longer eligible for this review") from error
    if (target["head"]["sha"], target["base"]["sha"]) != (run["head"], run["base"]):
        raise StaleReview("PR head or base moved during review")
    prefix = scope(run)
    if not values or not values[0].get("external_id", "").startswith(prefix):
        raise StaleReview("a newer review uses a different configuration")
    latest = next((check for check in values if check.get("external_id", "").startswith(prefix + f"{run['pr']}:")), None)
    if latest is None or latest["id"] != run["check_id"]:
        raise StaleReview("a newer review superseded this invocation")
    return own


def finish_check(api, run, success, title, *, cancelled=False):
    api.call(f"/repos/{REPOSITORY}/check-runs/{run['check_id']}", {
        "status": "completed", "conclusion": "cancelled" if cancelled else "success" if success else "failure",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "output": {"title": title,
                   "summary": f"Reviewed head {run['head']} against base {run['base']}. Full findings and validation limits: {run['url']}"},
    }, "PATCH")


def publication_failure(api, run, check, out=None):
    try:
        upsert(api, run, check, "publication failed", out=out, only_current=True)
    except (OSError, ValueError, KeyError, TypeError):
        print("Could not publish terminal summary; see workflow", flush=True)
    finally:
        finish_check(api, run, False, "Summary publication failed")


def publish(api, run, out, review_result):
    # Validate ownership independently of freshness so stale invocations can
    # terminate their own check without gaining access to a newer invocation.
    check, _ = own_check(api, run)
    success = False
    try:
        guard(api, run)
        try:
            if review_result != "success":
                raise ValueError("review job did not succeed")
            runner.verify(run, out)
            success = True
        except (OSError, ValueError, KeyError, TypeError):
            print("Review incomplete; see verified phase reports and diagnostics", flush=True)
        upsert(api, run, check, "completed" if success else "incomplete", out=out)
        guard(api, run)  # Recheck after reading artifacts and publishing.
        finish_check(api, run, success, "Four skill reviews completed" if success else "Review incomplete")
    except CancelledReview:
        try:
            upsert(api, run, check, "cancelled", out=out, only_current=True)
        finally:
            finish_check(api, run, False, "Review cancelled: command comment deleted", cancelled=True)
        raise
    except StaleReview:
        try:
            upsert(api, run, check, "stale", out=out, only_current=True)
        finally:
            finish_check(api, run, False, "Review stale; invoke again on the current revision")
        raise
    except (OSError, ValueError, KeyError, TypeError):
        publication_failure(api, run, check, out)
        raise
    if not success:
        raise ValueError("audit did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("request", "queue", "restore", "publish"))
    parser.add_argument("--pr")
    parser.add_argument("--head", type=sha)
    parser.add_argument("--comment-id", type=number)
    parser.add_argument("--run", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--review-result")
    args = parser.parse_args()
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or os.environ["GITHUB_REF"] != "refs/heads/main":
        raise ValueError("audit controller only runs on Ragu main")
    if args.command == "restore":
        # Public invocation metadata travels as a job output, independently of
        # artifact storage. The artifact remains a fallback if outputs are lost.
        control = os.environ.get("RAGU_AUDIT_CONTROL", "")
        if len(control) > 16384:
            raise ValueError("run identity is too large")
        run = json.loads(control) if control else runner.read_json(args.run)
        validate_identity(run)
        args.run.parent.mkdir(parents=True, exist_ok=True)
        runner.write_json(args.run, run)
        return
    api = GitHub()
    if args.command == "request":
        result = request(api, runner.read_json(os.environ["GITHUB_EVENT_PATH"]), os.environ["GITHUB_EVENT_NAME"])
        if result:
            output(pr=result[0], head=result[1])
    elif args.command == "queue":
        if args.head is None or args.comment_id is None:
            raise ValueError("queue requires the head and comment captured by the request job")
        run = queue(api, args.pr, args.head, args.comment_id)
        output(head=run["head"], control=json.dumps(run, separators=(",", ":")))
        try:
            args.run.parent.mkdir(parents=True, exist_ok=True)
            runner.write_json(args.run, run)
        except OSError:
            print("Control artifact unavailable; request identity is retained in job output", flush=True)
    else:
        publish(api, runner.read_json(args.run), args.out, args.review_result)


if __name__ == "__main__":
    main()
