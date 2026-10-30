"""Authorize requests, bind App checks to revisions, and publish skill reports."""

import argparse
from datetime import datetime, timezone
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
from urllib.error import HTTPError
from urllib.request import Request

import runner
import findings

REPOSITORY = "tachyon-zcash/ragu"
CHECK = "ragu-audit/completed"
MARKER = "<!-- ragu-audit-summary:v2 -->"
INLINE_MARKER = "<!-- ragu-audit-inline:v1:"


class SupersededReview(ValueError):
    """A newer invocation replaced this review."""


class CancelledReview(ValueError):
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
    def __init__(self, token_name="GH_TOKEN"):
        self.token_name = token_name

    def call(self, path, data=None, method=None):
        request = Request(
            "https://api.github.com" + path,
            data=None if data is None else json.dumps(data).encode(),
            method=method,
            headers={"Authorization": "Bearer " + os.environ[self.token_name], "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        response = runner.github_response(request, timeout=45)
        return json.loads(response) if response else None  # A deletion answers 204 with no body.

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
    # requested review to the live branch tip, not that snapshot.
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
    from reuse import active
    pending = {"repository": REPOSITORY, "pr": number(value), "head": target["head"]["sha"],
               "base": target["base"]["sha"], "configuration": sha(os.environ["GITHUB_WORKFLOW_SHA"]),
               "run_id": number(os.environ["GITHUB_RUN_ID"]), "attempt": number(os.environ["GITHUB_RUN_ATTEMPT"]),
               **model_configuration()}
    if active(api, pending):
        print("This exact review is already running; retaining its existing check and summary", flush=True)
        return None
    return number(value), target["head"]["sha"]


def model_configuration():
    result = {"model": os.environ["RAGU_AUDIT_MODEL"], "effort": os.environ["RAGU_AUDIT_EFFORT"],
              "reconcile_model": os.environ.get("RAGU_AUDIT_RECONCILE_MODEL") or runner.RECONCILE_MODEL,
              "reconcile_effort": os.environ.get("RAGU_AUDIT_RECONCILE_EFFORT") or runner.RECONCILE_EFFORT}
    prefixes = ["", "reconcile_"]
    if os.environ.get("RAGU_AUDIT_CORE_MODEL") or os.environ.get("RAGU_AUDIT_CORE_EFFORT"):
        # The core review reads the whole diff and may get a stronger model than the specialists.
        result["core_model"] = os.environ.get("RAGU_AUDIT_CORE_MODEL") or result["model"]
        result["core_effort"] = os.environ.get("RAGU_AUDIT_CORE_EFFORT") or result["effort"]
        prefixes.append("core_")
    for prefix in prefixes:
        if (not re.fullmatch(r"claude-[a-z0-9.-]{1,100}", result[prefix + "model"])
                or result[prefix + "effort"] not in ("low", "medium", "high", "xhigh", "max")):
            raise ValueError("set an explicit Claude model ID and valid effort")
    return result


def scope(run):
    # Checks belong to commits. Identical code in another PR must not
    # invalidate an existing review; PR identity only selects its own comment.
    return "ragu-audit:v4:" + findings.fingerprint(runner.reuse_key(run)) + ":"


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
            for skill in runner.ROLES:
                try:
                    status = runner.read_json(out / f"{skill}.status.json")
                    if status.get("run") == run and status.get("skill") == skill and status.get("state") == "budget":
                        return "Four reviews completed; the invocation reached its safety limit. Available findings follow."
                except (OSError, ValueError, AttributeError, TypeError):
                    pass
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
                           "cleanup": "review process cleanup did not finish",
                           "budget": "the review reached its safety limit",
                           "schedule": "the job had no time left for this review"}
                if status.get("run") == run and status.get("skill") == skill and status.get("state") in reasons:
                    lines.append(f"`{skill}` did not finish: {reasons[status['state']]}.")
                    continue
            except (OSError, ValueError, AttributeError, TypeError):
                pass
            try:
                result = runner.read_json(out / f"{skill}.json")
            except (OSError, ValueError):
                lines.append(f"`{skill}` did not finish: Claude Code returned no valid result.")
                continue
            lines.append(f"`{skill}` did not finish: {runner.incomplete_reason(result)}.")
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


def verified_findings(run, out):
    bundle = runner.candidates(run, out, partial=True)
    if len(bundle["reviews"]) == len(runner.SKILLS):
        try:
            return runner.verify_reconciliation(run, out)
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return bundle, None


def diff_lines(files):
    """Return exact head-side lines GitHub exposes in the PR's diff hunks."""
    result = set()
    for file in files:
        if file.get("status") == "removed":
            continue
        line = None
        for text in file.get("patch", "").splitlines():
            header = re.match(r"^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,[0-9]+)? @@", text)
            if header:
                line = int(header[1])
            elif line is not None and text.startswith((" ", "+")):
                if line > 0:
                    result.add((file["filename"], line))
                line += 1
    return result


def anchor(locations, available):
    """Choose where a finding's inline comment goes, as `(path, line, cited)`.

    An exact cited line in the diff wins, and `cited` is then None. GitHub
    accepts comments only on lines in a diff hunk, so a finding citing a
    changed file outside its hunks moves to that file's nearest diff line and
    `cited` keeps the location its comment links. A finding citing only files
    outside the diff attaches to the first diff line of the changed file
    nearest a cited file: the longest shared directory prefix, then the
    fewest further directories, then path order. Only a diff without
    commentable lines leaves a finding unanchored, returning None.
    """
    for loc in locations:
        if (loc["path"], loc["line"]) in available:
            return loc["path"], loc["line"], None
    for loc in locations:
        lines = [line for path, line in available if path == loc["path"]]
        if lines:
            return loc["path"], min(lines, key=lambda line: (abs(line - loc["line"]), line)), loc
    if not available:
        return None

    def closeness(pair):
        loc, path = pair
        cited, changed = PurePosixPath(loc["path"]).parent.parts, PurePosixPath(path).parent.parts
        shared = next((index for index, (a, b) in enumerate(zip(cited, changed)) if a != b), min(len(cited), len(changed)))
        return shared, shared - len(changed)

    # `max` keeps the first of equals: the earliest cited location, then path order.
    loc, path = max(((loc, path) for loc in locations for path in sorted({path for path, _ in available})), key=closeness)
    return path, min(line for changed, line in available if changed == path), loc


def owns_inline(review, app):
    if not review.get("body", "").startswith(INLINE_MARKER) or review.get("user", {}).get("type") != "Bot":
        return False
    via = review.get("performed_via_github_app")
    return via.get("id") == app["id"] if via else review["user"].get("login") == app["slug"] + "[bot]"


def publish_inline(api, run, check, out):
    try:
        bundle, groups = verified_findings(run, out)
    except (OSError, ValueError, KeyError, TypeError):
        return None
    active = [item for item in (groups if groups is not None else findings.combined(bundle))
              if item["disposition"] != "dismissed"]
    publication = {"urls": [], "fallback": [], "count": 0}
    if not active:
        return publication
    path = f"/repos/{REPOSITORY}/pulls/{run['pr']}"
    # PR files track the live branch. Anchor findings to the same frozen diff
    # the reviewers read, even after new commits or changes to main.
    comparison = api.call(f"/repos/{REPOSITORY}/compare/{run['base']}...{run['head']}?per_page=1")
    available = diff_lines(comparison["files"])
    comments = []
    for item in active:
        target = anchor(item["locations"], available)
        if target is None:
            publication["fallback"].append(item)
        else:
            file, line, cited = target
            comments.append({"path": file, "line": line, "side": "RIGHT",
                             "body": findings.inline_body(bundle, item, cited)})
    if not comments:
        return publication
    reviews = list(api.pages(path + "/reviews"))
    # Batch comments to avoid one notification-producing review per finding.
    # Identity excludes invocation IDs so identical reused reports do not
    # create duplicate threads on subsequent commands for the same snapshot.
    for start in range(0, len(comments), 50):
        batch = comments[start:start + 50]
        identity = findings.fingerprint({"pr": run["pr"], "run": runner.reuse_key(run), "comments": batch})
        body = f"{INLINE_MARKER}{identity} -->\n\nRagu audit findings for `{run['head']}` against `{run['base']}`.\n\nFull reports and validation limits are linked from the audit status comment."

        def existing():
            matches = [review for review in reviews if owns_inline(review, check["app"]) and review["body"] == body]
            if len(matches) > 1:
                raise ValueError("duplicate inline reviews")
            return matches[0] if matches else None

        review = existing()
        guard(api, run)
        if review is None:
            try:
                review = api.call(path + "/reviews", {"commit_id": run["head"], "body": body,
                                                     "event": "COMMENT", "comments": batch}, "POST")
            except (OSError, ValueError):
                # Never repeat a creation after an ambiguous response. Recover
                # only the exact App-owned review and verify every comment.
                reviews = list(api.pages(path + "/reviews"))
                review = existing()
                if review is None:
                    raise
            if not any(item["id"] == review["id"] for item in reviews):
                reviews.append(review)
        if (not owns_inline(review, check["app"]) or review["body"] != body
                or review.get("commit_id") != run["head"] or review.get("state") != "COMMENTED"):
            raise ValueError("inline review publication was not confirmed")
        # The per-review comment listing omits line and side; the PR's listing has them.
        actual = [item for item in api.pages(path + "/comments")
                  if item.get("pull_request_review_id") == review["id"] and not item.get("in_reply_to_id")]
        expected = {(item["path"], item["line"], item["side"], item["body"]) for item in batch}
        # GitHub can move a comment's current line and commit, or set line to
        # None for an outdated thread. Its original location stays pinned.
        received = {(item.get("path"), item.get("original_line", item.get("line")), item.get("side"), item.get("body")) for item in actual
                    if item.get("original_commit_id", item.get("commit_id")) == run["head"] and item.get("user", {}).get("type") == "Bot"
                    and item["user"].get("login") == check["app"]["slug"] + "[bot]"}
        if len(actual) != len(batch) or received != expected:
            raise ValueError("inline review comments were not confirmed")
        publication["urls"].append(f"https://github.com/{REPOSITORY}/pull/{run['pr']}#pullrequestreview-{review['id']}")
        publication["count"] += len(batch)
    guard(api, run)
    return publication


def summary(run, state, out=None, *, inline=None):
    lines = [MARKER, invocation_marker(run), "", f"## Ragu audit: {state}", ""]
    details = [f"Head: `{run['head']}` · Base: `{run['base']}`", "",
               f"Model: `{run['model']}` · Effort: `{run['effort']}`", ""]
    if "core_model" in run:
        details += [f"Core review: `{runner.model_settings(run, runner.SKILLS[0])[0]}` · "
                    f"Effort: `{runner.model_settings(run, runner.SKILLS[0])[1]}`", ""]
    details += [f"Reconciliation: `{runner.model_settings(run, runner.RECONCILER)[0]}` · "
                f"Effort: `{runner.model_settings(run, runner.RECONCILER)[1]}`", ""]
    if state == "running":
        lines += ["Running `code-review`, then `sean-review`, `tal-review`, and `alex-review` in parallel, followed by a short reconciliation. This comment will be updated.", ""]
    else:
        names, bundle, groups = [], None, None
        if out is not None:
            try:
                bundle, groups = verified_findings(run, out)
                names = [review["reviewer"] for review in bundle["reviews"]]
            except (OSError, ValueError, KeyError, TypeError):
                pass
        revision = f"https://github.com/{REPOSITORY}/commit/{run['head']}"
        lines += [f"**{len(names)}/4 reviews completed** · [{run['head'][:8]}]({revision})", ""]
        if state == "superseded":
            lines += ["A newer audit invocation replaced this one.", ""]
        elif state == "cancelled":
            lines += ["The command comment was deleted, so this review was cancelled. Post a new `/ragu-audit` comment to start again.", ""]
        elif state == "publication failed":
            lines += ["The controller could not verify live status or confirm publication. Completion was not granted. Verified reports below remain available; inspect the workflow before retrying.", ""]
        elif state != "completed":
            if out is not None:
                lines += [incomplete_details(run, out), ""]
            lines += ["The review did not complete. Inspect the workflow and available reports, then post `/ragu-audit` to retry.", ""]
        if bundle is not None:
            if groups is None and bundle["findings"]:
                notice = ("Combined reviewer findings. Additional source checking did not complete; disputed claims remain visible."
                          if len(names) == 4 else "Combined findings from the completed reviews.")
                details += [notice, ""]
            shown = groups
            if inline is not None:
                # Findings posted inline are not repeated here: one line counts them and links the reviews.
                active = [item for item in (groups if groups is not None else findings.combined(bundle))
                          if item["disposition"] != "dismissed"]
                fixes = sum(item["disposition"] == "must-fix" for item in active)
                counts = f"**Must-fix: {fixes} · Suggestions: {len(active) - fixes}**"
                if inline["urls"]:
                    links = ", ".join(f"[review {index}]({url})" for index, url in enumerate(inline["urls"], 1))
                    noun = "finding" if inline["count"] == 1 else "findings"
                    counts += f" · {inline['count']} {noun} posted inline: {links}"
                lines += ["### For humans", "", counts, ""]
                shown = inline["fallback"]
                if shown:
                    lines += ["The reviewed diff has no commentable lines, so these findings are kept here.", ""]
            else:
                lines += ["### For humans", ""]
            # Beside the counts line, findings a diff without commentable lines leaves here need no counted headings.
            headings = inline is None
            short = findings.shortlist(bundle, shown, heading_level=4, headings=headings) if inline is None or shown else []
            if len("\n".join(short).encode()) > 54000:
                short = findings.shortlist(bundle, shown, compact=True, heading_level=4, headings=headings)
            lines += short
            if any(runner.read_json(out / f"{skill}.json").get("permission_denials") for skill in names):
                details += ["Some tool requests were blocked; see the individual reports' limitations.", ""]
            dismissed = sum(item["disposition"] == "dismissed" for item in (groups or []))
            if dismissed:
                noun = "finding group" if dismissed == 1 else "finding groups"
                details += [f"{dismissed} {noun} dismissed; reasons are in the reconciliation report in the full bundle.", ""]
        else:
            lines += ["### For humans", "", "No verified findings are available.", ""]
        if names:
            lines += ["### For agents", ""]
            # Allocate the remaining comment budget to collapsed original reports.
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


def upsert(api, run, check, state, *, out=None, only_current=False, inline=None, new=False):
    """Publish this invocation's status comment.

    A `new` invocation posts its comment below the command, where GitHub shows
    it without a reload. Earlier summaries remain available with their reports
    and links. Later states edit only this invocation's marked comment.
    """
    listing = f"/repos/{REPOSITORY}/issues/{run['pr']}/comments"
    owned = [comment for comment in api.pages(listing) if owns_comment(comment, check["app"])]
    existing = next((comment for comment in owned if invocation_marker(run) in comment["body"].splitlines()), None)
    if existing is None and not new and only_current:
        return  # Terminal cleanup edits only this invocation's existing summary.
    body = summary(run, state, out, inline=inline)
    path = f"/repos/{REPOSITORY}/issues/comments/{existing['id']}" if existing else listing
    try:
        result = api.call(path, {"body": body}, "PATCH" if existing else "POST")
    except (OSError, ValueError):
        # A creation may have succeeded before its response was lost. Confirm
        # the exact App-owned body instead of creating a duplicate comment.
        result = next((comment for comment in api.pages(listing)
                       if owns_comment(comment, check["app"]) and comment["body"] == body), None)
        if result is None:
            raise
    if not owns_comment(result, check["app"]) or result["body"] != body:
        raise ValueError("summary publication was not confirmed")


def queue(api, value, expected_head=None, comment_id=None, *, read_api=None):
    target = pr(api, value)
    if expected_head is not None and target["head"]["sha"] != sha(expected_head):
        raise ValueError("PR head moved since the request; start a fresh run")
    run = {"repository": REPOSITORY, "pr": number(value), "head": target["head"]["sha"], "base": target["base"]["sha"],
           "configuration": sha(os.environ["GITHUB_WORKFLOW_SHA"]), **model_configuration(),
           "run_id": number(os.environ["GITHUB_RUN_ID"]), "attempt": number(os.environ["GITHUB_RUN_ATTEMPT"])}
    if comment_id is not None:
        run["comment_id"] = number(comment_id)
        command_present(api, run)
    if run["configuration"] != run["base"]:
        raise ValueError("main moved since this workflow was started; start a fresh run")
    if read_api is not None:
        # Request jobs can race before either creates a check. Repeat the live
        # lookup inside the serialized publisher job, before any App writes.
        from reuse import active
        if active(read_api, run):
            print("This exact review is already running; retaining its existing check and summary", flush=True)
            return None
    run["url"] = f"https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}"
    prefix = scope(run)
    run["external_id"] = prefix + f"{run['pr']}:{run['run_id']}:{run['attempt']}"
    data = {
        "name": CHECK, "head_sha": run["head"], "external_id": run["external_id"], "details_url": run["url"],
        "status": "in_progress",
        "output": {"title": "Review running", "summary": "Four skill reviews must finish for this exact head and base. Invoke with /ragu-audit."},
    }
    if comment_id is not None:
        data["output"]["text"] = json.dumps({"comment_id": number(comment_id)})
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
        upsert(api, run, check, "running", new=True)
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
    # Branch updates do not invalidate a frozen review. A newer invocation
    # can supersede it even when the new check belongs to another head.
    owned = [comment for comment in api.pages(f"/repos/{REPOSITORY}/issues/{run['pr']}/comments")
             if owns_comment(comment, own["app"])]
    for comment in owned:
        marker = re.search(r"^<!-- ragu-audit-run:[0-9]+:[0-9]+:([0-9]+) -->$", comment["body"], re.MULTILINE)
        if marker and int(marker[1]) > run["check_id"]:
            raise SupersededReview("a newer review superseded this invocation")
    prefix = scope(run)
    if not values or not (values[0].get("external_id") or "").startswith(prefix):
        raise SupersededReview("a newer review uses a different configuration")
    latest = next((check for check in values if (check.get("external_id") or "").startswith(prefix + f"{run['pr']}:")), None)
    if latest is None or latest["id"] != run["check_id"]:
        raise SupersededReview("a newer review superseded this invocation")
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
        finish_check(api, run, False, "Review publication failed")


def publish(api, run, out, review_result):
    # Validate ownership independently of supersession so old invocations can
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
        inline = publish_inline(api, run, check, out)
        upsert(api, run, check, "completed" if success else "incomplete", out=out, inline=inline)
        guard(api, run)  # Recheck after reading artifacts and publishing.
        finish_check(api, run, success, "Four skill reviews completed" if success else "Review incomplete")
    except CancelledReview:
        try:
            upsert(api, run, check, "cancelled", out=out, only_current=True)
        finally:
            finish_check(api, run, False, "Review cancelled: command comment deleted", cancelled=True)
        raise
    except SupersededReview:
        try:
            upsert(api, run, check, "superseded", out=out, only_current=True)
        finally:
            finish_check(api, run, False, "Review superseded by a newer invocation")
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
        run = queue(api, args.pr, args.head, args.comment_id, read_api=GitHub("GH_READ_TOKEN"))
        if run is None:
            return
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
