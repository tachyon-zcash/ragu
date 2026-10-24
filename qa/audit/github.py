"""Authorize requests, bind App checks to revisions, and publish skill reports."""

import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
from urllib.request import Request, urlopen

import runner

REPOSITORY = "tachyon-zcash/ragu"
CHECK = "ragu-audit/completed"
MARKER = "<!-- ragu-audit-summary:v2 -->"


class GitHub:
    def call(self, path, data=None, method=None):
        request = Request(
            "https://api.github.com" + path,
            data=None if data is None else json.dumps(data).encode(),
            method=method,
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
        )
        with urlopen(request, timeout=45) as response:
            return json.load(response)

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
    sha(result["base"]["sha"])
    sha(result["head"]["sha"])
    return result


def can_request(api, login):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login):
        return False
    return api.call(f"/repos/{REPOSITORY}/collaborators/{login}/permission").get("permission") in ("admin", "maintain", "write")


def request(api, event, event_name):
    execute = event_name in ("issue_comment", "workflow_dispatch")
    if event_name == "issue_comment":
        if not event.get("issue", {}).get("pull_request") or event.get("comment", {}).get("body", "").strip() != "/ragu-audit":
            return None
        comment_id = number(event["comment"]["id"])
        comment = api.call(f"/repos/{REPOSITORY}/issues/comments/{comment_id}")
        if comment.get("body", "").strip() != "/ragu-audit" or comment["user"]["type"] != "User":
            return None
        if comment["user"]["login"] != event["comment"]["user"]["login"] or comment["issue_url"] != f"https://api.github.com/repos/{REPOSITORY}/issues/{number(event['issue']['number'])}":
            raise ValueError("comment identity changed")
        if not can_request(api, comment["user"]["login"]):
            return None
        value = event["issue"]["number"]
    elif event_name == "workflow_dispatch":
        value = event["inputs"]["pull_request"]
    elif event_name == "pull_request_target":
        if event.get("action") == "edited" and "base" not in event.get("changes", {}):
            return None
        value = event["number"]
    else:
        return None
    if execute:
        for login in {os.environ["GITHUB_ACTOR"], os.environ["GITHUB_TRIGGERING_ACTOR"]}:
            if not can_request(api, login):
                return None
    pr(api, value)
    return number(value), execute


def scope(run):
    values = {key: run[key] for key in ("repository", "pr", "head", "base", "configuration", "model", "effort")}
    return "ragu-audit:v2:" + hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest() + ":"


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


def summary(run, state, out=None):
    lines = [MARKER, "", f"## Ragu audit: {state}", "", f"Head: `{run['head']}` · Base: `{run['base']}`", "",
             f"Model: `{run['model']}` · Effort: `{run['effort']}`", "", f"[Workflow and complete reports]({run['url']})", ""]
    if state == "completed":
        for skill in runner.SKILLS:
            lines += [f"<details><summary>{skill}</summary>", "", excerpt((out / f"{skill}.md").read_text()), "", "</details>", ""]
        lines += ["All four review passes completed. Maintainers assess findings and approve changes."]
    elif state == "running":
        lines += ["Running `code-review` → `sean-review` → `tal-review` → `alex-review`. This comment will be updated."]
    elif state == "required":
        lines += ["This revision needs a fresh review. A maintainer can post `/ragu-audit` to start it."]
    else:
        lines += ["The review did not complete. Inspect the workflow and available reports, then post `/ragu-audit` to retry."]
    return "\n".join(lines)


def upsert(api, run, check, state, *, create, out=None):
    comments = api.pages(f"/repos/{REPOSITORY}/issues/{run['pr']}/comments")
    existing = next((comment for comment in comments if owns_comment(comment, check["app"])), None)
    if existing is None and not create:
        return
    body = summary(run, state, out)
    path = f"/repos/{REPOSITORY}/issues/comments/{existing['id']}" if existing else f"/repos/{REPOSITORY}/issues/{run['pr']}/comments"
    result = api.call(path, {"body": body}, "PATCH" if existing else "POST")
    if not owns_comment(result, check["app"]) or result["body"] != body:
        raise ValueError("summary publication was not confirmed")


def queue(api, value, execute):
    target = pr(api, value)
    model, effort = os.environ["RAGU_AUDIT_MODEL"], os.environ["RAGU_AUDIT_EFFORT"]
    if not re.fullmatch(r"claude-[a-z0-9.-]{1,100}", model) or effort not in ("low", "medium", "high", "xhigh", "max"):
        raise ValueError("set an explicit Claude model ID and effort")
    run = {"repository": REPOSITORY, "pr": number(value), "head": target["head"]["sha"], "base": target["base"]["sha"],
           "configuration": sha(os.environ["GITHUB_WORKFLOW_SHA"]), "model": model, "effort": effort,
           "run_id": number(os.environ["GITHUB_RUN_ID"]), "attempt": number(os.environ["GITHUB_RUN_ATTEMPT"])}
    if run["configuration"] != run["base"]:
        raise ValueError("main moved since this workflow was started; start a fresh run")
    run["url"] = f"https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}"
    prefix = scope(run)
    existing = checks(api, run["head"], os.environ["RAGU_AUDIT_APP_ID"])
    if not execute and existing and existing[0].get("external_id", "").startswith(prefix):
        return None
    run["external_id"] = prefix + f"{run['run_id']}:{run['attempt']}"
    check = api.call(f"/repos/{REPOSITORY}/check-runs", {
        "name": CHECK, "head_sha": run["head"], "external_id": run["external_id"], "details_url": run["url"],
        "status": "in_progress" if execute else "queued",
        "output": {"title": "Review running" if execute else "Review required", "summary": "Four skill reviews must finish for this exact head and base. Invoke with /ragu-audit."},
    }, "POST")
    if str(check["app"]["id"]) != os.environ["RAGU_AUDIT_APP_ID"] or check["head_sha"] != run["head"]:
        raise ValueError("check was not published by the configured App")
    run["check_id"] = check["id"]
    run["app_id"] = check["app"]["id"]
    upsert(api, run, check, "running" if execute else "required", create=execute)
    return run


def guard(api, run):
    if run["repository"] != REPOSITORY or run["configuration"] != sha(os.environ["GITHUB_WORKFLOW_SHA"]):
        raise ValueError("run identity does not match the trusted controller")
    if str(run["run_id"]) != os.environ["GITHUB_RUN_ID"] or str(run["attempt"]) != os.environ["GITHUB_RUN_ATTEMPT"]:
        raise ValueError("run identity does not match this workflow attempt")
    target = pr(api, run["pr"])
    if (target["head"]["sha"], target["base"]["sha"]) != (run["head"], run["base"]):
        raise ValueError("PR head or base moved during review")
    values = checks(api, run["head"], os.environ["RAGU_AUDIT_APP_ID"])
    if not values or values[0]["id"] != run["check_id"] or values[0].get("external_id") != run["external_id"]:
        raise ValueError("a newer review superseded this invocation")
    return values[0]


def publish(api, run, out, review_result):
    check = guard(api, run)
    success = False
    try:
        if review_result != "success":
            raise ValueError("review job did not succeed")
        runner.verify(run, out)
        success = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Review incomplete: {error}", flush=True)
    upsert(api, run, check, "completed" if success else "incomplete", create=True, out=out)
    guard(api, run)  # Recheck after reading artifacts and publishing the comment.
    api.call(f"/repos/{REPOSITORY}/check-runs/{run['check_id']}", {
        "status": "completed", "conclusion": "success" if success else "failure",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "output": {"title": "Four skill reviews completed" if success else "Review incomplete",
                   "summary": f"Reviewed head {run['head']} against base {run['base']}. Full findings and validation limits: {run['url']}"},
    }, "PATCH")
    if not success:
        raise ValueError("audit did not complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("request", "queue", "invalidate", "publish"))
    parser.add_argument("--pr")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--run", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--review-result")
    args = parser.parse_args()
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or os.environ["GITHUB_REF"] != "refs/heads/main":
        raise ValueError("audit controller only runs on Ragu main")
    api = GitHub()
    if args.command == "request":
        if os.environ["GITHUB_EVENT_NAME"] == "push":
            values = [target["number"] for target in api.pages(f"/repos/{REPOSITORY}/pulls?state=open&base=main")]
            if values:
                output(prs=json.dumps(values), execute="false")
            return
        result = request(api, runner.read_json(os.environ["GITHUB_EVENT_PATH"]), os.environ["GITHUB_EVENT_NAME"])
        if result:
            output(pr=result[0], prs=json.dumps([result[0]]), execute=str(result[1]).lower())
    elif args.command == "invalidate":
        for target in api.pages(f"/repos/{REPOSITORY}/pulls?state=open&base=main"):
            queue(api, target["number"], False)
    elif args.command == "queue":
        run = queue(api, args.pr, args.execute)
        if run:
            args.run.parent.mkdir(parents=True, exist_ok=True)
            runner.write_json(args.run, run)
            output(head=run["head"])
    else:
        publish(api, runner.read_json(args.run), args.out, args.review_result)


if __name__ == "__main__":
    main()
