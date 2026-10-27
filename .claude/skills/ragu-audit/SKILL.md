---
name: ragu-audit
description: Run the /ragu-audit PR review on this machine with your own Claude login instead of the workflow's API key, then post its inline findings and summary from your GitHub account once you confirm.
argument-hint: "<PR number> [--head <sha>]"
disable-model-invocation: true
---

# Ragu audit (local)

Audit PR `$ARGUMENTS` with `qa/audit/local.py`. It runs the bot's four reviews
and reconciliation with the same sandbox and summary, but signs in with the
Claude login on this machine. See `qa/audit/README.md`.

1. If `$ARGUMENTS` names no PR number, ask for one. From the repository root,
   start this as a background command with no timeout:

   ```
   python3 qa/audit/local.py run $ARGUMENTS
   ```

   The review takes tens of minutes; wait for it to finish rather than polling.
   Each reviewer starts its own sandbox, which cannot start inside a sandboxed
   shell. If the command fails for that reason, ask before rerunning it outside
   the sandbox.

2. When it finishes, read the summary preview it printed. Report whether the
   review completed, the Must-fix and Suggestions counts, and each finding's
   title and location. Do not fix the PR or re-review its findings.

3. Ask whether to post. Only after a yes, run the `publish` command the run
   printed. It posts the inline findings and summary from the user's GitHub
   account, replacing their earlier local summary on that PR. Report the URL.

Never post, push, or comment any other way. A local run records no
`ragu-audit/completed` check; only the workflow's App can.
