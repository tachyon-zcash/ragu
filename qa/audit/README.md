# Ragu audit

`/ragu-audit` runs Ragu's code-review skill, then the Sean, Tal, and Alex review
skills in parallel against the same PR revision. Specialists start with the
core finding index and consult the full core report when additional reasoning
or validation details are needed. Each specialist reads its skill's evidence
reference. These are complementary review perspectives; checks follow the
changes and relevant project policies.
CI owns formatting, linting, documentation builds, and routine test suites.
The bot runs focused tests only to investigate suspected bugs.

Post the exact command as a new PR comment with write access. Commits do not
trigger the bot. The bot posts merged **Must-fix** findings and **Suggestions**
as inline review comments, with evidence and reviewer attribution. A short
source-checking pass refines the findings; if it cannot finish, verified
reviewer findings are still published. One status comment links to the inline
reviews and preserves the collapsed original reports. Findings with no cited
line in the diff remain in that comment.
Delete the original command comment to stop its review.

Identical reviews reuse verified results; retries resume unfinished passes.
All four reviewers and reconciliation use Sonnet 5.5 at high effort.
An internal spending limit stops runaway reviews.

Require `ragu-audit/completed` to gate merging on all four passes finishing.
After pushing new commits, post the command again. Completion records finished
passes, not approval.

The runner and skills live in this repository. [Setup](SETUP.md).

## Run locally

`/ragu-audit <PR>` in Claude Code runs the same reviews on your machine with
your Claude login, drawing on your Claude plan instead of the workflow's API
key. It shows the summary first, then posts the inline findings and summary
from your GitHub account once you confirm. The commands behind it:

```
python3 qa/audit/local.py run <PR>        # review; posts nothing
python3 qa/audit/local.py publish <work>  # post a finished run
```

Run it from a checkout of `main`: reviewers trust that checkout's skills and
policies, as the workflow trusts `main`. It needs Claude Code and `gh` signed
in, and the Rust toolchains from `rust-toolchain.toml` installed.
`RAGU_AUDIT_*` variables override the models, as in the workflow.

A local run differs from the workflow:

- It records no `ragu-audit/completed` check; only the App can.
- Comments come from your account. Publishing again replaces your earlier
  local summary on that PR.
- A moved PR head makes the review stale; a moved `main` does not.
- Reviewers sign in through your Claude configuration directory.
- PR code runs on your machine. The Bash sandbox and network allowlist still
  apply, and your Claude configuration, keychain, and common credential stores
  are hidden, but the rest of your home directory is readable. Run it only on
  PRs you would build locally.
