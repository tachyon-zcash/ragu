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
reviewer findings are still published. Each invocation keeps its own status
comment with inline review links, finding counts, and collapsed original
reports. A finding cited outside the diff hunks attaches to the nearest diff
line of its file and links the cited line. A finding citing only files outside
the diff attaches to the nearest changed file and links its cited line, so
every finding is posted inline. Each invocation freezes its head and base commits. Later pushes
or updates to main do not change its findings, inline locations, or completion;
all results remain attached to the reviewed commit. New invocations preserve
earlier summaries and inline threads; identical reruns reuse existing inline
reviews.
Delete the original command comment to stop its review.

Identical reviews reuse verified results; retries resume unfinished passes.
A pass whose session fails without a verdict is retried once while the job has
time; if the core pass fails, the specialists still review independently.
All four reviewers and reconciliation use Sonnet 5.5 at high effort.
`RAGU_AUDIT_CORE_MODEL` and `RAGU_AUDIT_CORE_EFFORT` give the core review,
which must read the whole diff, a stronger model than the specialists.
An internal spending limit stops runaway reviews.

Require `ragu-audit/completed` to gate merging on all four passes finishing.
After pushing new commits, post the command again. Completion records finished
passes, not approval: a pass is complete once every changed file was examined,
and each report names the mechanical changes it only skimmed.

The runner and skills live in this repository. [Setup](SETUP.md).
