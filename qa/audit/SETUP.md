# GitHub integration

After this workflow lands on `main`:

1. Create a GitHub App installed **only on tachyon-zcash/ragu**, with repository
   permissions **Checks: write**, **Pull requests: write**, and **Contents: read**.
   No webhook is needed.
2. Create two Ragu Actions environments, both restricted to the `main` branch:
   `ragu-audit-publisher`, containing secret `RAGU_AUDIT_APP_PRIVATE_KEY`, and
   `ragu-audit-model`, containing secret `ANTHROPIC_API_KEY`.
   Keep these credentials out of repository and organization-wide secrets.
3. Set repository variable `RAGU_AUDIT_APP_ID` to the App's numeric ID.
   Model and effort are configured in `.github/workflows/audit.yml`'s `env`
   block. All four reviews, their subagents, and reconciliation use
   `claude-sonnet-5-5` at `high` effort. Each invocation pins both the review
   and reconciliation configurations.
   Claude Code is pinned to 2.1.310 in the runner and installation script.
4. Set `RAGU_AUDIT_ENABLED=true` and post exactly `/ragu-audit` as a new PR
   conversation comment. The command requires live write, maintain, or admin
   permission. PR updates and pushes do not trigger the audit workflow.
   Deleting the original command comment stops that invocation. The trusted
   controller checks for deletion every 15 seconds and stops all active review
   process groups; Linux PID isolation also contains detached child processes.
   Credential cleanup and status publication then finish, with the App check
   marked cancelled. Deleting the bot's summary does not stop the review.
5. After a successful test run, require `ragu-audit/completed` on `main`, selecting
   this App as the expected publisher. Enable "Require branches to be up to date
   before merging" to enforce review against the current base. Keep the existing
   CI and approval rules.

The App posts retained findings as inline review comments after duplicate
merging and source adjudication, preserving evidence, corrections, reviewer
attribution, and disagreements. Comments attach to exact cited head-side lines
in the reviewed diff; there is no suggestion-count cutoff. GitHub accepts
comments only on lines in a diff hunk, so a finding whose cited lines all fall
outside the hunks of a changed file attaches to that file's nearest diff line
and links the cited line. A finding citing only files outside the diff attaches
to the first diff line of the changed file sharing the longest directory prefix
with a cited file, and links the cited line. Only a diff without commentable
lines leaves findings in the status comment. The diff and comments use the invocation's
pinned base and head commits. New pushes, updates to main, or closing the PR
do not invalidate that snapshot or change how its findings are published.
Each invocation keeps an App-owned status comment with **For humans** counts
and links to its inline reviews. It posts the comment below the command, where
it appears without a page reload; later states edit only that invocation's
comment.
Earlier summaries, report links, and inline threads remain available. Identical
reruns reuse existing inline reviews. Reviewed revisions, model
settings, and extra notes are collapsed under Run details.
Under **For agents**, the four original Markdown reviewer reports remain
collapsed below the summary, with full artifact links when the comment budget requires truncation.
The workflow's complete bundle also includes structured findings, native results, and reconciliation decisions.
Artifacts are retained for 30 days; individual report links require GitHub login
and fall back to the workflow when an auxiliary upload fails. Missing or
failed native runs, missing reports, and modified review worktrees fail the
completion check. A deleted command cancels its invocation, and a newer invocation
can supersede it without allowing it to overwrite the newer summary or check.
Checks attach to the reviewed commits; identical snapshots across PRs
can share a result, while each invocation updates its own PR comment. Findings
do not automatically block this check; maintainers resolve them through normal
review.

Denied tool requests stay blocked but do not by themselves invalidate a
completed review. The reviewer must use permitted alternatives and report
limitations, or return `complete=false` if missing evidence prevents finishing.
Native session errors, unfinished coverage, invalid receipts, and changed
source still fail the gate.

All four passes focus on source review. Separate CI workflows own formatting,
Clippy and other lints, documentation builds, routine builds, and broad test
suites. The bot neither runs those checks nor waits for their status. This
controller policy overrides generic skill instructions to run automated
validation; CI results do not determine review completion. A reviewer can run
a focused test or reproducer to investigate a concrete suspected defect.

The core code-review pass runs first. Sean, Tal, and Alex then run concurrently,
each with a separate source worktree and Claude state. They start with the
normalized core finding index and consult the original Markdown report only
when they need additional reasoning or validation details. Full original
reports remain in artifacts and under **For agents**. Specialists read their
skill's evidence reference, but cannot read each other's reports or state, or
modify another checkout. Cargo's download cache is shared
within the fresh runner; adequate recorded validation can be reused instead of
running the same checks four times. Each specialist defaults to one third of
the runner's logical CPUs for Cargo compilation, with a minimum of one build
job; the core pass uses the full CPU count. Per-pass durations are recorded in the
receipt, with native token usage and cost in each Claude result artifact.

Repeated authorized commands for an already active identical review retain its
existing run and status, including commands arriving together before either
starts. Later invocations and failed-run retries can recover
completed passes from the exact same head, base, trusted controller/policies,
CLI version, and review/reconciliation model settings. Specialists stay paired
with their original core report and finding IDs. A changed snapshot or effort
forces fresh reviews. Post a new command or use GitHub's **Re-run all jobs** to
retry with fresh authorization and reuse an earlier attempt's verified artifacts.
Re-running only failed jobs cannot reuse an earlier attempt's authorization.
Cancelled, deleted, or stranded workflows do not suppress a new request.

Reuse reads only this repository's App-owned checks and artifacts from the
trusted main `audit.yml` workflow. It verifies the source workflow, attempt,
receipt, native completion, report hashes, schema, and core dependency before
rebinding reports to the new invocation. Original receipts remain in artifacts
as provenance. It never executes downloaded artifacts. Missing, expired, or
invalid evidence falls back to fresh review; lookup has a one-minute limit.
A damaged specialist or optional reconciliation does not
discard valid siblings. Complete matching reviews and reconciliation require
no new model calls. Read-only Actions/Checks permissions support lookup; App
permissions and model credential isolation are unchanged.

Reviewers return their complete Markdown report in the skill's normal prose
format, alongside structured findings with source locations, cause, evidence,
impact, and proposed correction. The controller preserves the prose rather than
reconstructing it from those fields. Specialists get the completed core report
and a normalized `core-findings.json` index for assessment references. The
reconciler receives structured findings without duplicating the full prose.
The controller immediately combines these into one summary, merging exact
matching causes/corrections at the same locations and
preserving attribution. Different wording remains separate until source
adjudication. Disputed findings remain visible as suggestions, with the
counterevidence. This summary needs no additional model call and is saved as
`combined.md` before optional refinement. Specialists can support or challenge core
finding IDs. Once all four finish, a read-only reconciliation gets the normalized
findings and a separate checkout of the same pinned source. It merges findings
only when cause and correction agree, checks disputed claims against source and
existing tests, and records reasons for all dispositions, including dismissed
claims. Reviewer consensus alone is not evidence. PR descriptions and discussion
are not supplied. Unmeasured performance questions remain suggestions; when
measurements were not assessed the report says so.

Reconciliation has a three-minute deadline and a 20-turn limit, with only the
native Read tool: no shell, edits, tests, builds, or benchmarks. It must account
for every original finding ID exactly once. Its separate receipt binds the
input bundle and final report; it cannot modify the four-review completion
receipt. Failure, timeout, invalid output, or damaged reconciliation artifacts
publish combined findings derived from all verified reviewers, with a notice
that additional source checking did not finish. There is
no extra model call when all reviewers return zero findings. Reconciliation does
not determine the completion gate. Deleting the invoking comment also stops
reconciliation; publication still marks the invocation cancelled.

Each pass has a 55-minute deadline and emits a safe progress heartbeat every
30 seconds in the workflow log (elapsed time, event count, and fixed tool names;
no tool arguments or reasoning). Git setup and verification commands have
three-minute deadlines and cannot prompt for credentials. Timeout/cancellation
stops the review process group; on Linux a private PID namespace also contains
detached children. Artifacts retain the final native result, bounded stderr
with the model key redacted, and controller-owned per-pass status metadata.
Raw event transcripts are not uploaded.

Each invocation has one shared internal $25 estimated API safety limit. Reviewers
and reconciliation can use the entire remaining pool, without individual quotas.
The controller aggregates streamed input, cache, and output usage across parallel
sessions, deduplicates cumulative updates, and reconciles native final estimates.
Its pricing table covers the configured Opus/Sonnet models; an unknown model or
unsupported usage stops the guard rather than silently permitting unpriced work.
Each CLI session also receives the current remaining budget as a fallback limit.
Reused results incur no new model calls and do not consume this invocation's pool.
Reaching the combined limit stops outstanding review processes and fails the run.
The bot still publishes available completed findings and their original reports,
with a short explanation of incomplete work. Reconciliation uses the same pool.

This guard uses CLI estimates, so in-flight requests may overshoot and the
provider's bill can differ. The limit applies per invocation, not cumulatively
across a PR's commits or retries. Cost totals are not added to PR comments or
workflow summaries; a stopped pass gets only a generic safety-limit diagnostic.

The queue passes public request identity through a job output and keeps the
control artifact as a fallback. Both model and publisher jobs validate the
workflow, revision, App, and invocation identity before using it. A failed
control-file write or artifact upload cannot by itself strand a queued check.
Individual reviewer archives also contain the native result and shared receipt,
so the publisher can recover verified reviews if the combined archive fails.
An unavailable specialist report is identified and omitted without hiding its
verified siblings. Core evidence is required to validate their assessment
references; any missing or invalid review still fails the completion gate.
Artifact transfers have one-minute step limits, with time reserved for status
publication. Failure of both report channels still fails the completion gate.
No credentials travel through these outputs or control files.

Controller reads and repeated updates retry transient GitHub server or
connection failures, including interrupted HTTP responses, up to three times
with bounded backoff. Check, comment, and inline review creation are not
retried automatically; a lost response is recovered only when the exact
App-owned publication can be confirmed. Inline comments are grouped into
comment-only reviews of at most 50 findings, pinned to the reviewed commit.
Identical snapshots, configurations, and finding batches reuse existing
reviews across retries and repeated commands. The publisher checks every
posted comment before granting completion. Persistent publication failures keep the gate unsuccessful and
attempt to replace the running comment with verified reports and an explicit
publication-failed status.

Each pass also has a short, private scratch directory, with peer scratch
protected from reads and host writes. The short path prevents Claude from
falling back to a shared Bash temp directory. On Linux, a per-reviewer mount
namespace replaces the default shared temp directories with private directories
before Claude starts, preventing the inner runtime from re-opening host scratch
files. These private replacements remain writable to Claude for runtime IPC;
the Bash sandbox and network policy still apply. The controller creates report
files before launching any reviewer and writes them in place, so Linux
read-deny mounts also hide reports written later.

New commits need another `/ragu-audit` comment. A required check blocks an
unreviewed head without running a workflow. Completed checks do not update when
`main` advances; requiring up-to-date branches forces a new head and review.
GitHub can show skipped runs for other issue comments because comment-body
filtering happens at the job level. Those runs do not access either environment.

Review skills and policies come from the workflow's trusted `main` revision,
not the PR. Claude runs noninteractively with a required Bash sandbox, protected
controller/report paths, and an API key helper outside that sandbox. The model
job has no App key; publisher jobs never execute PR code. Required Rust
toolchains are installed before the model key is made available. Tests can
write scratch files and Cargo dependencies, but no caches are saved afterward.
The controller prepares the Cargo home, executable directory, and readable
configuration files before starting Claude. Persistent `.mcp.json` and `.claude`
guards in the shared Cargo home avoid temporary guard-path races between
concurrent Linux sandboxes; the protected paths stay unwritable
to review tools. Ordinary Cargo
commands use the fixed network allowlist; per-command domain arguments cannot
widen it. The native Read tool can inspect trusted skill references and this prepared
Cargo home, including registry and Git dependency source; native edits to the cache remain denied.
Claude's saved tool output lives separately from the credential
directory. Review tools can read that output but cannot modify CLI state.
Incomplete comments name unfinished passes and fixed diagnostics without
publishing model text, tool arguments, or stderr as the failure reason.
Only the trusted controller receives the repository's read-only GitHub token
to check the invoking comment; it is excluded from the review CLI's environment
along with all other GitHub and cloud credentials. The model job has no Actions
write permission and does not need an additional secret for cancellation.

Trusted system instructions mark PR files, test output, and earlier reports as
untrusted evidence. Project hooks/MCP configuration do not load, skill shell
preprocessing is disabled, and shell commands cannot retry outside the sandbox.
Native tests deliberately attempt credential reads and report tampering after
reading injected instructions. These test containment with a fake API, not
the configured model's resistance to misleading text. Review coverage and
findings remain model-reported and need human assessment.

A new command can cancel an older review on that PR; stale results cannot
pass the gate. The publisher terminates the old invocation's check and edits
only that invocation's own summary, leaving newer summaries untouched. Failed or stale
reviews still show verified summaries and findings from completed passes,
clearly tied to the reviewed revisions. Brief App writes are serialized across
PRs; model reviews remain concurrent. GitHub labels jobs that use an environment as deployments. Regression
tests run in the existing Workflow audit CI, without audit credentials or paid
model calls. Merge queues are not supported by this comment-only workflow.
A required check cannot substitute for human review or establish soundness.

Retire the separate `tachyon-zcash/ragu-audit` repository after this integration
lands and an authenticated comment-triggered review succeeds. This workflow
has no dependency on that repository.
