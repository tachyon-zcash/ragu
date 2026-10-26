---
name: code-review
description: Review Rust changes, files, or PRs using project policies and validated findings
user-invocable: true
---

# Code Review

Review code specified by `$ARGUMENTS`, using the project's code review policies.

## Step 1: Figure Out What to Review

The user's `$ARGUMENTS` could be anything. Interpret them:

| Arguments | What to do |
|-----------|-----------|
| *(empty)* | Review `git diff HEAD -- '*.rs'` (combined staged/unstaged changes) and the untracked files listed by `git ls-files --others --exclude-standard -- '*.rs'`. If neither contains changes, say so and stop. |
| Staged changes | Use `git diff --cached -- '*.rs'` and read file contents from the index, which may differ from the worktree. |
| A file path | Read that file. Review it. |
| A file path with lines (`foo.rs:50-80`) | Read that file. Focus the review on those lines (but read the full file for context). |
| Multiple file paths | Read all of them. Review each, and also look for consistency across them. |
| A PR number or URL (`#123`, URL) | Review the PR diff and matching file contents at the revisions recorded below. |
| A module or concept name | Use Grep/Glob to find where that code lives. Read those files. Review them. |
| A mix of the above | Handle each part, then review the union. |

If you're unsure what the user means, clarify the scope before starting review.

### Establish the Review Snapshot

Record the selected files, scope, and full revision IDs: PR base tip, comparison
base (normally the merge base), and head; or local HEAD plus the selected diff
and contents, including untracked files. For staged reviews, use index contents.
For PRs, read full affected files at those revisions. Use the captured inputs
for review and checks; preserve existing edits when preparing an isolated snapshot.

Before reporting, recheck the inputs. If they changed, refresh affected findings
and checks or identify the older snapshot and unfinished work. Do not mix
evidence from different snapshots.

## Step 2: Apply Review Policies

Review every applicable policy area, including its required shared policies.

1. Find all `.claude/code-review/*.md` files with Glob, or the Bash fallback below.
2. Read `.claude/code-review/standards.md` and every applicable policy.
3. For documentation reviews, also read `.claude/review-shared/writing.md`,
   `.claude/review-shared/math.md`, and
   `.claude/review-shared/surface-placement.md`.

**Do NOT flag:**

- For diff reviews, unrelated pre-existing issues
- Things that linters or compilers already catch (formatting, imports,
  type errors) — automated checks run separately
- Pedantic nitpicks or style preferences not backed by project policy
- An intentional behavior change solely because it differs from the old
  behavior — still check the intended new contract and project policies
- The specific lint diagnostic explicitly waived by an ignore/allow
  attribute — still review that code for independent correctness issues

**Tool usage rules:**

- Prefer Grep for content searches and Glob for file discovery when available.
  In minimal runtimes without them, use Bash `rg` for searches and
  `rg --files --hidden` for discovery, including the review policy directory.
- Use the Read tool to read files — do NOT use `cat`, `head`, or `tail`.
- When you do use Bash, the command must be a clean shell command with NO
  comment lines (`#`) prepended. Put your reasoning in the `description`
  parameter, not in the command itself.

## Step 3: Run Required Checks and Targeted Tests

For Rust or build changes, run formatting with pinned nightly rustfmt,
workspace Clippy, rustdoc (including private items), and targeted tests for
changed behavior. Use the CI toolchains, targets, features, and configuration;
deny Clippy and rustdoc warnings.

Run checks once against the reviewed snapshot. For documentation-only changes,
check the edited surface.

Record commands, configuration, results, and test counts. Confirm the intended
tests actually ran. Explain skipped or unavailable checks, distinguish setup
failures from test failures, and avoid duplicating automated diagnostics as
review findings.

## Step 4: Validate Candidate Findings

Check each candidate against complete affected code, callers, and applicable
project policies. Try to disprove behavioral defects using existing safeguards,
unreachable triggers, or a deliberate change that satisfies the new contract.
For policy violations, verify the cited rule and conflicting code or text.
In diff reviews, confirm how the change introduces, worsens, or exposes the
issue. Verify the consequence and cited locations.

Resolve conflicting claims using evidence; merge findings sharing a root cause.

## Step 5: Synthesize

Report each discovered policy area as completed, incomplete, or not applicable
(with a reason). Coverage is complete only when every applicable area is reviewed.

Present the scope and snapshot, check results, and unresolved questions or
coverage/validation gaps. List **must-fix** findings before **suggestions**,
ordered within each group by file and line. If there are no supported findings,
say so for the inspected scope.

If the review scope was cross-file or conceptual, add a short section about
cross-cutting observations (consistency, naming conventions, etc.).

## Step 6: Follow Up When Requested

Deliver the review before applying fixes or publishing comments. Follow up only
when requested; honor authorization already given without asking again.

### Local Mode (file paths, diff, concept)

For findings the user requests to fix:

1. Read the target file to get the current content.
2. Apply the correction, preserving unrelated edits.
3. Run relevant regression tests. For Rust code or build-configuration fixes,
   run `just ci_local`; for documentation-only fixes, use the surface-specific
   checks described in Step 3.
4. Report what changed, the validation results, and any remaining findings.

Report skipped findings as deferred, with any supplied reason.

### PR Mode (`#123` or PR URL)

Before requested publication, recheck the PR head and refresh affected findings
if it changed. Post the synthesis with `gh pr comment`, using a numbered list,
code links pinned to the full reviewed commit SHA and line ranges
(`L[start]-L[end]`), and any coverage or validation limits.
