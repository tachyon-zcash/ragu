# Find the PR number for a given owner, branch, and SHA.
# This is useful for finding the PR number of a triggering forked PR.
#
# Input: array of PR objects from `gh pr list --repo <repo name> --state open --json number,headRefName,headRefOid,headRepositoryOwner`
# Output: a single PR number, or nothing if no matching PR is found
#
# This is used when a `bench-alert.yml` workflow is triggered by successful completion of the `bench.yml` workflow.

.[] | select(
  .headRepositoryOwner.login == $pr_owner and
  .headRefName == $pr_branch and
  .headRefOid == $pr_sha
) | .number
