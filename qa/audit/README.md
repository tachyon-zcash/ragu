# Ragu audit

`/ragu-audit` runs Ragu's code-review skill, then the Sean, Tal, and Alex review
skills against the same PR revision. These are complementary review
perspectives; checks follow the changes and relevant project policies.

Post the command as a PR comment with write access. The bot updates one summary
comment with each pass's findings and links to the full reports.
`ragu-audit/completed` stays blocked until all four passes finish; a new head or
base requires a fresh run. Completion records review coverage, not approval.

The runner and skills live in this repository. [Setup](SETUP.md).
