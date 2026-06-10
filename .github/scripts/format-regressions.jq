# Format regressions as a markdown table for PR comments.
#
# Input: array of regression objects from extract-regressions.jq, each with {name, current, baseline, ratio}
# Output: complete markdown table with header and rows
#
# This is used by `bench.yml` to format the regression table in the PR's bench job summary.

"| Benchmark | Current | Baseline | Ratio |",
"| --------- | ------- | -------- | ----- |",
(.[] | "| `\(.name)` | \(.current) | \(.baseline) | \(.ratio * 100 | round / 100) |")
