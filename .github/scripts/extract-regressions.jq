# Extract regressions from gungraun benchmark summaries.
#
# Input: array of gungraun summary objects (use --slurp with `find target/gungraun -name 'summary.json' -exec cat {} +`)
# Args: --argjson threshold <number> (e.g., 1.5 for 150% of baseline)
# Output: sorted by ratio descending: `{name: string, current: number, baseline: number, ratio: number}[]`
#
# This is used by `bench-alert.yml` to identify benchmarks that regressed beyond the threshold.
# Only the Ir (instruction count) metric is compared; other metrics (L1hits, LLhits, etc.) are ignored.
#
# Gungraun summary schema reference: https://github.com/gungraun/gungraun/raw/refs/heads/main/gungraun-runner/schemas/summary.v6.schema.json
#
# Gungraun comparisons use EitherOrBoth:
#   - Both: [new, old] when baseline exists
#   - Left: new value only (no baseline to compare)
#   - Right: in the schema, but never observed?

def extract_metric_value:
  if .Int then .Int
  elif .Float then .Float
  else null
  end;

[.[] |
  (.module_path + "::" + .function_name + (if .id then " " + .id else "" end)) as $name |
  .profiles[0].summaries.total.summary.Callgrind.Ir.metrics as $metrics |

  # Only process entries with comparison data (Both)
  select($metrics.Both != null) |

  ($metrics.Both[0] | extract_metric_value) as $new |
  ($metrics.Both[1] | extract_metric_value) as $old |

  select($new != null and $old != null and $old > 0) |

  {name: $name, current: $new, baseline: $old, ratio: ($new / $old)} |
  select(.ratio > $threshold)
] | sort_by(-.ratio)
