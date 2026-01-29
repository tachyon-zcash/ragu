# Transform gungraun JSON output to github-action-benchmark format
# Extracts all Callgrind metrics from each benchmark
#
# Schema reference: https://github.com/gungraun/gungraun/raw/refs/heads/main/gungraun-runner/schemas/summary.v6.schema.json

# Helper to extract numeric value from Metric (Int or Float)
def extract_metric_value:
    if .Int then .Int
    elif .Float then .Float
    else null
    end;

# Extract current run's value from metrics
#
# Gungraun uses EitherOrBoth to represent baseline comparisons:
#   - Both: [old, new] when benchmark exists in both baseline and current run
#   - Left: current run value when no baseline exists (new benchmark or first run)
#   - Right: baseline-only? we don't want this value. seems to not appear in practice?
#
# Priority order for extracting the CURRENT run's value:
#   1. Both[0] - comparison exists. take the new value (gungraun stores [new, old])
#   2. Left    - no baseline exists. this is the current run's value
#   3. Right   - never.
def extract_current_value:
    (.Both[0] // .Left) | extract_metric_value;

# Map metric name to unit (matches gungraun's default console output)
def metric_unit:
    if . == "Ir" then "instructions"
    elif . == "L1hits" then "L1 hits"
    elif . == "LLhits" then "LL hits"
    elif . == "RamHits" then "RAM hits"
    elif . == "TotalRW" then "total accesses"
    elif . == "EstimatedCycles" then "cycles"
    else "count"
    end;

# Filter to gungraun's default console output metrics
def is_default_metric:
    . == "Ir" or . == "L1hits" or . == "LLhits" or . == "RamHits" or . == "TotalRW" or . == "EstimatedCycles";

# Main transformation: flatten benchmark results into github-action-benchmark format
#
# Input: array of gungraun benchmark results (use --slurp to combine multiple summary.json files)
# Output: array of {name, unit, value} objects for github-action-benchmark
#
# Example output entry (matches terminal header format):
#   {"name": "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf() Ir", "unit": "instructions", "value": 123456}
[.[] |
    # Build benchmark name to match terminal output format:
    # "module_path::function_name id" e.g., "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf()"
    (.module_path + "::" + .function_name + (if .id then (" " + .id) else "" end)) as $bench_name |

    # Extract Callgrind metrics from the first profile's total summary
    .profiles[0].summaries.total.summary.Callgrind | to_entries[] |

    # Filter to gungraun's default metrics and skip entries without values
    select(.key | is_default_metric) |
    select(.value.metrics != null) |

    # Emit one entry per metric in github-action-benchmark format
    {
        name: ($bench_name + " " + .key),  # e.g., "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf() Ir"
        unit: (.key | metric_unit),         # e.g., "instructions" for Ir
        value: (.value.metrics | extract_current_value)
    }
]
# Filter out any entries where value extraction failed
| map(select(.value != null))
