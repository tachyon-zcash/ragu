# Wallet and aggregator benchmarks

This suite measures the wallet at rank 13 and the aggregator at rank 15 with
AcceleratedBackend. It uses the WitnessLeaf and Hash2 test circuits, header size
4, inputs 42 and 7, and StdRng seed 0. The workload is the one used for the
optimized/decompression measurements.

The Rust benchmark lives in
[crates/ragu_pcd/benches/workflow.rs](../../crates/ragu_pcd/benches/workflow.rs).
The Python runner builds immutable revisions, measures complete workflows, and
checks their proof digests, shapes, and final RNG state. It supports macOS and
Linux and requires Python 3.12+, Git, and Rust installed through rustup. Install
the toolchain in rust-toolchain.toml, or select one compiler for all revisions
with --toolchain.

## Run

From the repository root:

~~~sh
python3 qa/bench/run.py run --threads 12
~~~

This builds four executables: ASM off/on, each with a true single-thread build
and a multicore build using 12 Rayon workers. Single-thread builds omit the
multicore feature; they are not Rayon builds limited to one worker. ASM selects
Udon's AArch64 assembly feature. On other architectures, those two feature
configurations still use portable field arithmetic.

The default is one warmup and three measured processes per configuration. Each
process creates fresh applications and verifies all generated proofs. Builds
finish before measurements start, and variants run sequentially in a rotated
and reversed order across rounds.

For a compatible baseline comparison, use local Git revisions:

~~~sh
python3 qa/bench/run.py run --base BASE_SHA --revision HEAD \
  --threads 12 --repetitions 5
~~~

The same workload source from the invoking checkout is overlaid on both
archived revisions. Each revision must contain its committed Cargo.lock and
support the workload's APIs. Only committed library code is measured; uncommitted
library edits are not included. The tool does not fetch remote refs. A mismatch
in proof digests, shapes, or RNG state stops the comparison, so protocol-changing
revisions require separate campaigns.

Limit a run or prepare its builds in advance:

~~~sh
python3 qa/bench/run.py run --asm on --modes multi --threads 12 \
  --offline --jobs 2 --build-only
python3 qa/bench/run.py resume /absolute/path/to/output
~~~

--offline requires an already populated Cargo cache. --reference accepts a raw
JSONL run from an earlier campaign and requires the same proof and RNG identities.
All Cargo builds use --locked and explicit features with default features
disabled. The runner clears ambient Rust flags, wrappers, and profile overrides.
It records compiler versions, hardware, source and lockfile hashes, Cargo
commands, feature trees, and hashes of the exact measured executables.

## Workload and timing boundaries

Wallet operations include application finalization and bootstrap, two separate
leaf seeds, ordinary verification, compression, compressed verification, and one
fuse of the two existing leaves. The aggregator decompresses those two wallet
proofs, verifies them, fuses them, compresses the parent, and verifies that one
aggregated compressed proof.

Every timing row measures one API call. Startup rows include finalization and
bootstrap once per application. Canonical decompression preparation is retained
as a separate raw timing. Serialization and digest computation occur outside
the timed calls. Ordinary proof verification and the final RNG checkpoint also
check that single/multicore and ASM variants preserve behavior.

The report contains wallet and aggregator columns, with separate ASM-off and
ASM-on tables. Sizes use decimal KB/MB and times use seconds. For operations
performed on both children, the reported median pools the two samples from each
measured process. The report also retains each process's median and the full
sample range; closely spaced results within that variability are uncertain.
Whole-process peak RSS includes startup and proving, not just verification.

## Artifacts and interruptions

Output defaults to a new directory under target/workflow-bench/, which Git
ignores. --output can select another **new** directory. The runner never
overwrites an existing campaign.

Each output directory contains:

- report.md, samples.csv, and results.json for the tables and all raw timings.
- manifest.json and quality.json for configuration and round selection.
- raw/ for every process's JSONL, stderr, CPU observations, memory counters,
  elapsed time, sleep detection, exit code, and peak RSS when /usr/bin/time is
  available.
- bin/, build-logs/, sources/, and snapshots/ for the exact executables, Cargo
  output, frozen source trees, and Git archives.
- controller/ for copies of the runner and workload used for the campaign.

The runner waits for active build/test jobs before each process; it never pauses
another job. It records contention that appears during a process and retains
those samples. --no-wait disables the initial wait and records that choice;
it is useful for functional checks, not for avoiding noisy results.

On macOS the runner uses caffeinate while measuring. A recorded system sleep or
an interrupted attempt causes the entire matched round to be retained and a
replacement round to run. It does not select samples based on elapsed time.
Ctrl-C preserves completed runs and archives the interrupted attempt on resume.
Failed proof checks or unexplained partial files stop the campaign for inspection
instead of silently replacing a failure.

Resume requires unchanged frozen sources, workload, executables, compiler, and
host details. If the checkout's runner has changed, use the saved copy:

~~~sh
python3 /absolute/path/to/output/controller/run.py resume /absolute/path/to/output
python3 /absolute/path/to/output/controller/run.py summarize /absolute/path/to/output
~~~

Keep generated results, metadata, and binaries outside Git. Share the output
directory with a published report when its raw evidence is needed.

## Check the suite

~~~sh
python3 -m unittest discover -s qa/bench -p 'test_*.py'
cargo bench -p ragu_pcd --all-features --locked --bench workflow --no-run
~~~

The benchmark PR workflow runs these checks. It does not enforce wall-clock
performance thresholds on shared CI machines. Run timing comparisons on the
target hardware with a quiet system.
