# list all available just commands
default:
    @just --list

_nixery_meta := if arch() == "aarch64" { "arm64/shell" } else { "shell" }

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

_nightly := "nightly-2026-05-23"

# static checks CI enforces: rustfmt, every clippy configuration, rustdoc, QA source checks, book
[group('dev')]
lint: fmt_check clippy docs qa_lint fuzz_lint fv_lint _book_build

fix: _typos_setup
  cargo +{{_nightly}} fmt --all -- --config-path rustfmt.nightly.toml
  cargo fix --allow-dirty --allow-staged --all-features
  cargo clippy --fix --allow-dirty --allow-staged --all-features
  typos -w

_install_binstall:
  @command -v cargo-binstall > /dev/null || cargo install cargo-binstall

_book_setup: _install_binstall
  @cargo binstall --quiet --no-confirm mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2 mdbook-linkcheck@0.7.7 mdbook-admonish@1.20.0

_typos_setup: _install_binstall
  @cargo binstall --quiet --no-confirm typos-cli

_gungraun_setup: _install_binstall
  @cargo binstall --quiet --no-confirm gungraun-runner@0.17.0

_flamegraph_setup: _install_binstall
  @cargo binstall --quiet --no-confirm flamegraph

# locally [build | serve | watch] Ragu book
book COMMAND: _book_setup
  mdbook {{COMMAND}} ./book --open

# fast per-commit tests (~2 min warm): all unit and integration tests but the slow proving suites in `_test_skip`; ARGS go to libtest, e.g. `just test compress::`
[group('dev')]
test *ARGS:
  cargo test --profile fast-test --workspace --all-features --locked -- {{_test_skip}} {{ARGS}}

# Each pattern is a libtest substring filter. These suites prove with the
# Aggregator or extension profiles, recurse through several generations, or
# compare backends. They are 62 tests but about 80% of the suite's test time,
# each taking from half a minute to several minutes. What remains still proves end to end
# (`nontrivial`, `wire`, `compress::tests`, the standard-profile `verify::tests`,
# and others). `ci_test_all`, `backend_lane` and `ci_fixtures` run the skipped ones.
_test_skip := (
  "--skip proof::profile_substitution_tests " +
  "--skip proof::backend_equivalence " +
  "--skip proof::fuse_fixture_tests " +
  "--skip setup_binding_tests " +
  "--skip profile_corruption_tests " +
  "--skip decompress_statement_tests " +
  "--skip _binding_holds_the_sides_to_each_other " +
  "--skip extension_polynomials_are_bound_with_a_ " +
  "--skip an_extension_proves_verifies_and_compresses " +
  "--skip proof::app_stage_tests::the_stage_commitment_binds_exactly_the_staged_values " +
  "--skip proof::app_stage_tests::steps_ " +
  "--skip noncanonical_unit_children_reject_through_two_generations " +
  "--skip targets_match_the_decider_across_proof_shapes " +
  "--skip decider_rejects_malformed_inputs_and_propagates_header_errors " +
  "--skip test_non_step_slots_reject_application_instances " +
  "--skip bootstrap_exempts_child_claims_with_consistent_commitments " +
  "--skip rerandomization_flow " +
  "--skip multiple_rerandomizations_all_verify " +
  "--skip both_profiles_prove_in_one_binary"
)

# run quicker proptests used for routine local/CI coverage
proptests_fast *ARGS:
  PROPTEST_CASES="${PROPTEST_CASES:-64}" cargo test --release -p ragu_core --locked --all-features proptest {{ARGS}}

# run slower proptests with higher default case counts
proptests_heavy *ARGS:
  PROPTEST_CASES="${PROPTEST_CASES:-256}" cargo test --release -p ragu_circuits --all-features proptest {{ARGS}}

# run benchmarks (auto-detects platform)
bench *ARGS:
    @just _bench_{{os()}} {{ARGS}}

_bench_macos *ARGS:
    #!/bin/sh
    [ -t 1 ] && tty_opt="--tty" # use tty if stdout is a tty
    container=$(docker run $tty_opt --detach --interactive --init --rm \
        -v "{{justfile_dir()}}":/workspace:ro \
        -v ragu-cargo:/.cargo \
        -v ragu-rustup:/.rustup \
        -v "{{justfile_dir()}}"/target:/workspace/target \
        -e CARGO_HOME=/.cargo \
        -e RUSTUP_HOME=/.rustup \
        -w /workspace \
        --security-opt seccomp=unconfined \
        nixery.dev/{{_nixery_meta}}/cargo-binstall/gcc/just/rustup/valgrind \
        just _bench_linux {{ARGS}})
    trap "docker kill $container > /dev/null 2>&1" EXIT HUP
    docker attach --no-stdin $container

_bench_linux *ARGS: _gungraun_setup
    cargo bench --workspace --all-features --bench gungraun {{ARGS}}

# generate flamegraph in target/*.svg
flamegraph PACKAGE GROUP TARGET *ARGS:
    @just _flamegraph_{{os()}} {{PACKAGE}} {{GROUP}} {{TARGET}} {{ARGS}}

# generate flamegraph for ragu_pcd::fuse()
flamegraph_fuse:
    @just flamegraph ragu_pcd app_proof fuse

_flamegraph_macos PACKAGE GROUP TARGET *ARGS:
    #!/bin/sh
    [ -t 1 ] && tty_opt="--tty"
    container=$(docker run $tty_opt --detach --interactive --init --rm \
        -v "{{justfile_dir()}}":/workspace \
        -v ragu-cargo:/.cargo \
        -v ragu-rustup:/.rustup \
        -v ragu-flamegraph-target:/tmp/ragu-target \
        -e CARGO_HOME=/.cargo \
        -e RUSTUP_HOME=/.rustup \
        -w /workspace \
        --privileged \
        nixery.dev/{{_nixery_meta}}/cargo-binstall/busybox/gcc/just/rustup/perf \
        just _flamegraph_linux {{PACKAGE}} {{GROUP}} {{TARGET}} {{ARGS}})
    trap "docker kill $container > /dev/null 2>&1" EXIT HUP
    docker attach --no-stdin $container

_flamegraph_linux PACKAGE GROUP TARGET *ARGS: _flamegraph_setup
    #!/bin/sh
    set -e
    bench_file="crates/{{PACKAGE}}/benches/gungraun.rs"
    if [ ! -f "$bench_file" ]; then
        echo "error: bench file not found: $bench_file" >&2; exit 1
    fi
    bench_list=$(grep -A2 "name = {{GROUP}}" "$bench_file" | grep 'benchmarks' | sed 's/.*=\s*//;s/[^a-zA-Z0-9_,]//g')
    if [ -z "$bench_list" ]; then
        echo "error: group '{{GROUP}}' not found in $bench_file" >&2; exit 1
    fi
    func_idx=0
    for fn in $(echo "$bench_list" | tr ',' ' '); do
        [ "$fn" = "{{TARGET}}" ] && break
        func_idx=$((func_idx + 1))
    done
    CARGO_TARGET_DIR=/tmp/ragu-target CARGO_PROFILE_RELEASE_DEBUG=true \
        cargo flamegraph --release -p {{PACKAGE}} --bench gungraun \
        -o "target/flamegraph-{{PACKAGE}}-{{GROUP}}-{{TARGET}}.svg" {{ARGS}} \
        -- --gungraun-run {{GROUP}} "$func_idx" 0

# ---------------------------------------------------------------------------
# Lint pieces. `just lint` runs all of them; each mirrors a CI step, named in
# its comment, so a red CI check maps back to one recipe here.
# ---------------------------------------------------------------------------

# rustfmt with the pinned nightly (rust.yml: fmt)
[group('lint')]
fmt_check:
  cargo +{{_nightly}} fmt --all -- --config-path rustfmt.nightly.toml --check

# clippy in every configuration CI lints (rust.yml: clippy, mock; backend.yml)
[group('lint')]
clippy: backend_clippy
  cargo clippy --workspace --lib --tests --benches --locked --all-features -- -D warnings
  cargo clippy -p ragu_pcd --lib --locked -- -D warnings
  cargo clippy -p ragu_pcd --lib --locked --features baked,multicore -- -D warnings
  cargo clippy -p ragu --no-default-features --features mock --lib --tests --locked -- -D warnings

# rustdoc with warnings denied, private items included (rust.yml: docs)
[group('lint')]
docs:
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --locked --all-features --document-private-items

# source checks with no compilation step (lint.yml)
[group('lint')]
qa_lint:
  #!/usr/bin/env bash
  set -euo pipefail
  if git grep -n --untracked -e 'as GadgetKind.*>::Rebind' -- '*.rs' ':!crates/ragu_core/src/gadgets.rs'; then
    echo "error: verbose GadgetKind::Rebind UFCS pattern; use the Bound<'dr, D, K> alias instead" >&2
    exit 1
  fi
  PYTHONDONTWRITEBYTECODE=1 python3 qa/params/check_poseidon_params.py

# fuzz target census, circuit source lint against its baseline, harness compiles (rust.yml: fuzz-check; fuzz-cron.yml: source-lint)
[group('lint')]
fuzz_lint:
  qa/fuzz/check_targets.sh
  cd qa/fuzz && RUSTUP_TOOLCHAIN={{_nightly}} cargo run --locked --bin circuit_lint -- --deny-advisories
  cd qa/fuzz && RUSTUP_TOOLCHAIN={{_nightly}} cargo check --locked --bins

# FV trust-boundary census and exported Lean files up to date (fv.yml)
[group('lint')]
fv_lint:
  scripts/check_fv_endpoint_census.sh
  scripts/check_fv_contract_composition.sh
  cargo run --locked -p lean_extraction -- check

_book_build: _book_setup
  mdbook build ./book

# ---------------------------------------------------------------------------
# CI jobs. `just ci_local` runs every one that can run on this machine.
# ---------------------------------------------------------------------------

# every CI check runnable on this machine, serially; only the Windows/macOS matrix legs are left out. Expect well over an hour.
[group('ci')]
ci_local: lint ci_test_all ci_test_default ci_corruption ci_mock proptests_fast ci_nostd ci_bitrot ci_fuzz_harness backend_lane ci_fixtures ci_fv ci_supply_chain
  @echo "All CI checks passed!"

# full test suite, all features (rust.yml: all-feature)
[group('ci')]
ci_test_all:
  cargo test --release --all --locked --all-features

# full test suite, default features (rust.yml: default-feature)
[group('ci')]
ci_test_default:
  cargo test --release --all --locked

# ignored corruption and online-oracle suites, recursive regression seeds (rust.yml: test-corruption)
[group('ci')]
ci_corruption:
  cargo test --release -p ragu_pcd --locked --all-features --test corruption -- --include-ignored
  cargo test --release -p ragu_pcd --locked --all-features --test online_oracles -- --include-ignored
  PROPTEST_CASES=1 cargo test --release -p ragu_pcd --locked --all-features --lib -- --ignored --test-threads=1 \
    proof::recursive_boundary_tests::stages::same_lift_bit_substitutions_reject_through_two_generations \
    proof::recursive_boundary_tests::stages::corrupted_hoisted_products_reject_through_two_generations \
    proof::recursive_binding_tests::challenge_binding::partial_and_pre_beta_substitutions_reject_through_two_generations

# the mock API under no-default-features (rust.yml: mock; its clippy step is in `clippy`)
[group('ci')]
ci_mock:
  cargo test --release -p ragu --no-default-features --features mock --locked

# the mock API on a bare-metal target (rust.yml: build-nostd)
[group('ci')]
ci_nostd: _thumb_setup
  cargo build -p ragu --lib --locked --no-default-features --features mock --target thumbv7em-none-eabihf

# benches and examples still build (rust.yml: bitrot; bench.yml: build benchmarks)
[group('ci')]
ci_bitrot:
  cargo build --workspace --benches --examples --all-features
  cargo bench --workspace --all-features --locked --bench gungraun --no-run

# fuzz support and patcher tests, proof-wire entry points (rust.yml: fuzz-check)
[group('ci')]
ci_fuzz_harness: fuzz_lint
  #!/usr/bin/env bash
  set -euo pipefail
  cd qa/fuzz
  export RUSTUP_TOOLCHAIN={{_nightly}}
  cargo test --locked --lib
  PROPTEST_CASES=2 cargo test --release --locked --lib internal_patcher::tests -- --include-ignored
  PROPTEST_CASES=2 cargo test --release --locked --all-features --lib internal_patcher::tests -- --include-ignored
  cargo test --release --locked --lib proof_wire::tests::decode_to_verify_smoke -- --ignored --exact
  inputs=$(mktemp -d)
  trap 'rm -rf "$inputs"' EXIT
  printf '\001' > "$inputs/valid"
  printf '\005' > "$inputs/scalar"
  for target in fuzz_proof_wire fuzz_compressed_wire; do
    cargo run --release --locked --bin "$target" -- "$inputs"/* -timeout=180 -rss_limit_mb=4096
  done

# golden fuse and verifier fixtures (fixtures.yml)
[group('ci')]
ci_fixtures:
  RAGU_FIXTURES=check cargo test --release -p ragu_pcd --locked --all-features --lib proof::fuse_fixture_tests -- --include-ignored

# exporter tests, Lean build, fingerprint equivalence (fv.yml); skipped with a warning when `lake` is not installed
[group('ci')]
ci_fv: fv_lint
  #!/usr/bin/env bash
  set -euo pipefail
  cargo test --locked -p lean_extraction
  if ! command -v lake > /dev/null; then
    echo "warning: lake not found; skipping the Lean build and fingerprint checks of fv.yml" >&2
    exit 0
  fi
  out=$(mktemp -d)
  trap 'rm -rf "$out"' EXIT
  (cd qa/fv && lake exe cache get && lake build --wfail)
  cargo run --locked -p lean_extraction -- fingerprint | sort > "$out/rust.txt"
  (cd qa/fv && lake env lean --run Ragu/Fingerprint/Main.lean) | sort > "$out/lean.txt"
  diff -u "$out/rust.txt" "$out/lean.txt"
  seed=$(openssl rand -hex 32)
  echo "polynomial fingerprint seed: $seed"
  cargo run --locked -p lean_extraction -- polynomial-fingerprint --seed "$seed" --points 2 | sort > "$out/poly-rust.txt"
  (cd qa/fv && lake env lean --run Ragu/PolynomialFingerprint/Main.lean "$seed" 2) | sort > "$out/poly-lean.txt"
  diff -u "$out/poly-rust.txt" "$out/poly-lean.txt"

# cargo vet and cargo audit (vet.yml)
[group('ci')]
ci_supply_chain: _supply_chain_setup
  RUSTUP_TOOLCHAIN=stable cargo vet --locked --store-path ./qa/supply-chain/
  RUSTUP_TOOLCHAIN=stable cargo audit

_thumb_setup:
  @rustup target add thumbv7em-none-eabihf > /dev/null

_supply_chain_setup: _install_binstall
  @cargo binstall --quiet --no-confirm cargo-vet@0.10.2 cargo-audit@0.22.1

# ---------------------------------------------------------------------------
# Backend lane (backend.yml)
# ---------------------------------------------------------------------------

# backend feature configurations compile cleanly, and the PCD routes MSMs and FFTs through the backend
[group('backend')]
backend_clippy:
  cargo clippy -p ragu_acceleration --lib --tests --no-default-features -- -D warnings
  cargo clippy -p ragu_pcd --lib --tests --benches --no-default-features -- -D warnings
  CLIPPY_CONF_DIR=qa/backend cargo clippy -p ragu_pcd --lib --no-deps --all-features -- -D clippy::disallowed_methods

# backend lane: the PCD end-to-end equivalence, serially
[group('backend')]
backend_equivalence *ARGS:
  PROPTEST_CASES="${PROPTEST_CASES:-4}" cargo test --release -p ragu_pcd --no-default-features --lib backend_equivalence:: {{ARGS}} -- --test-threads=1

# correctness-first fallbacks retain their bare-metal no_std configurations
[group('backend')]
backend_nostd: _thumb_setup
  cargo build -p ragu_backend -p ragu_acceleration --lib --no-default-features --target thumbv7em-none-eabihf
  cargo build -p ragu_pcd --lib --no-default-features --features alloc --target thumbv7em-none-eabihf
  cargo build -p ragu_no_std --lib --no-default-features --locked --target thumbv7em-none-eabihf

# backend correctness lane: compilation, equivalence, and no_std
[group('backend')]
backend_lane: backend_clippy backend_equivalence backend_nostd
