# list all available just commands
default:
    @just --list

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

lint:
  cargo clippy --workspace --lib --tests --benches --features unstable-test-fixtures -- -D warnings
  cargo fmt --all -- --check
  typos
  mdbook build ./book

fix:
  cargo fmt --all
  cargo fix --allow-dirty --allow-staged --features unstable-test-fixtures
  cargo clippy --fix --allow-dirty --allow-staged --features unstable-test-fixtures
  typos -w

_install_binstall:
  @cargo install cargo-binstall

_book_setup: _install_binstall
  @cargo binstall -y mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2 mdbook-linkcheck@0.7.7 mdbook-admonish@1.20.0
  @cargo binstall -y typos-cli

_gungraun_setup: _install_binstall
  @cargo binstall --quiet --no-confirm gungraun-runner@0.17.0

# locally [build | serve | watch] Ragu book
book COMMAND: _book_setup
  mdbook {{COMMAND}} ./book --open

# run all tests
test *ARGS:
  cargo test --workspace {{ARGS}}

# run benchmarks (auto-detects platform)
bench *ARGS:
    @just bench-{{os()}} {{ARGS}}

bench-macos *ARGS:
    {{justfile_directory()}}/scripts/dockerized_bench.sh {{ARGS}}

bench-linux *ARGS: _gungraun_setup
    cargo bench --workspace --features unstable-test-fixtures {{ARGS}}

# run CI checks locally (formatting, clippy, tests)
ci_local: _book_setup
  @echo "Running formatting check..."
  cargo fmt --all -- --check
  @echo "Running clippy..."
  cargo clippy --all --locked --features unstable-test-fixtures -- -D warnings
  @echo "Running tests..."
  cargo test --release --all --locked
  @echo "Building benchmarks..."
  cargo build --benches --workspace --features unstable-test-fixtures
  @echo "Checking documentation..."
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --locked --document-private-items
  @echo "Building book..."
  mdbook build ./book
  @echo "All CI checks passed!"
