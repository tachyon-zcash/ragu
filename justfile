# list all available just commands
default:
    @just --list

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

lint:
  cargo clippy --workspace --lib --tests --benches -- -D warnings
  cargo fmt --all -- --check

fix:
  cargo fmt --all
  cargo fix --allow-dirty --allow-staged
  cargo clippy --fix --allow-dirty --allow-staged

_install_binstall:
  @which cargo-binstall >/dev/null 2>&1 || cargo install cargo-binstall

_book_setup: _install_binstall
  @cargo binstall -y mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2

# locally [build | serve | watch] Ragu book
book COMMAND: _book_setup
  mdbook {{COMMAND}} ./book --open

# run CI checks locally (formatting, clippy, tests)
ci_local: fix
  @echo "Running formatting check..."
  cargo fmt --all -- --check
  @echo "Running clippy..."
  cargo clippy --all --locked -- -D warnings
  @echo "Running tests..."
  cargo test --release --all --locked
  @echo "Building benchmarks and examples..."
  cargo build --benches --examples --all-features
  @echo "Checking documentation..."
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --locked --document-private-items
  @echo "All CI checks passed!"
