# list all available just commands
default:
    @just --list

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

lint: _typos_setup _book_setup
  cargo clippy --workspace --lib --tests --benches --features unstable-test-fixtures -- -D warnings
  cargo fmt --all -- --check
  typos
  mdbook build ./book

fix: _typos_setup 
  cargo fmt --all
  cargo fix --allow-dirty --allow-staged --features unstable-test-fixtures
  cargo clippy --fix --allow-dirty --allow-staged --features unstable-test-fixtures
  typos -w

_install_binstall:
  @command -v cargo-binstall > /dev/null || cargo install cargo-binstall

_book_setup: _install_binstall
  @cargo binstall --quiet --no-confirm mdbook@0.4.52 mdbook-katex@0.9.4 mdbook-mermaid@0.16.2 mdbook-linkcheck@0.7.7 mdbook-admonish@1.20.0

_typos_setup: _install_binstall
  @cargo binstall --quiet --no-confirm typos-cli

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

_nixery_meta := if arch() == "aarch64" { "arm64/shell" } else { "shell" }
bench-macos *ARGS:
    #!/usr/bin/env sh
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
        just bench-linux {{ARGS}})
    trap "docker kill $container > /dev/null 2>&1" EXIT HUP
    docker attach --no-stdin $container

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
