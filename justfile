# list all available just commands
default:
    @just --list

_nixery_meta := if arch() == "aarch64" { "arm64/shell" } else { "shell" }

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

lint: _typos_setup _book_setup
  cargo clippy --workspace --lib --tests --benches --all-features -- -D warnings
  cargo fmt --all -- --check
  typos
  mdbook build ./book

fix: _typos_setup 
  cargo fmt --all
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

# run all tests
test *ARGS:
  cargo test --workspace --all-features {{ARGS}}

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
    cargo bench --workspace --all-features {{ARGS}}

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
    bench_name=$(echo {{PACKAGE}} | sed 's/^ragu_//')
    bench_file="crates/{{PACKAGE}}/benches/${bench_name}.rs"
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
        cargo flamegraph --release -p {{PACKAGE}} --bench "$bench_name" \
        -o "target/flamegraph-{{PACKAGE}}-{{GROUP}}-{{TARGET}}.svg" {{ARGS}} \
        -- --gungraun-run {{GROUP}} "$func_idx" 0

# run CI checks locally (formatting, clippy, tests)
ci_local: _book_setup
  @echo "Running formatting check..."
  cargo fmt --all -- --check
  @echo "Running clippy..."
  cargo clippy --workspace --lib --tests --benches --locked --all-features -- -D warnings
  @echo "Running tests..."
  cargo test --release --all --locked --all-features
  @echo "Building benchmarks and examples..."
  cargo build --benches --examples --all-features
  @echo "Checking documentation..."
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all --locked --document-private-items
  @echo "Building book..."
  mdbook build ./book
  @echo "All CI checks passed!"
