# list all available just commands
default:
    @just --list

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

# locally [build | serve | watch] Ragu book
book COMMAND: _book_setup
  mdbook {{COMMAND}} ./book --open

# run all tests
test *ARGS:
  cargo test --workspace --all-features {{ARGS}}

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
    cargo bench --workspace --all-features {{ARGS}}

# generate flamegraph (auto-detects platform)
# usage: just flamegraph ragu_pcd fuse
flamegraph PACKAGE TARGET *ARGS:
    @just flamegraph-{{os()}} {{PACKAGE}} {{TARGET}} {{ARGS}}

# resolve a benchmark target name to --gungraun-run arguments by parsing the bench source
_resolve_bench PACKAGE TARGET:
    #!/usr/bin/env sh
    set -e
    bench_name=$(echo {{PACKAGE}} | sed 's/^ragu_//')
    bench_file="crates/{{PACKAGE}}/benches/${bench_name}.rs"
    if [ ! -f "$bench_file" ]; then
        echo "error: bench file not found: $bench_file" >&2; exit 1
    fi
    # find which group contains this benchmark and its index within the group
    group=$(grep -B5 "benchmarks.*\b{{TARGET}}\b" "$bench_file" | grep 'name = ' | tail -1 | sed 's/.*name = //;s/[; ].*//')
    if [ -z "$group" ]; then
        echo "error: target '{{TARGET}}' not found in $bench_file" >&2
        echo "available targets:" >&2
        grep 'benchmarks\s*=' "$bench_file" | sed 's/.*=//;s/[; ]//g' | tr ',' '\n' | sed 's/^/  /' >&2
        exit 1
    fi
    # extract the benchmarks list for this group and find the function index
    bench_list=$(grep -A1 "name = ${group}" "$bench_file" | grep 'benchmarks' | sed 's/.*=//;s/[; ]//g')
    func_idx=0
    for fn in $(echo "$bench_list" | tr ',' ' '); do
        if [ "$fn" = "{{TARGET}}" ]; then break; fi
        func_idx=$((func_idx + 1))
    done
    echo "${bench_name} ${group} ${func_idx} 0"

flamegraph-macos PACKAGE TARGET *ARGS:
    #!/usr/bin/env sh
    set -e
    [ -t 1 ] && tty_opt="--tty"
    resolved=$(just _resolve_bench {{PACKAGE}} {{TARGET}})
    bench_name=$(echo "$resolved" | cut -d' ' -f1)
    group=$(echo "$resolved" | cut -d' ' -f2)
    func_idx=$(echo "$resolved" | cut -d' ' -f3)
    bench_idx=$(echo "$resolved" | cut -d' ' -f4)
    container=$(docker run $tty_opt --detach --interactive --init --rm \
        -v "{{justfile_dir()}}":/workspace \
        -e CARGO_PROFILE_RELEASE_DEBUG=true \
        -w /workspace \
        --privileged \
        rust:1.90-bookworm \
        sh -c "apt-get update -qq && apt-get install -y -qq linux-perf >/dev/null 2>&1 && \
            cargo install --quiet flamegraph && \
            cargo flamegraph --release -p {{PACKAGE}} --bench $bench_name \
                -o target/flamegraph-{{PACKAGE}}-{{TARGET}}.svg {{ARGS}} \
                -- --gungraun-run $group $func_idx $bench_idx")
    trap "docker kill $container > /dev/null 2>&1" EXIT HUP
    docker attach --no-stdin $container

_flamegraph_setup: _install_binstall
    @cargo binstall --quiet --no-confirm flamegraph

flamegraph-linux PACKAGE TARGET *ARGS: _flamegraph_setup
    #!/usr/bin/env sh
    set -e
    resolved=$(just _resolve_bench {{PACKAGE}} {{TARGET}})
    bench_name=$(echo "$resolved" | cut -d' ' -f1)
    group=$(echo "$resolved" | cut -d' ' -f2)
    func_idx=$(echo "$resolved" | cut -d' ' -f3)
    bench_idx=$(echo "$resolved" | cut -d' ' -f4)
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --release -p {{PACKAGE}} --bench "$bench_name" \
        -o "target/flamegraph-{{PACKAGE}}-{{TARGET}}.svg" {{ARGS}} \
        -- --gungraun-run "$group" "$func_idx" "$bench_idx"

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
