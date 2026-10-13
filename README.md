<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

---

# `ragu` ![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/tachyon-zcash/ragu)

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not require a trusted setup. Developed for [Project Tachyon](https://tachyon.z.cash/) and compatible with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) employed in [Zcash](https://z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations.

> ⚠️ **Ragu is under heavy development and has not undergone auditing.** Do not use this software in production.

## Resources

* [The Ragu Book](https://tachyon.z.cash/ragu/) provides high-level documentation for working with Ragu, the protocol's design, and implementation details. The source code for the book lives in this repository in the [`book`](https://github.com/tachyon-zcash/ragu/tree/main/book) subdirectory.
* [Crate documentation](https://docs.rs/ragu) is available for official Ragu crate releases.
* Unofficial (internal) library documentation is [continually rendered](https://tachyon.z.cash/ragu/internal/ragu/) from the `main` branch. This is primarily for developers of Ragu.

## Requirements

* The minimum supported [Rust](https://rust-lang.org/) version is currently **1.97.1**.
* Ragu requires minimal dependencies and currently strives to avoid using dependencies that are not already used in [Zebra](https://github.com/ZcashFoundation/zebra).
* Ragu's library crates are [`no_std`]-compatible and need a global allocator. `ragu_pcd` enables `alloc` by default; its optional `multicore` feature uses [`maybe-rayon`] and enables `std`. The root `ragu` crate's `multicore` feature is a compatibility no-op. See the [book][book-no-std] for per-crate feature details.

[Zebra]: https://github.com/ZcashFoundation/zebra
[`no_std`]: https://doc.rust-lang.org/reference/names/preludes.html#the-no_std-attribute
[`maybe-rayon`]: https://crates.io/crates/maybe-rayon
[book-no-std]: https://tachyon.z.cash/ragu/guide/requirements.html#no-std

## Working on Ragu

Run these commands from the repository root with `just` installed. The
[justfile](./justfile) defines the local development commands:

| Command | Purpose |
| --- | --- |
| `just` | List available recipes. |
| `just build` | Build the default workspace members. |
| `just test` | Run workspace tests with all features. |
| `just lint` | Run Clippy, the formatting check, spelling checks, and the book build. |
| `just ci_local` | Run the local CI recipe, including backend and bare-metal build checks. |

CI formats Rust with `nightly-2026-05-23` and `rustfmt.nightly.toml`.
Use the same toolchain and configuration locally:

```sh
rustup toolchain install nightly-2026-05-23 --profile minimal --component rustfmt
cargo +nightly-2026-05-23 fmt --all -- --config-path rustfmt.nightly.toml --check
```

Omit `--check` to apply formatting. A successful formatting check with the
default toolchain does not establish that the nightly CI check will pass.
The lint and book recipes install their documentation and spelling tools
through `cargo-binstall` when needed. The bare-metal checks in `just ci_local`
also require the `thumbv7em-none-eabihf` target for the workspace toolchain:

```sh
rustup target add thumbv7em-none-eabihf
```

Once the book tools are installed, build from the repository root with
`mdbook build book`, or build and preview from the `book` directory:

```sh
cd book
mdbook build
# Or preview the book locally:
mdbook serve
```

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
