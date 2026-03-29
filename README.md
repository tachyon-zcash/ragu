<p align="center">
  <img width="300" height="80" src="https://tachyon.z.cash/assets/ragu/v1/github-600x160.png">
</p>

---

# `ragu` ![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/tachyon-zcash/ragu)

**Ragu** is a Rust-language [proof-carrying data (PCD)](https://ic-people.epfl.ch/~achiesa/docs/CT10.pdf) framework that implements a modified version of the ECDLP-based recursive SNARK construction from [Halo [BGH19]](https://eprint.iacr.org/2019/1021). Ragu does not require a trusted setup. Developed for [Project Tachyon](https://tachyon.z.cash/) and compatible with the [Pasta curves](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/) employed in [Zcash](https://z.cash/), Ragu targets performance and feature support that is competitive with other ECC-based [accumulation](https://eprint.iacr.org/2020/499)/[folding](https://eprint.iacr.org/2021/370) schemes without complicated circuit arithmetizations.

> ⚠️ **Ragu is under heavy development and has not undergone auditing.** Do not use this software in production.

## Resources

* [The Ragu Book](https://tachyon.z.cash/ragu/) provides high-level documentation about Ragu, how it can be used, how it is designed, and how to contribute. The source code for the book lives in this repository in the [`book`](https://github.com/tachyon-zcash/ragu/tree/main/book) subdirectory.
* [Crate documentation](https://docs.rs/ragu) is available for official Ragu crate releases.
* Unofficial (internal) library documentation is [continually rendered](https://tachyon.z.cash/ragu/internal/ragu/) from the `main` branch. This is primarily for developers of Ragu.

## Requirements

<!-- BEGIN SYNC: this section must be kept in sync with book/src/guide/requirements.md -->

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.90.0**.
* Ragu requires minimal dependencies and currently strives to avoid using
  dependencies that are not already used in
  [Zebra](https://github.com/ZcashFoundation/zebra).

## `no_std` Support

Ragu's approach to `std` and `no_std` follows four principles:

1. **`no_std` compatible.** All library crates are `#![no_std]` and gate
   standard-library usage behind an optional `std` feature flag. The
   default `multicore` feature implies `std`; to build without it, use
   `--no-default-features`.
2. **`alloc` is required.** All library crates depend on the [`alloc`]
   crate for heap-allocated types such as `Vec` and `Box`, gated behind
   a default-on `alloc` feature flag. In practice this means Ragu can
   target environments that provide a global allocator but lack a full
   `std` runtime, such as WebAssembly or embedded platforms.
3. **Performance features may depend on `std`.** Optional features like
   `multicore` enable multi-threaded parallelism and imply `std`.
4. **`std` is required on the host.** Build scripts, procedural macros,
   tests, and benchmarks all run on the host and require `std`. This is a
   common requirement even for `no_std` libraries in the Rust
   ecosystem.

[`alloc`]: https://doc.rust-lang.org/alloc/

<!-- END SYNC -->
## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
