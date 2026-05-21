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

* The minimum supported [Rust](https://rust-lang.org/) version is currently
  **1.90.0**.
* Ragu requires minimal dependencies and currently strives to avoid using
  dependencies that are not already used in
  [Zebra](https://github.com/ZcashFoundation/zebra).
* Ragu's library crates are `no_std`-compatible and only need a global
  allocator; the default `multicore` feature uses [maybe-rayon] and pulls
  in `std`. See the [book](https://tachyon.z.cash/ragu/guide/requirements.html#no-std)
  for details.

[maybe-rayon]: https://crates.io/crates/maybe-rayon

## License

This library is distributed under the terms of both the MIT license and the Apache License (Version 2.0). See [LICENSE-APACHE](./LICENSE-APACHE), [LICENSE-MIT](./LICENSE-MIT) and [COPYRIGHT](./COPYRIGHT).
